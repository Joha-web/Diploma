"""
ReconX - Module: low-impact reflected XSS candidate probing.
"""

from __future__ import annotations

import html
import re
import shlex
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from modules.active_probe_base import ActiveProbeBase


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Streaming / long-polling endpoints (socket.io, SockJS, HMR…) keep the
# connection open, so dalfox/XSStrike hang on them until they time out. They
# are not XSS-testable surfaces — skip them as scan targets.
STREAMING_URL_RE = re.compile(
    r"/socket\.io/|/sockjs|/engine\.io|[?&]EIO=|[?&]transport=(?:polling|websocket)|"
    r"/__webpack_hmr|/hot-update|/livereload|/_next/webpack-hmr|/sse(?:/|$|\?)",
    re.I,
)

# XSS payload catalogue. Each entry sets up a different context-breakout so the
# reflection classifier can promote it from "text_reflection" up to script_context
# or html_attribute when the reflected output proves a real sink. The `{marker}`
# placeholder is the per-run random token used to verify reflection.
# Sourced from PayloadsAllTheThings/XSS Injection.
DEFAULT_PAYLOADS = [
    # Plain marker — used to learn baseline reflection / escape behaviour.
    ("plain_marker", "{marker}"),

    # Classic attribute & tag-breakouts using the <reconx-xss> canary tag so the
    # html_tag classifier fires when the tag survives in the response body.
    ("double_quote_html", '"><reconx-xss data-rxss="{marker}"></reconx-xss>'),
    ("single_quote_html", "'><reconx-xss data-rxss='{marker}'></reconx-xss>"),
    ("script_breakout", '</script><reconx-xss data-rxss="{marker}"></reconx-xss>'),
    ("attribute_marker", '" data-rxss="{marker}'),

    # HTML comment breakout — apps that wrap user input in <!-- ... --> for templating
    # need a `-->` to escape the comment context first.
    ("html_comment_breakout", '--><reconx-xss data-rxss="{marker}"></reconx-xss><!--'),

    # CDATA breakout (XHTML / XML-like contexts).
    ("cdata_breakout", ']]><reconx-xss data-rxss="{marker}"></reconx-xss><![CDATA['),

    # SVG-based event handler. `<svg onload=...>` survives many HTML sanitisers that
    # only blacklist <script>. The marker is in the attribute payload so the
    # classifier's _inside_tag check fires (MEDIUM).
    ("svg_onload", '<svg/onload="window.name=\'{marker}\'"><reconx-xss data-rxss="{marker}"></reconx-xss></svg>'),

    # IMG onerror — fires on any broken src. One of the highest-success XSS vectors.
    ("img_onerror", '<img src=x onerror="window.name=\'{marker}\'"><reconx-xss data-rxss="{marker}"></reconx-xss>'),

    # JS string-literal breakout (double-quoted). Marker reflects inside <script>...
    # so _inside_script promotes to HIGH script_context_reflection.
    ("js_string_dq", '";reconx_rxss="{marker}";//'),

    # JS string-literal breakout (single-quoted).
    ("js_string_sq", "';reconx_rxss='{marker}';//"),

    # ES6 template-literal breakout (backtick contexts).
    ("js_template_literal", '`${{reconx_rxss=\'{marker}\'}}`'),

    # Attribute-value breakout without needing tag close — works inside `value="…"`
    # contexts. Uses `autofocus` to trigger `onfocus` without user interaction.
    ("attr_event_breakout", '" autofocus onfocus="window.name=\'{marker}\'" data-rxss="{marker}'),

    # `javascript:` URI scheme — for params reflected into href/src (e.g. open redirect
    # styles where the value lands inside an anchor href).
    ("javascript_scheme", 'javascript:/*--></title></style></textarea></script><reconx-xss data-rxss="{marker}"></reconx-xss>'),

    # Polyglot — collapses HTML / JS / attribute breakouts into one string. Famous
    # 0xsobky-style polyglot, adapted to drop the <reconx-xss> canary at the end.
    ("polyglot", "javascript:`/*'/*\"/*--></noscript></style></title></textarea></script><reconx-xss data-rxss=\"{marker}\"></reconx-xss>"),
]


class XSSModule(ActiveProbeBase):
    name = "xss"
    description = "Cross-Site Scripting Testing"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        parameter_results: dict | None = None,
        fuzzer_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.marker = f"rxss{uuid.uuid4().hex[:12]}"

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "targets": [], "total": 0, "status": "disabled"}

        cfg = self.module_config()
        targets = self.limit(self._collect_targets(), "max_targets", 80)
        if not targets:
            self.warn("No parameterized URLs for XSS probing")
            return {"findings": [], "targets": [], "total": 0}

        self.save_json(targets, "xss_targets.json")

        findings: list[dict] = []
        tool_runs: list[dict] = []
        requests_sent = 0
        missing_tools: list[str] = []
        ran_any_tool = False

        # Heavier external scanners (XSStrike / XSSer) crawl and fuzz per target,
        # so cap them independently of the dalfox/reflection target budget.
        tool_targets = targets[: int(cfg.get("max_tool_targets", 20))]

        # 1. dalfox (fast, low FP) — over the full target set
        if cfg.get("use_dalfox", True):
            if self.has_tool("dalfox"):
                ran_any_tool = True
                for index, target in enumerate(targets, start=1):
                    target_findings, run = self._run_dalfox(target, cfg, index)
                    findings.extend(target_findings)
                    tool_runs.append(run)
            else:
                missing_tools.append("dalfox")

        # 2. XSStrike — intelligent payload generation / reflection analysis
        if cfg.get("use_xsstrike", True):
            xsstrike_cmd = self._xsstrike_command(cfg)
            if xsstrike_cmd:
                ran_any_tool = True
                for index, target in enumerate(tool_targets, start=1):
                    target_findings, run = self._run_xsstrike(xsstrike_cmd, target, cfg, index)
                    findings.extend(target_findings)
                    tool_runs.append(run)
            else:
                missing_tools.append("xsstrike")

        # 3. XSSer — classic injection fuzzer
        if cfg.get("use_xsser", True):
            if self.has_tool("xsser"):
                ran_any_tool = True
                for index, target in enumerate(tool_targets, start=1):
                    target_findings, run = self._run_xsser(target, cfg, index)
                    findings.extend(target_findings)
                    tool_runs.append(run)
            else:
                missing_tools.append("xsser")

        if missing_tools:
            self.warn(f"XSS tools not in PATH: {', '.join(missing_tools)} "
                      "(using reflection fallback / remaining tools)")

        # 4. Built-in reflection probe — fallback / always-available baseline
        if cfg.get("fallback_reflection", True):
            fallback_findings, requests_sent = self._run_reflection_probe(targets, cfg)
            findings.extend(fallback_findings)
        elif not ran_any_tool:
            return {
                "findings": [],
                "targets": targets,
                "runs": [],
                "total": 0,
                "status": "skipped",
                "missing_tools": missing_tools,
            }

        findings = self.dedup_findings(findings)
        self.save_json(findings, "xss_findings.json")
        if tool_runs:
            self.save_json(tool_runs, "xss_tool_runs.json")
        result = {
            "findings": findings,
            "targets": targets,
            "runs": tool_runs,
            "total": len(findings),
            "tested": len(targets),
            "requests_sent": requests_sent,
        }
        if missing_tools:
            result["missing_tools"] = missing_tools
        return result

    def _run_reflection_probe(self, targets: list[dict], cfg: dict) -> tuple[list[dict], int]:
        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        requests_sent = 0
        max_requests = int(cfg.get("max_requests", 240))
        timeout = self._http_timeout(cfg)
        max_params = int(cfg.get("max_params_per_target", 4))

        for target in targets:
            baseline = self.http_get(target["url"], session=session, timeout=timeout, verify=False)
            baseline_body = baseline.text or "" if baseline else ""
            for param in target.get("params", [])[:max_params]:
                if requests_sent >= max_requests:
                    break
                param_findings, sent = self._probe_param(target, param, baseline_body, session, cfg)
                requests_sent += sent
                findings.extend(param_findings)
            if requests_sent >= max_requests:
                break

        return findings, requests_sent

    def _run_dalfox(self, target: dict, cfg: dict, index: int) -> tuple[list[dict], dict]:
        cmd = self._dalfox_command(target, cfg)
        timeout = int(cfg.get("dalfox_timeout", cfg.get("timeout", 300)))
        stdout_file = f"dalfox_run_{index:03d}.txt"
        out_path = self.module_dir / stdout_file
        result = self._exec_to_file(cmd, out_path, timeout, f"dalfox {target['url']}")
        output = self._read_tool_output(out_path)
        findings = self._parse_dalfox_findings(output, target, stdout_file, index)
        return findings, {
            "tool": "dalfox",
            "url": target["url"],
            "params": target.get("params", []),
            "returncode": result.returncode,
            "stdout_file": stdout_file,
            "findings": len(findings),
        }

    def _dalfox_command(self, target: dict, cfg: dict) -> list[str]:
        cmd = [
            "dalfox",
            "url",
            target["url"],
            "--silence",
            "--no-color",
            "--timeout",
            str(self._bounded_int(cfg.get("request_timeout", 10), 1, 120)),
        ]
        # dalfox parallelism. The old default of 1 serialised every payload and
        # made dalfox time out before finishing; 40 keeps it fast without being
        # as aggressive as dalfox's own default of 100.
        workers = self._bounded_int(cfg.get("workers", 40), 1, 100)
        cmd.extend(["--worker", str(workers)])
        params = [param for param in target.get("params", []) if param]
        if params:
            cmd.append("--skip-discovery")
            for param in params:
                cmd.extend(["-p", param])
        for arg in cfg.get("dalfox_extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())
        return cmd

    def _parse_dalfox_findings(self, output: str, target: dict, stdout_file: str, index: int) -> list[dict]:
        poc_entries: list[tuple[str, str]] = []
        found_lines: list[str] = []
        for line in (output or "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            upper = stripped.upper()
            if "[POC]" not in upper:
                if "XSS FOUND" in upper:
                    found_lines.append(stripped)
                continue
            urls = re.findall(r"https?://[^\s'\"<>]+", stripped)
            poc_url = urls[0].strip("[](){}.,;") if urls else target["url"]
            poc_entries.append((stripped, poc_url))

        if not poc_entries:
            poc_entries = [(line, target["url"]) for line in found_lines]

        findings: list[dict] = []
        for offset, (line, poc_url) in enumerate(poc_entries, start=1):
            param = self._matching_param(poc_url, target.get("params", []))
            findings.append(self.make_finding(
                "xss_dalfox_confirmed",
                poc_url,
                title="Dalfox reported reflected XSS",
                description=(
                    "Dalfox reported an XSS proof of concept for a parameterized endpoint. "
                    "Validate impact manually before exploitation."
                ),
                severity="HIGH",
                confidence=0.90,
                finding_type="xss",
                references=[
                    "https://portswigger.net/web-security/cross-site-scripting",
                    "https://owasp.org/www-community/attacks/xss/",
                ],
                exploitability="confirmed",
                evidence={
                    "tool": "dalfox",
                    "line": line,
                    "param": param,
                    "run_index": index,
                    "finding_offset": offset,
                    "stdout_file": stdout_file,
                    "sources": target.get("sources", []),
                },
            ))
        return findings

    def _exec_to_file(self, cmd: list[str], out_path: Path, timeout: int, label: str):
        """Run a tool with its output streamed to a file via the shell.

        XSStrike and XSSer emit thousands of payloads and often outlast the
        timeout. BaseModule.exec() discards stdout when it kills a timed-out
        process, which would lose findings the tool already printed. Redirecting
        to disk means partial output (and any findings in it) survives the kill.
        """
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shell_cmd = " ".join(shlex.quote(c) for c in cmd) + f" > {shlex.quote(str(out_path))} 2>&1"
        return self.exec(shell_cmd, timeout=timeout, shell=True, label=label)

    @staticmethod
    def _read_tool_output(out_path: Path) -> str:
        try:
            return out_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # ── XSStrike ────────────────────────────────────────────────────────────────
    def _xsstrike_command(self, cfg: dict) -> list[str] | None:
        """Resolve XSStrike to an on-PATH binary or a `python3 xsstrike.py` call."""
        if self.has_tool("xsstrike"):
            return ["xsstrike"]
        configured = str(cfg.get("xsstrike_path", "")).strip()
        for path in [configured, "/opt/XSStrike/xsstrike.py", "/usr/share/XSStrike/xsstrike.py"]:
            if path and Path(path).exists():
                return ["python3", path]
        return None

    def _run_xsstrike(self, base_cmd: list[str], target: dict, cfg: dict, index: int) -> tuple[list[dict], dict]:
        # --skip suppresses the interactive update prompt; XSStrike tests the GET
        # parameters already present in the URL.
        cmd = base_cmd + [
            "-u", target["url"], "--skip",
            "--timeout", str(self._bounded_int(cfg.get("request_timeout", 10), 1, 120)),
        ]
        for arg in cfg.get("xsstrike_extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())
        timeout = int(cfg.get("xsstrike_timeout", cfg.get("timeout", 600)))
        stdout_file = f"xsstrike_run_{index:03d}.txt"
        out_path = self.module_dir / stdout_file
        result = self._exec_to_file(cmd, out_path, timeout, f"xsstrike {target['url']}")
        output = self._read_tool_output(out_path)
        findings = self._parse_xsstrike(output, target, stdout_file, index)
        return findings, {
            "tool": "xsstrike", "url": target["url"], "params": target.get("params", []),
            "returncode": result.returncode, "stdout_file": stdout_file, "findings": len(findings),
        }

    def _parse_xsstrike(self, output: str, target: dict, stdout_file: str, index: int) -> list[dict]:
        # XSStrike has no machine output; a working vector is reported as a
        # "Payload: …" line, with "Efficiency: 100" denoting an unfiltered hit.
        payload_lines: list[str] = []
        efficiency = 0
        for line in (output or "").splitlines():
            stripped = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()  # strip ANSI colour
            low = stripped.lower()
            if "payload:" in low:
                payload_lines.append(stripped)
            m = re.search(r"efficiency:\s*(\d+)", low)
            if m:
                efficiency = max(efficiency, int(m.group(1)))
        if not payload_lines:
            return []
        confirmed = efficiency >= 100
        return [self.make_finding(
            "xss_xsstrike_confirmed" if confirmed else "xss_xsstrike_reported",
            target["url"],
            title="XSStrike reported a working XSS payload" if confirmed
                  else "XSStrike reported a candidate XSS reflection",
            description=(
                "XSStrike generated a payload that the page reflected. "
                f"Max efficiency {efficiency}%. Validate manually before exploitation."
            ),
            severity="HIGH" if confirmed else "MEDIUM",
            confidence=0.82 if confirmed else 0.6,
            finding_type="xss",
            references=["https://github.com/s0md3v/XSStrike",
                        "https://owasp.org/www-community/attacks/xss/"],
            exploitability="active",
            evidence={
                "tool": "xsstrike", "param": self._matching_param(target["url"], target.get("params", [])),
                "efficiency": efficiency, "payload": payload_lines[0][:200],
                "run_index": index, "stdout_file": stdout_file, "sources": target.get("sources", []),
            },
        )]

    # ── XSSer ─────────────────────────────────────────────────────────────────────
    def _run_xsser(self, target: dict, cfg: dict, index: int) -> tuple[list[dict], dict]:
        # XSSer needs an explicit injection point: -u <base> -g <path?param=XSS>.
        # The "--url + --auto" form aborts with "cannot find a place to start".
        base, getdata = self._xsser_target(target)
        cmd = [
            "xsser", "-u", base, "-g", getdata, "--auto", "--statistics",
            "--threads", str(self._bounded_int(cfg.get("xsser_threads", 3), 1, 20)),
            "--timeout", str(self._bounded_int(cfg.get("request_timeout", 10), 1, 120)),
        ]
        # Cap the vector set so XSSer finishes within the timeout (default 1293).
        auto_set = self._bounded_int(cfg.get("xsser_auto_set", 600), 0, 1293)
        if auto_set:
            cmd += ["--auto-set", str(auto_set)]
        for arg in cfg.get("xsser_extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())
        timeout = int(cfg.get("xsser_timeout", cfg.get("timeout", 600)))
        stdout_file = f"xsser_run_{index:03d}.txt"
        out_path = self.module_dir / stdout_file
        result = self._exec_to_file(cmd, out_path, timeout, f"xsser {target['url']}")
        output = self._read_tool_output(out_path)
        findings = self._parse_xsser(output, target, stdout_file, index)
        return findings, {
            "tool": "xsser", "url": target["url"], "params": target.get("params", []),
            "returncode": result.returncode, "stdout_file": stdout_file, "findings": len(findings),
        }

    @classmethod
    def _xsser_target(cls, target: dict) -> tuple[str, str]:
        """Split a URL into XSSer's (-u base, -g path?param=XSS) form.

        Each target parameter's value is replaced with the literal marker XSS,
        which XSSer substitutes with its payload vectors.
        """
        parsed = urlparse(target["url"])
        base = f"{parsed.scheme}://{parsed.netloc}"
        want = set(target.get("params", []))
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if pairs:
            query = "&".join(f"{k}=XSS" if (not want or k in want) else f"{k}={v}"
                             for k, v in pairs)
        else:
            query = "&".join(f"{p}=XSS" for p in want) or "XSS"
        return base, f"{parsed.path or '/'}?{query}"

    def _parse_xsser(self, output: str, target: dict, stdout_file: str, index: int) -> list[dict]:
        # XSSer marks confirmed vectors with [FOUND] in its "Injection(s) Results"
        # block and lists them under "[+] Vulnerable(s):" (vs "[Not Info]" when
        # nothing fires). Only raise a finding when something is actually FOUND.
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
        found_lines = [ln.strip() for ln in clean.splitlines()
                       if re.search(r"\[\s*FOUND\s*\]", ln, re.I)]
        vuln_section = re.search(
            r"\[\+\]\s*Vulnerable\(s\):\s*(.+?)(?:-{5,}|={5,}|\Z)", clean, re.I | re.S)
        vuln_text = (vuln_section.group(1).strip() if vuln_section else "")
        has_vuln = bool(vuln_text) and not re.search(r"\[\s*Not\s+(Info|Found)\s*\]", vuln_text, re.I)
        if not found_lines and not has_vuln:
            return []
        return [self.make_finding(
            "xss_xsser_reported",
            target["url"],
            title="XSSer reported an XSS injection",
            description=(
                f"XSSer flagged {len(found_lines) or 'an'} injection vector(s) as FOUND. "
                "XSSer is prone to false positives — confirm the payload manually."
            ),
            severity="MEDIUM",
            confidence=0.58,
            finding_type="xss",
            references=["https://xsser.03c8.net/",
                        "https://owasp.org/www-community/attacks/xss/"],
            exploitability="active",
            evidence={
                "tool": "xsser", "param": self._matching_param(target["url"], target.get("params", [])),
                "found_count": len(found_lines), "lines": (found_lines or [vuln_text])[:3],
                "run_index": index, "stdout_file": stdout_file, "sources": target.get("sources", []),
            },
        )]

    def _probe_param(
        self,
        target: dict,
        param: str,
        baseline_body: str,
        session: requests.Session,
        cfg: dict,
    ) -> tuple[list[dict], int]:
        findings: list[dict] = []
        sent = 0
        timeout = self._http_timeout(cfg)
        for payload_name, payload in self._payloads(cfg):
            probe_url = self._replace_or_add(target["url"], param, payload)
            sent += 1
            resp = self.http_get(
                probe_url,
                session=session,
                timeout=timeout,
                verify=False,
            )
            if resp is None:
                continue
            body = resp.text or ""
            if self.marker not in body or self.marker in baseline_body:
                continue
            if self._reflection_is_json_uri_echo(body, self.marker, param):
                # Marker only appears inside a JSON-encoded request-URI field (e.g.
                # Laravel debugbar, framework error JSON). Not an executable context.
                continue
            finding_id, severity, confidence, context = self._classify_reflection(body)
            findings.append(self.make_finding(
                finding_id,
                probe_url,
                severity=severity,
                confidence=confidence,
                evidence={
                    "param": param,
                    "payload_name": payload_name,
                    "payload": payload,
                    "context": context,
                    "status": resp.status_code,
                    "escaped": context == "escaped_reflection",
                    "excerpt": self._excerpt(body, self.marker),
                    "sources": target.get("sources", []),
                },
            ))

        best = self._best_finding(findings)
        return ([best] if best else []), sent

    def _payloads(self, cfg: dict) -> list[tuple[str, str]]:
        payloads = [
            (name, template.format(marker=self.marker))
            for name, template in DEFAULT_PAYLOADS
        ]
        for idx, payload in enumerate(cfg.get("payloads", []) or [], start=1):
            if isinstance(payload, str) and payload.strip():
                payloads.append((f"custom_{idx}", payload.format(marker=self.marker)))
        return payloads[: int(cfg.get("max_payloads", len(payloads)))]

    def _http_timeout(self, cfg: dict) -> float:
        try:
            return float(cfg.get("request_timeout", self.request_timeout()))
        except (TypeError, ValueError):
            return self.request_timeout()

    def _classify_reflection(self, body: str) -> tuple[str, str, float, str]:
        lowered = body.lower()
        unescaped = html.unescape(body).lower()
        if self._inside_script(body, self.marker):
            return "xss_script_context_reflection", "HIGH", 0.78, "script_context"
        if "<reconx-xss" in lowered:
            return "xss_html_injection_candidate", "HIGH", 0.82, "html_tag"
        if self._inside_tag(body, self.marker):
            return "xss_attribute_context_reflection", "MEDIUM", 0.74, "html_attribute"
        if "<reconx-xss" in unescaped:
            return "xss_reflected_input", "LOW", 0.62, "escaped_reflection"
        return "xss_reflected_input", "LOW", 0.58, "text_reflection"

    def _collect_targets(self) -> list[dict]:
        targets: dict[str, dict] = {}

        def add(url: str, params: set[str] | list[str], source: str) -> None:
            url = str(url or "").strip()
            clean_params = {str(param).strip() for param in params if str(param).strip()}
            if not url.startswith(("http://", "https://")) or not clean_params:
                return
            if STREAMING_URL_RE.search(url):
                return  # socket.io / SSE / HMR — dalfox hangs on these
            if "?" not in url:
                url = self._with_param(url, sorted(clean_params)[0])
            else:
                existing = self._query_params(url)
                for missing in sorted(clean_params - existing):
                    url = self._with_param(url, missing)
            if not self.is_in_scope(url):
                return
            entry = targets.setdefault(url, {"url": url, "params": set(), "sources": set()})
            entry["params"].update(clean_params)
            entry["sources"].add(source)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                add(item.get("url", ""), {item.get("param") or item.get("name", "")}, item.get("source", "parameter_discovery"))

        for url in self.parameter_results.get("parameterized_targets", []) or []:
            add(str(url), self._query_params(str(url)), "parameter_discovery")

        classified = self.fuzzer_results.get("classified", {}) or {}
        for url in classified.get("with_params", []) or []:
            add(str(url), self._query_params(str(url)), "fuzzer")
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            if "?" in str(url):
                add(str(url), self._query_params(str(url)), "fuzzer")

        return [
            {
                "url": item["url"],
                "params": sorted(item["params"]),
                "sources": sorted(item["sources"]),
            }
            for item in sorted(targets.values(), key=lambda entry: entry["url"])
        ]

    @staticmethod
    def _query_params(url: str) -> set[str]:
        return {name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name}

    @staticmethod
    def _with_param(url: str, param: str) -> str:
        parsed = urlparse(url)
        query = urlencode({param: "reconx"})
        if parsed.query:
            query = f"{parsed.query}&{query}"
        return urlunparse(parsed._replace(query=query))

    @staticmethod
    def _replace_or_add(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated = []
        for key, existing in pairs:
            if key == param:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, existing))
        if not replaced:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    @classmethod
    def _matching_param(cls, url: str, params: list[str]) -> str:
        query_params = cls._query_params(url)
        for param in params:
            if param in query_params:
                return param
        return params[0] if params else ""

    @staticmethod
    def _bounded_int(value, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = minimum
        return min(max(parsed, minimum), maximum)

    @staticmethod
    def _inside_script(body: str, marker: str) -> bool:
        idx = body.find(marker)
        if idx < 0:
            return False
        before = body[:idx].lower()
        script_start = before.rfind("<script")
        script_end = before.rfind("</script")
        return script_start > script_end

    @staticmethod
    def _reflection_is_json_uri_echo(body: str, marker: str, param: str) -> bool:
        """Return True if every occurrence of the marker is inside a JSON request-URI echo
        (debugbar/error JSON, access-log style responses). Not exploitable as XSS even
        though the script-context heuristic would otherwise match."""
        if not body or marker not in body:
            return False
        # Quick reject: payload not rendered into HTML, only into JSON URI strings.
        echo_tokens = (
            '"uri"', "'uri'", '"url"', "'url'", '"path"',
            "request_uri", "REQUEST_URI", "fullUrl",
            '"originalUrl"', '"requestUri"',
        )
        idx = 0
        any_match = False
        while True:
            pos = body.find(marker, idx)
            if pos < 0:
                break
            any_match = True
            window = body[max(0, pos - 300): pos]
            # JSON-encoded URI characteristic: backslash-escaped slashes (\/) and
            # backslash-u escapes (& for & in query string).
            has_json_escapes = ("\\/" in window) or ("\\u00" in window)
            has_echo_token = any(tok in window for tok in echo_tokens)
            has_param = (f"{param}=" in window) or (f"{param}\\u003d" in window)
            if has_json_escapes and (has_echo_token or has_param):
                idx = pos + len(marker)
                continue
            return False
        return any_match

    @staticmethod
    def _inside_tag(body: str, marker: str) -> bool:
        idx = body.find(marker)
        if idx < 0:
            return False
        tag_start = body.rfind("<", 0, idx)
        prior_close = body.rfind(">", 0, idx)
        next_close = body.find(">", idx)
        return tag_start > prior_close and next_close != -1

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 120) -> str:
        match = re.search(re.escape(marker), body or "", re.I)
        if not match:
            return (body or "")[: radius * 2]
        start = max(match.start() - radius, 0)
        end = min(match.end() + radius, len(body))
        return body[start:end]

    @staticmethod
    def _best_finding(findings: list[dict]) -> dict | None:
        if not findings:
            return None
        return sorted(
            findings,
            key=lambda item: (
                SEVERITY_RANK.get(item.get("severity", "INFO"), 0),
                float(item.get("confidence", 0) or 0),
            ),
            reverse=True,
        )[0]
