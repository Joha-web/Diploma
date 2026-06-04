"""
ReconX — Module: OS command injection.

Two layers, like the SSRF/SQLi probes:

  1. **Where might it exist?** A scorer ranks every (url, param) by command-
     injection likelihood from the parameter NAME (cmd, exec, ping, host, dns…),
     the VALUE shape (a hostname/IP fed to a diagnostic tool), and the endpoint
     PATH (/ping, /exec, /tool…). An optional in-band exec pre-screen (an
     echo+arithmetic payload) force-promotes parameters that actually execute.
  2. **Confirm.** High-scoring parameters are tested with **commix** (-p) and
     fuzzed with **ffuf** + the SecLists command-injection-commix wordlist
     (matching the executed `MARKER<sum>MARKER` echo pattern).
"""

from __future__ import annotations

import re
import shlex
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase

# ── Command-injection-likelihood signals ──────────────────────────────────────
CMDI_HIGH_PARAMS = frozenset({
    "cmd", "command", "exec", "execute", "run", "system", "shell", "ping",
    "host", "hostname", "nslookup", "traceroute", "tracert", "dig", "whois",
    "lookup", "dns", "ip", "ipaddr", "domain", "cmdline", "process", "proc",
    "daemon", "service", "script", "func", "do", "task", "job",
})
CMDI_MEDIUM_PARAMS = frozenset({
    "target", "addr", "name", "file", "path", "load", "fetch", "convert",
    "compress", "archive", "zip", "backup", "restore", "log", "mail", "email",
    "format", "ext", "tool", "util", "option", "arg", "action", "data",
    "input", "output",
})
CMDI_PATH_HINTS = re.compile(
    r"(ping|exec|cmd|command|run|system|shell|tool|util|diagnostic|network|"
    r"traceroute|nslookup|dns|lookup|whois|console|terminal|backup|restore|"
    r"convert|compress|process|task|cron|admin|debug)", re.I,
)
HOST_VALUE_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$", re.I)
# Filenames (report.pdf, photo.jpg) match the host regex — exclude common
# document/media extensions so they don't score as diagnostic-tool host input.
NON_HOST_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|jpe?g|png|gif|svg|webp|bmp|ico|zip|rar|"
    r"gz|tar|7z|mp[34]|avi|mov|wmv|html?|xml|json|css|js|woff2?|ttf|eot)$", re.I)
CMD_VALUE_RE = re.compile(r"[;&|`$]|[/\\]|\.(?:sh|exe|bat|cmd|py|pl)$", re.I)
FILE_VALUE_RE = re.compile(r"\.\w{1,5}$")

# Executed echo-pattern from the SecLists commix wordlist: MARKER<sum>MARKER.
FFUF_CMDI_REGEX = r"[A-Z]{6}[0-9]+[A-Z]{6}"
COMMIX_HIT_RE = re.compile(
    r"(?i)(appears to be injectable|is vulnerable to|vulnerable to .{0,30}command injection|"
    r"parameter '[^']+' is vulnerable)")
DEFAULT_CMDI_WORDLIST = "/usr/share/wordlists/seclists/Fuzzing/command-injection-commix.txt"


class CommandInjectionModule(ActiveProbeBase):
    name = "command_injection"
    description = "OS Command Injection (commix + ffuf)"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 parameter_results: dict | None = None,
                 fuzzer_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []
        for sub in ("commix", "ffuf"):
            (self.module_dir / sub).mkdir(exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────
    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "candidates": [], "total": 0, "status": "disabled"}
        cfg = self.module_config()
        possible = float(cfg.get("possible_threshold", 0.3))
        strong = float(cfg.get("strong_threshold", 0.5))

        candidates = self._collect_candidates()
        if cfg.get("exec_prescreen", True):
            self._exec_prescreen(candidates, cfg)
        if cfg.get("time_prescreen", True):
            self._timing_prescreen(candidates, cfg)
        scored = sorted((c for c in candidates if c["score"] >= possible),
                        key=lambda c: c["score"], reverse=True)
        self.save_json(scored, "cmdi_candidates.json")

        findings: list[dict] = []
        confirmed: set[tuple] = set()

        def mark(cand, finding):
            findings.append(finding)
            confirmed.add((self._base(cand["url"]), cand["param"].lower()))

        # Pre-screen confirmations (infra-free): in-band echo, then time-based blind.
        for cand in scored:
            if cand.get("exec_confirmed"):
                mark(cand, self._confirmed_finding(cand, "in-band probe", 0.9,
                                                   {"payload": cand.get("exec_payload", "")}))
            elif cand.get("time_confirmed"):
                mark(cand, self._confirmed_finding(cand, "time-based blind probe", 0.85,
                                                   {"payload": cand.get("time_payload", ""),
                                                    "delay_seconds": cand.get("time_delay")}))

        likely = self._build_targets(scored, strong, cfg)

        # commix
        if cfg.get("commix", True) and self.has_tool("commix"):
            for index, cand in enumerate(likely, start=1):
                for f in self._run_commix(cand, cfg, index):
                    mark(cand, f)
        elif cfg.get("commix", True) and likely:
            self.info("commix not found — using ffuf / scored candidates only")

        # ffuf + SecLists command-injection wordlist
        if cfg.get("ffuf", True) and self.has_tool("ffuf"):
            wordlist = self._wordlist(cfg)
            if wordlist:
                for index, cand in enumerate(likely, start=1):
                    if (self._base(cand["url"]), cand["param"].lower()) in confirmed:
                        continue
                    for f in self._run_ffuf(cand, wordlist, cfg, index):
                        mark(cand, f)
            else:
                self.warn("command-injection wordlist not found (set scan.command_injection.wordlist)")

        # Candidate findings — skip parameters already confirmed.
        for cand in scored:
            if (self._base(cand["url"]), cand["param"].lower()) not in confirmed:
                findings.append(self._candidate_finding(cand, strong))

        findings = self.dedup_findings(findings)
        self.save_json(findings, "command_injection_findings.json")
        return {
            "findings": findings,
            "candidates": scored,
            "candidate_count": len(scored),
            "total": len(findings),
            "confirmed": len(confirmed),
            "tested": len(likely),
        }

    def summary(self) -> str:
        r = self.results
        return f"💣 {r.get('candidate_count', 0)} CMDi candidate(s), {r.get('confirmed', 0)} confirmed"

    # ── Scoring ─────────────────────────────────────────────────────────────────
    @staticmethod
    def _score(param: str, value: str, path: str) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        pname = (param or "").strip().lower()
        val = str(value or "").strip()

        if HOST_VALUE_RE.match(val) and not NON_HOST_EXT_RE.search(val):
            score += 0.35
            reasons.append("value is a host/IP (diagnostic-tool input)")
        elif val and CMD_VALUE_RE.search(val):
            score += 0.15
            reasons.append("value looks like a command/path")
        elif val and FILE_VALUE_RE.search(val):
            score += 0.15
            reasons.append("value is a filename")

        if pname in CMDI_HIGH_PARAMS:
            score += 0.45
            reasons.append(f"param name '{param}' is exec/diagnostic-prone")
        elif pname in CMDI_MEDIUM_PARAMS:
            score += 0.25
            reasons.append(f"param name '{param}' is sometimes command-bound")

        hit = CMDI_PATH_HINTS.search(path or "")
        if hit:
            score += 0.25
            reasons.append(f"command/diagnostic endpoint ('{hit.group(0)}')")

        return min(score, 1.0), reasons

    def _collect_candidates(self) -> list[dict]:
        cands: dict[tuple, dict] = {}

        def add(url: str, param: str, value: str, source: str):
            url, param = str(url or "").strip(), str(param or "").strip()
            if not url.startswith(("http://", "https://")) or not param:
                return
            if param not in self._query_params(url):
                url = self._with_param(url, param)
            if not self.is_in_scope(url):
                return
            parsed = urlparse(url)
            key = (self._base(url), param.lower())
            score, reasons = self._score(param, value, parsed.path)
            existing = cands.get(key)
            if existing is None or score > existing["score"]:
                cands[key] = {"url": url, "param": param, "value": value, "path": parsed.path,
                              "score": round(score, 2), "reasons": reasons, "sources": [source]}
            elif source not in cands[key]["sources"]:
                cands[key]["sources"].append(source)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                url = item.get("url", "")
                param = item.get("param") or item.get("name", "")
                value = dict(parse_qsl(urlparse(url).query)).get(param, "")
                add(url, param, value, item.get("source", "parameter_discovery"))

        urls = set(self.parameter_results.get("parameterized_targets", []) or [])
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls.update(classified.get("with_params", []) or [])
        urls.update(u for u in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(u))
        for url in urls:
            for param, value in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
                add(str(url), param, value, "fuzzer")

        return list(cands.values())

    def _build_targets(self, scored: list[dict], strong: float, cfg: dict) -> list[dict]:
        likely = [c for c in scored if c["score"] >= strong]
        return likely[: int(cfg.get("max_targets", 15))]

    # ── In-band exec pre-screen ─────────────────────────────────────────────────
    def _exec_prescreen(self, candidates: list[dict], cfg: dict) -> None:
        import requests
        session = requests.Session()
        session.verify = False
        timeout = float(cfg.get("request_timeout", 10))
        max_requests = int(cfg.get("prescreen_max_requests", 50))
        min_score = float(cfg.get("prescreen_min_score", 0.25))
        a, b = 13337, 24690
        total = str(a + b)
        sent = 0
        for cand in sorted(candidates, key=lambda c: c["score"], reverse=True):
            if sent >= max_requests:
                break
            if cand["score"] < min_score:
                continue
            marker = f"CMDX{uuid.uuid4().hex[:6].upper()}"
            expected = f"{marker}{total}"
            payloads = [
                f";echo {marker}$(({a}+{b}))", f"|echo {marker}$(({a}+{b}))",
                f"&echo {marker}$(({a}+{b}))", f"`echo {marker}$(({a}+{b}))`",
                f"$(echo {marker}$(({a}+{b})))",
            ]
            for payload in payloads:
                if sent >= max_requests:
                    break
                probe = self._set_param_value(cand["url"], cand["param"], (cand["value"] or "1") + payload)
                resp = self.http_get(probe, session=session, timeout=timeout, verify=False)
                sent += 1
                # The literal payload reflects "marker$((..." — only true execution
                # yields the marker immediately followed by the computed sum.
                if resp is not None and expected in (resp.text or ""):
                    cand["score"] = max(cand["score"], 0.95)
                    cand["reasons"] = cand["reasons"] + ["echo+arithmetic payload executed in-band"]
                    cand["exec_confirmed"] = True
                    cand["exec_payload"] = payload
                    break

    # ── Time-based blind pre-screen ──────────────────────────────────────────────
    # Payload templates that suspend the OS command for N seconds across the
    # common shells / both OSes. {v} = original value, {d} = delay seconds.
    _TIME_PAYLOADS = (
        "{v};sleep {d}", "{v}|sleep {d}", "{v}$(sleep {d})", "{v}`sleep {d}`",
        "{v}&&sleep {d}", "{v}& ping -c {d} 127.0.0.1", "{v}& ping -n {d} 127.0.0.1",
    )

    def _timing_prescreen(self, candidates: list[dict], cfg: dict) -> None:
        """Detect *blind* command injection by measuring response delay.

        Catches the common case the in-band echo / ffuf marker miss: the command
        runs but returns no output. A `sleep N` payload that delays the response
        by ~N seconds — re-confirmed with a 2N delay to rule out a slow endpoint —
        is strong evidence of execution.
        """
        import requests
        session = requests.Session()
        session.verify = False
        delay = self._bounded(cfg.get("time_delay", 6), 3, 30)
        confirm = delay * 2
        req_timeout = max(float(cfg.get("request_timeout", 10)), confirm + 5)
        max_targets = int(cfg.get("time_prescreen_max", 20))
        min_score = float(cfg.get("prescreen_min_score", 0.25))
        tested = 0

        for cand in sorted(candidates, key=lambda c: c["score"], reverse=True):
            if tested >= max_targets:
                break
            if cand["score"] < min_score or cand.get("exec_confirmed"):
                continue
            base_value = cand["value"] or "1"
            baseline = self._timed_get(self._set_param_value(cand["url"], cand["param"], base_value),
                                       session, req_timeout)
            if baseline is None or baseline >= delay:
                continue  # unreachable or already too slow to distinguish
            tested += 1
            for tmpl in self._TIME_PAYLOADS:
                probe = self._set_param_value(cand["url"], cand["param"], tmpl.format(v=base_value, d=delay))
                elapsed = self._timed_get(probe, session, req_timeout)
                if elapsed is None or elapsed < delay or (elapsed - baseline) < delay * 0.7:
                    continue
                # Confirm with double the delay to rule out a coincidentally slow response.
                confirm_probe = self._set_param_value(cand["url"], cand["param"], tmpl.format(v=base_value, d=confirm))
                confirm_elapsed = self._timed_get(confirm_probe, session, req_timeout)
                if confirm_elapsed is not None and confirm_elapsed >= confirm * 0.7 and confirm_elapsed > elapsed:
                    cand["score"] = max(cand["score"], 0.9)
                    cand["reasons"] = cand["reasons"] + [
                        f"time-based blind: sleep {delay}s→{elapsed:.1f}s, sleep {confirm}s→{confirm_elapsed:.1f}s"]
                    cand["time_confirmed"] = True
                    cand["time_payload"] = tmpl.format(v=base_value, d=delay)
                    cand["time_delay"] = round(elapsed, 1)
                    break

    def _timed_get(self, url: str, session, timeout: float) -> float | None:
        start = time.monotonic()
        resp = self.http_get(url, session=session, timeout=timeout, verify=False)
        if resp is None:
            return None
        return time.monotonic() - start

    # ── External-tool runner (timeout-safe) ───────────────────────────────────────
    def _exec_to_file(self, cmd: list[str], out_path: Path, timeout: int, label: str):
        """Run a tool with output streamed to a file so a timeout-kill keeps any
        confirmation it already printed (exec() drops stdout on timeout)."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shell_cmd = " ".join(shlex.quote(c) for c in cmd) + f" > {shlex.quote(str(out_path))} 2>&1"
        return self.exec(shell_cmd, timeout=timeout, shell=True, label=label)

    @staticmethod
    def _read_tool_output(out_path: Path) -> str:
        try:
            return out_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # ── commix ──────────────────────────────────────────────────────────────────
    def _run_commix(self, cand: dict, cfg: dict, index: int) -> list[dict]:
        out_dir = self.module_dir / "commix"
        cmd = ["commix", "-u", cand["url"], "-p", cand["param"], "--batch",
               "--output-dir", str(out_dir),
               "--level", str(self._bounded(cfg.get("level", 1), 1, 3))]
        for arg in cfg.get("commix_extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())
        stdout_file = f"commix/run_{index:03d}.txt"
        out_path = self.module_dir / stdout_file
        self._exec_to_file(cmd, out_path, int(cfg.get("commix_timeout", 300)),
                           f"commix {cand['param']}@{cand['path']}")
        output = self._read_tool_output(out_path)
        if not COMMIX_HIT_RE.search(output):
            return []
        hits = [ln.strip() for ln in output.splitlines() if COMMIX_HIT_RE.search(ln)]
        return [self._confirmed_finding(cand, "commix", 0.9,
                                        {"hits": hits[:5], "stdout_file": stdout_file})]

    # ── ffuf + SecLists wordlist ────────────────────────────────────────────────
    def _run_ffuf(self, cand: dict, wordlist: str, cfg: dict, index: int) -> list[dict]:
        fuzz_url = self._inject_fuzz(cand["url"], cand["param"])
        out = self.module_dir / "ffuf" / f"cmdi_{index:03d}.json"
        cmd = ["ffuf", "-u", fuzz_url, "-w", f"{wordlist}:FUZZ", "-mc", "all",
               "-mr", FFUF_CMDI_REGEX, "-t", str(self._bounded(cfg.get("threads", 30), 1, 100)),
               "-timeout", str(self._bounded(cfg.get("request_timeout", 10), 1, 120)),
               "-of", "json", "-o", str(out), "-s", "-noninteractive"]
        self.exec(cmd, timeout=int(cfg.get("ffuf_timeout", 300)), label=f"ffuf CMDi {cand['param']}")
        data = self.load_json(out)
        results = data.get("results", []) if isinstance(data, dict) else []
        findings: list[dict] = []
        for res in results[: int(cfg.get("max_ffuf_hits", 5))]:
            payload = (res.get("input", {}) or {}).get("FUZZ", "")
            if payload:
                findings.append(self._confirmed_finding(cand, "ffuf", 0.8,
                    {"payload": payload, "match_url": res.get("url", ""),
                     "status": res.get("status"), "wordlist": Path(wordlist).name}))
                break  # one confirmation per parameter is enough
        return findings

    # ── Findings ────────────────────────────────────────────────────────────────
    def _confirmed_finding(self, cand: dict, tool: str, confidence: float, extra: dict) -> dict:
        return self.make_finding(
            "command_injection_detected",
            cand.get("url", ""),
            title=f"OS command injection via '{cand['param']}' (confirmed by {tool})",
            description=("User input on this parameter reached an OS command. "
                         "An injected payload executed on the server — treat as critical."),
            severity="CRITICAL",
            confidence=confidence,
            finding_type="command_injection",
            exploitability="confirmed",
            evidence={"param": cand["param"], "path": cand.get("path", ""),
                      "tool": tool, "score": cand["score"], "reasons": cand["reasons"], **extra},
        )

    def _candidate_finding(self, cand: dict, strong: float) -> dict:
        tier = "likely" if cand["score"] >= strong else "possible"
        return self.make_finding(
            "cmdi_candidate_parameter",
            cand["url"],
            title=f"{tier.capitalize()} command-injection parameter: {cand['param']}",
            description=("Parameter scored as a probable OS command-injection point. "
                         + "; ".join(cand["reasons"]) + ". Unconfirmed — validated with commix/ffuf when likely."),
            severity="MEDIUM" if cand["score"] >= strong else "LOW",
            confidence=min(0.85, 0.4 + cand["score"] * 0.4),
            finding_type="command_injection",
            exploitability="candidate",
            evidence={"param": cand["param"], "value": str(cand["value"])[:80],
                      "path": cand["path"], "score": cand["score"],
                      "reasons": cand["reasons"], "sources": cand["sources"], "tier": tier},
        )

    # ── Helpers ─────────────────────────────────────────────────────────────────
    def _wordlist(self, cfg: dict) -> str:
        for path in [str(cfg.get("wordlist", "")).strip(), DEFAULT_CMDI_WORDLIST,
                     DEFAULT_CMDI_WORDLIST.replace("/usr/share/wordlists/seclists", "/opt/SecLists")]:
            if path and Path(path).exists():
                return path
        return ""

    @staticmethod
    def _query_params(url: str) -> set:
        return {name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name}

    @staticmethod
    def _with_param(url: str, param: str) -> str:
        parsed = urlparse(url)
        query = f"{parsed.query}&{urlencode({param: 'reconx'})}" if parsed.query else urlencode({param: "reconx"})
        return urlunparse(parsed._replace(query=query))

    def _inject_fuzz(self, url: str, param: str) -> str:
        return self._set_param_value(url, param, "FUZZ")

    @staticmethod
    def _set_param_value(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        names = {k for k, _ in pairs}
        updated = [(k, value if k == param else v) for k, v in pairs]
        if param not in names:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    @staticmethod
    def _base(url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query="", fragment=""))

    @staticmethod
    def _bounded(value, minimum: int, maximum: int) -> int:
        try:
            return max(minimum, min(maximum, int(value)))
        except (TypeError, ValueError):
            return minimum
