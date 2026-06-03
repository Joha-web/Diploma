"""
ReconX — Module: SSRF candidate scoring + SSRFmap exploitation.

Two layers:

  1. **Where might SSRF exist?** A non-intrusive scorer ranks every discovered
     (url, parameter) by SSRF likelihood from three signal groups — the
     parameter VALUE shape (is it already a URL/host?), the parameter NAME
     (url, redirect, webhook, proxy, image…), and the endpoint PATH context
     (/proxy, /fetch, /preview…). Anything injection_probe already flagged as
     SSRF is force-promoted. Each candidate carries human-readable reasons.

  2. **Confirm with SSRFmap.** For the high-scoring candidates, generate a raw
     HTTP request file and run SSRFmap (swisskyrepo/SSRFmap) against the target
     parameter. This runs automatically whenever SSRFmap is installed and the
     module is enabled (set `scan.ssrf_probe.use_ssrfmap: false` to score
     candidates only). It is active — it makes the server reach internal
     services and cloud metadata — but only against in-scope, scored targets.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase

# ── SSRF-likelihood signals ───────────────────────────────────────────────────
SSRF_HIGH_PARAMS = frozenset({
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirecturl", "redirect_url", "return", "returnurl",
    "return_url", "returnto", "return_to", "next", "continue", "callback",
    "callback_url", "webhook", "webhook_url", "proxy", "proxy_url", "fetch",
    "fetchurl", "load", "loadurl", "image", "imageurl", "image_url", "img",
    "imgurl", "file", "fileurl", "file_url", "path", "document", "page",
    "pageurl", "feed", "feedurl", "host", "target", "targeturl", "to", "out",
    "domain", "site", "siteurl", "remote", "remoteurl", "upload_url", "uploadurl",
    "download_url", "downloadurl", "endpoint", "server", "serverurl", "forward",
    "forwardurl", "rss", "oembed", "avatar", "avatar_url", "thumbnail",
    "screenshot", "preview", "render", "import", "importurl", "sitemap", "wsdl",
    "gateway",
})
SSRF_MEDIUM_PARAMS = frozenset({
    "data", "ref", "reference", "view", "show", "open", "openurl", "share",
    "shareurl", "window", "u", "q", "req", "request", "location", "address",
    "addr",
})
SSRF_PATH_HINTS = re.compile(
    r"(proxy|fetch|preview|thumbnail|thumb|image|img|pdf|render|screenshot|"
    r"import|webhook|callback|convert|export|oembed|feed|rss|sitemap|fromurl|"
    r"from-url|by-url|byurl|remote|crawl|scrape|resolve|dns|whois|ping)",
    re.I,
)
URL_VALUE_RE = re.compile(r"^\s*(?:https?:|ftp:|gopher:|dict:|file:|//)", re.I)
HOST_VALUE_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$", re.I)
RESOURCE_VALUE_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|pdf|xml|json|rss|ico)(?:$|[?#])", re.I)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Output lines that signal SSRFmap actually reached something internal.
SSRFMAP_HIT_RE = re.compile(
    r"(is responsive|port\s+\d+\s+(?:is\s+)?open|open port|ami-id|instance-id|"
    r"security-credentials|iam/security|computeMetadata|meta-data/|"
    r"root:[^:]*:0:0:|internal ip|metadata|reachable|leaked|vulnerable|"
    r"is alive|responded)",
    re.I,
)


class SSRFProbeModule(ActiveProbeBase):
    name = "ssrf_probe"
    description = "SSRF Candidate Scoring & SSRFmap"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 parameter_results: dict | None = None,
                 fuzzer_results: dict | None = None,
                 injection_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.injection_results = injection_results or {}
        self.live_hosts = live_hosts or []
        (self.module_dir / "requests").mkdir(exist_ok=True)
        (self.module_dir / "ssrfmap").mkdir(exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────
    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "candidates": [], "total": 0, "status": "disabled"}

        cfg = self.module_config()
        possible = float(cfg.get("possible_threshold", 0.35))
        strong = float(cfg.get("strong_threshold", 0.6))

        candidates = self._collect_candidates()
        scored = [c for c in candidates if c["score"] >= possible]
        scored.sort(key=lambda c: c["score"], reverse=True)
        self.save_json(scored, "ssrf_candidates.json")

        findings: list[dict] = [self._candidate_finding(c, strong) for c in scored]

        # SSRFmap confirmation — runs automatically whenever it is enabled and
        # the tool is installed (set use_ssrfmap: false to score candidates only).
        ssrfmap_runs: list[dict] = []
        run_ssrfmap = cfg.get("use_ssrfmap", True)
        ssrfmap_cmd = self._ssrfmap_command(cfg) if run_ssrfmap else None

        if scored and run_ssrfmap and not ssrfmap_cmd:
            self.info("SSRFmap not found (set scan.ssrf_probe.ssrfmap_path or /opt/SSRFmap) "
                      "— reporting scored candidates only")
        elif scored and not run_ssrfmap:
            self.info(f"{len(scored)} SSRF candidate(s) scored; SSRFmap disabled (use_ssrfmap: false)")
        elif ssrfmap_cmd:
            strong_candidates = [c for c in scored if c["score"] >= strong]
            targets = self.limit(strong_candidates, "max_targets", 15)
            self.info(f"SSRFmap over {len(targets)} high-likelihood candidate(s)")
            for index, cand in enumerate(targets, start=1):
                conf, run = self._run_ssrfmap(ssrfmap_cmd, cand, cfg, index)
                findings.extend(conf)
                ssrfmap_runs.append(run)

        findings = self.dedup_findings(findings)
        self.save_json(findings, "ssrf_findings.json")
        return {
            "findings": findings,
            "candidates": scored,
            "total": len(findings),
            "candidate_count": len(scored),
            "ssrfmap_runs": ssrfmap_runs,
            "ssrfmap_used": bool(ssrfmap_cmd),
        }

    def summary(self) -> str:
        r = self.results
        confirmed = sum(1 for f in r.get("findings", []) if f.get("id") == "ssrfmap_confirmed")
        return f"🎯 {r.get('candidate_count', 0)} SSRF candidate(s), {confirmed} confirmed"

    # ── Candidate collection & scoring ──────────────────────────────────────────
    def _collect_candidates(self) -> list[dict]:
        candidates: dict[tuple[str, str], dict] = {}

        def add(url: str, param: str, value: str, method: str, source: str, forced: bool = False):
            url = str(url or "").strip()
            param = str(param or "").strip()
            if not url.startswith(("http://", "https://")) or not param:
                return
            if not self.is_in_scope(url):
                return
            parsed = urlparse(url)
            base = urlunparse(parsed._replace(query="", fragment=""))
            key = (base, param.lower())
            score, reasons = self._score(param, value, parsed.path)
            if forced:
                score = max(score, 0.95)
                reasons = reasons + ["flagged by injection_probe SSRF detection"]
            entry = candidates.get(key)
            if entry is None or score > entry["score"]:
                candidates[key] = {
                    "url": url, "param": param, "value": value,
                    "method": str(method or "GET").upper(), "path": parsed.path,
                    "score": round(min(score, 1.0), 2), "reasons": reasons,
                    "sources": [source], "forced": forced,
                }
            elif source not in entry["sources"]:
                entry["sources"].append(source)

        # parameter_discovery — (url, param), value parsed from the URL if present
        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                url = item.get("url", "")
                param = item.get("param") or item.get("name", "")
                value = dict(parse_qsl(urlparse(url).query)).get(param, "")
                add(url, param, value, item.get("method", "GET"),
                    item.get("source", "parameter_discovery"))

        # fuzzer — every parameterised URL contributes its (param, value) pairs
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls = set(classified.get("with_params", []) or [])
        urls.update(u for u in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(u))
        urls.update(self.parameter_results.get("parameterized_targets", []) or [])
        for url in urls:
            for param, value in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
                add(str(url), param, value, "GET", "fuzzer")

        # injection_probe — promote anything it already flagged as SSRF
        for finding in self.injection_results.get("findings", []) or []:
            if "ssrf" in str(finding.get("id", "")).lower():
                ev = finding.get("evidence", {}) or {}
                add(finding.get("url") or finding.get("matched_url", ""),
                    ev.get("param", ""), ev.get("value", ""), "GET",
                    "injection_probe", forced=True)

        return list(candidates.values())

    def _score(self, param: str, value: str, path: str) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        pname = (param or "").strip().lower()
        val = str(value or "").strip()

        # 1. value shape — strongest signal (the app already accepts a URL here)
        if URL_VALUE_RE.match(val):
            score += 0.6
            reasons.append(f"value is a URL ({val[:48]})")
        elif HOST_VALUE_RE.match(val):
            score += 0.35
            reasons.append("value is a host/IP")
        elif RESOURCE_VALUE_RE.search(val):
            score += 0.15
            reasons.append("value is a fetchable resource")

        # 2. parameter name
        if pname in SSRF_HIGH_PARAMS:
            score += 0.45
            reasons.append(f"param name '{param}' is SSRF-prone")
        elif pname in SSRF_MEDIUM_PARAMS:
            score += 0.25
            reasons.append(f"param name '{param}' is sometimes SSRF-prone")

        # 3. endpoint path context (the feature is a URL fetcher)
        hit = SSRF_PATH_HINTS.search(path or "")
        if hit:
            score += 0.25
            reasons.append(f"endpoint path suggests URL fetch ('{hit.group(0)}')")

        return min(score, 1.0), reasons

    def _candidate_finding(self, cand: dict, strong: float) -> dict:
        tier = "likely" if cand["score"] >= strong else "possible"
        return self.make_finding(
            "ssrf_candidate_parameter",
            cand["url"],
            title=f"{tier.capitalize()} SSRF parameter: {cand['param']}",
            description=("Parameter scored as a probable SSRF sink. " + "; ".join(cand["reasons"])
                         + ". Unconfirmed — validate with SSRFmap or manually."),
            severity="MEDIUM" if cand["score"] >= strong else "LOW",
            confidence=min(0.85, 0.4 + cand["score"] * 0.4),
            finding_type="ssrf",
            exploitability="candidate",
            evidence={
                "param": cand["param"], "value": cand["value"][:80],
                "method": cand["method"], "path": cand["path"],
                "score": cand["score"], "reasons": cand["reasons"],
                "sources": cand["sources"], "tier": tier,
            },
        )

    # ── SSRFmap ─────────────────────────────────────────────────────────────────
    def _ssrfmap_command(self, cfg: dict) -> list[str] | None:
        if self.has_tool("ssrfmap"):
            return ["ssrfmap"]
        for path in [str(cfg.get("ssrfmap_path", "")).strip(),
                     "/opt/SSRFmap/ssrfmap.py", "/usr/share/SSRFmap/ssrfmap.py"]:
            if path and Path(path).exists():
                return ["python3", path]
        return None

    def _run_ssrfmap(self, base_cmd: list[str], cand: dict, cfg: dict, index: int) -> tuple[list[dict], dict]:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{cand['path']}_{cand['param']}").strip("_")[:120]
        req_file = self.module_dir / "requests" / f"req_{index:03d}_{safe}.txt"
        req_file.write_text(self._raw_request(cand), encoding="utf-8")

        modules = cfg.get("ssrfmap_modules", "portscan,readfiles,aws,gce,alibaba,digitalocean")
        cmd = base_cmd + ["-r", str(req_file), "-p", cand["param"], "-m", modules]
        # Optional native listener for blind/OOB SSRF (SSRFmap uses its own handler,
        # not interactsh) — only when the user supplies a reachable lhost.
        lhost = str(cfg.get("lhost", "")).strip()
        if lhost:
            cmd += ["--lhost", lhost, "--lport", str(cfg.get("lport", 8080))]
        for arg in cfg.get("ssrfmap_extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())

        timeout = int(cfg.get("ssrfmap_timeout", cfg.get("timeout", 600)))
        result = self.exec(cmd, timeout=timeout, label=f"ssrfmap {cand['param']}@{cand['path']}")
        output = ANSI_RE.sub("", "\n".join(p for p in (result.stdout, result.stderr) if p))
        out_file = f"ssrfmap/run_{index:03d}.txt"
        self.save_text(output, out_file)
        findings = self._parse_ssrfmap(output, cand, modules, out_file, index)
        return findings, {
            "url": cand["url"], "param": cand["param"], "modules": modules,
            "returncode": result.returncode, "stdout_file": out_file, "findings": len(findings),
        }

    def _raw_request(self, cand: dict) -> str:
        parsed = urlparse(cand["url"])
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc
        return (
            f"{cand['method']} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 ReconX/2.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

    def _parse_ssrfmap(self, output: str, cand: dict, modules: str,
                       out_file: str, index: int) -> list[dict]:
        hits = [line.strip() for line in output.splitlines() if SSRFMAP_HIT_RE.search(line)]
        if not hits:
            return []
        return [self.make_finding(
            "ssrfmap_confirmed",
            cand["url"],
            title=f"SSRF confirmed by SSRFmap on parameter '{cand['param']}'",
            description=("SSRFmap reached an internal/cloud resource through this parameter. "
                         "Validate the impact (internal service / metadata) manually."),
            severity="HIGH",
            confidence=0.85,
            finding_type="ssrf",
            exploitability="confirmed",
            evidence={
                "param": cand["param"], "path": cand["path"], "modules": modules,
                "hits": hits[:10], "run_index": index, "stdout_file": out_file,
                "candidate_score": cand["score"], "reasons": cand["reasons"],
            },
        )]
