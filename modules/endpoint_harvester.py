"""
ReconX — Module: Endpoint Harvester.

Aggregates several best-of-breed endpoint-discovery tools into one pass and
normalises their output into a single deduplicated, scope-filtered, classified
endpoint set:

  * cariddi      — crawls the known URL set and extracts endpoints, request
                   parameters, secrets and "juicy" info (JSON mode, one pass).
  * LinkFinder   — pulls endpoints out of each discovered JavaScript bundle.
  * xnLinkFinder — pulls endpoints *and* parameters out of the seed URL list.
  * kiterunner   — API-route brute-forcing (aggressive; OFF by default, enabled
                   by the deep / intrusive presets or explicit config).

gau / waybackurls already run in the recon module, so passive URL harvesting is
not duplicated here — recon's URLs are consumed as seeds instead.

Every tool is optional: a missing binary is logged and skipped, never fatal.
"""

import re
import shlex
from pathlib import Path
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule
from modules.finding_registry import build_finding

# ── Endpoint classification ───────────────────────────────────────────────────
# Lightweight, offline regex classification of "what kind of endpoint is this".
# Patterns require the token to be a path segment (preceded by '/' and followed
# by '/', end-of-path, query, or a spec extension) to avoid substring false hits.
ENDPOINT_PATTERNS: dict[str, str] = {
    "api": (
        r"(?:^|/)(api|rest|graphql|graphiql|rpc|jsonrpc|jsonapi|odata|"
        r"wp-json|hasura|services?|_matrix)(?:/|$|\?|\.json|\.ya?ml)"
        r"|(?:^|/)v[0-9]+(?:\.[0-9]+)?(?:/|$|\?)"
    ),
    "auth": (
        r"(?:^|/)(login|logout|signin|sign_in|signup|sign_up|register|"
        r"auth|authn|authenticate|oauth2?|openid|connect|sso|saml2?|acs|"
        r"token|tokens|refresh|session|sessions|password|passwd|forgot|"
        r"reset|recover|verify|verification|mfa|otp|2fa|totp|webauthn)"
        r"(?:/|$|\?)"
    ),
    "admin": (
        r"(?:^|/)(admin|administrator|manage|management|dashboard|console|"
        r"cpanel|plesk|webmin|phpmyadmin|wp-admin|grafana|kibana|jenkins|"
        r"portainer|prometheus|traefik|kong|sonarqube|actuator)(?:/|$|\?)"
    ),
    "docs": (
        r"(?:^|/)(swagger(?:-ui)?|openapi|api-docs|apidocs|redoc|"
        r"graphql-playground)(?:/|$|\?|\.json|\.ya?ml)"
    ),
    "graphql": r"(?:^|/)graphi?ql(?:/|$|\?)",
    "websocket": r"^wss?://|(?:^|/)(ws|wss|websocket|socket\.io)(?:/|$|\?)",
    "sensitive_files": (
        r"\.(env|git|bak|backup|old|sql|db|sqlite|dump|log|config|cfg|conf|ini|"
        r"key|pem|p12|pfx|zip|tar|gz|tgz|map|swp|orig)(\?|$)"
    ),
    "static": (
        r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|webp|"
        r"pdf|mp3|avif)(\?|$)"
    ),
}

# A query string with at least one key=value pair → parameterised endpoint.
PARAM_RE = re.compile(r"\?[^=\s]+=")
# kiterunner output rows: "GET    200 [   1234,   56,    7] https://host/path ..."
KR_LINE_RE = re.compile(r"https?://[^\s'\"<>]+")


class EndpointHarvesterModule(BaseModule):
    name = "endpoint_harvester"
    description = "Endpoint Harvesting (cariddi, LinkFinder, xnLinkFinder, kiterunner)"
    # Left empty so the module always runs and degrades per-tool — mirrors fuzzer.
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 recon_results: dict | None = None,
                 fuzzer_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.recon_results = recon_results or {}
        self.fuzzer_results = fuzzer_results or {}
        for sub in ("cariddi", "linkfinder", "xnlinkfinder", "kiterunner", "merged"):
            (self.module_dir / sub).mkdir(exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────
    def module_config(self) -> dict:
        cfg = self.config.get("scan", {}).get(self.name, {})
        return cfg if isinstance(cfg, dict) else {}

    def run(self) -> dict:
        cfg = self.module_config()
        if not cfg.get("enabled", True):
            return {"status": "disabled", "total_endpoints": 0, "total": 0}

        seeds = self._seed_urls(cfg)
        if not seeds:
            self.warn("No seed URLs for endpoint harvesting")
            return {"total_endpoints": 0, "total": 0, "classified": {}}
        self.save_text(seeds, "seeds.txt")
        self.info(f"Harvesting endpoints from {len(seeds)} seed URL(s)")

        endpoints: set[str] = set(seeds)
        secrets: list[dict] = []
        parameters: list[dict] = []
        infos: list[dict] = []
        sources: dict[str, int] = {}

        # 1. cariddi — crawl + secrets + params + juicy info (single JSON pass)
        if cfg.get("cariddi", True) and self.has_tool("cariddi"):
            eps, secs, params, juicy = self._run_cariddi(seeds, cfg)
            endpoints |= eps
            secrets.extend(secs)
            parameters.extend(params)
            infos.extend(juicy)
            sources["cariddi"] = len(eps)
        elif cfg.get("cariddi", True):
            self.info("cariddi not found — skipping crawl")

        # 2. LinkFinder — endpoints from JavaScript bundles
        if cfg.get("linkfinder", True):
            lf_cmd = self._linkfinder_command(cfg)
            if lf_cmd:
                eps = self._run_linkfinder(lf_cmd, cfg)
                endpoints |= eps
                sources["linkfinder"] = len(eps)
            else:
                self.info("LinkFinder not found — skipping JS link extraction")

        # 3. xnLinkFinder — endpoints + params from the seed list
        if cfg.get("xnlinkfinder", True):
            xn_cmd = self._xnlinkfinder_command(cfg)
            if xn_cmd:
                eps, params = self._run_xnlinkfinder(xn_cmd, cfg)
                endpoints |= eps
                parameters.extend(params)
                sources["xnlinkfinder"] = len(eps)
            else:
                self.info("xnLinkFinder not found — skipping")

        # 4. kiterunner — API route brute-force (gated; off by default)
        if cfg.get("kiterunner", False):
            kr_bin = self._kiterunner_binary()
            if kr_bin:
                eps = self._run_kiterunner(kr_bin, cfg)
                endpoints |= eps
                sources["kiterunner"] = len(eps)
            else:
                self.info("kiterunner (kr) not found — skipping API brute-force")

        merged = self.filter_in_scope_urls(endpoints)
        self.save_text(merged, "merged/all_endpoints.txt")
        classified = self._classify(merged)
        parameters = self._dedupe_params(parameters)

        if secrets:
            self.save_json(secrets, "merged/secrets.json")
        if parameters:
            self.save_text(sorted({p["param"] for p in parameters}), "merged/parameters.txt")

        findings = self._build_findings(classified, secrets, parameters)
        if findings:
            self.save_json(findings, "endpoint_harvester_findings.json")

        self.success(
            f"{len(merged)} endpoints "
            f"({', '.join(f'{k}:{v}' for k, v in sources.items()) or 'seeds only'}) | "
            f"{len(parameters)} params | {len(secrets)} secret(s)"
        )
        return {
            "total_endpoints": len(merged),
            "total": len(findings),
            "all_endpoints": merged,
            "classified": classified,
            "parameters": parameters,
            "secrets": secrets,
            "juicy_info": infos,
            "sources": sources,
            "findings": findings,
            "total_findings": len(findings),
        }

    def summary(self) -> str:
        r = self.results
        return (f"🧭 {r.get('total_endpoints', 0)} endpoints | "
                f"🔑 {len(r.get('secrets', []))} secrets | "
                f"⚙ {len(r.get('parameters', []))} params")

    # ── Seed collection ─────────────────────────────────────────────────────────
    def _seed_urls(self, cfg: dict) -> list[str]:
        """Build the seed URL set from recon URLs, fuzzer endpoints and live hosts."""
        seeds: set[str] = set()
        # recon's gau / waybackurls / katana harvest
        for url in self.recon_results.get("all_urls", []) or []:
            seeds.add(str(url))
        # fuzzer's crawled + classified endpoints
        seeds.update(str(u) for u in self.fuzzer_results.get("all_endpoints", []) or [])
        # live host roots
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                seeds.add(m.group(0))
        scoped = self.filter_in_scope_urls(seeds)
        return scoped[: int(cfg.get("max_seeds", 200))]

    def _js_urls(self, cfg: dict) -> list[str]:
        """JavaScript bundle URLs discovered by the fuzzer (for LinkFinder)."""
        js = [str(u) for u in self.fuzzer_results.get("js_urls", []) or []]
        if not js:
            # Fall back to any *.js endpoint in the merged set.
            js = [u for u in self.fuzzer_results.get("all_endpoints", []) or []
                  if re.search(r"\.m?js(?:[?#]|$)", str(u), re.I)]
        js = self.filter_in_scope_urls(js)
        return js[: int(cfg.get("max_js", 100))]

    # ── cariddi ─────────────────────────────────────────────────────────────────
    # ── Timeout-safe tool runner ──────────────────────────────────────────────
    def _exec_to_file(self, cmd: list[str], out_path: Path, timeout: int, label: str):
        """Run a tool with stdout streamed to a file so a timeout-kill keeps
        whatever it already produced (exec() drops stdout on a timeout)."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shell_cmd = " ".join(shlex.quote(c) for c in cmd) + f" > {shlex.quote(str(out_path))} 2>/dev/null"
        return self.exec(shell_cmd, timeout=timeout, shell=True, label=label)

    def _run_cariddi(self, seeds: list[str], cfg: dict) -> tuple[set[str], list, list, list]:
        self.info("cariddi crawl")
        seeds_file = self.module_dir / "cariddi" / "seeds.txt"
        self.save_text(seeds, "cariddi/seeds.txt")
        out = self.module_dir / "cariddi" / "output.jsonl"

        if self._reuse_output(out, cfg):
            return self._parse_cariddi(self.load_lines(out))

        args = ["cariddi", "-json", "-c", str(int(cfg.get("cariddi_concurrency", 20)))]
        if cfg.get("cariddi_intensive"):
            args.append("-intensive")
        if cfg.get("cariddi_collect_secrets", True):
            args.append("-s")
        args += ["-e", "-info", "-juicy"]

        # Stream cariddi's JSON output straight to the file so a long crawl that
        # outlasts the timeout still yields whatever it already wrote.
        cmd = (f"cat {shlex.quote(str(seeds_file))} | " + " ".join(shlex.quote(a) for a in args)
               + f" > {shlex.quote(str(out))} 2>/dev/null")
        self.exec(cmd, timeout=int(cfg.get("timeout", 300)), shell=True, label="cariddi")
        lines = self.load_lines(out)
        return self._parse_cariddi(lines, redact=not cfg.get("retain_raw_secrets", False))

    def _parse_cariddi(self, lines: list[str], redact: bool = True) -> tuple[set[str], list, list, list]:
        """Parse cariddi's JSON-lines stream into endpoints, secrets, params, info."""
        import json
        endpoints: set[str] = set()
        secrets: list[dict] = []
        parameters: list[dict] = []
        juicy: list[dict] = []
        for line in lines:
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                # Tolerate plain-URL lines if cariddi emitted any.
                for u in self.extract_urls(line):
                    endpoints.add(u)
                continue
            if not isinstance(obj, dict):
                continue
            url = obj.get("url") or obj.get("URL") or ""
            if url:
                endpoints.add(url)
            matches = obj.get("matches") or obj.get("Matches") or {}
            if not isinstance(matches, dict):
                continue
            for sec in matches.get("secrets") or matches.get("Secrets") or []:
                if isinstance(sec, dict):
                    raw = str(sec.get("match") or sec.get("Match", ""))
                    secrets.append({
                        "url": url,
                        "name": sec.get("name") or sec.get("Name", "secret"),
                        "match": self._redact(raw) if redact else raw,
                    })
            for prm in matches.get("parameters") or matches.get("Parameters") or []:
                name = prm.get("name") or prm.get("Name") if isinstance(prm, dict) else prm
                if name:
                    parameters.append({"url": url, "param": str(name), "source": "cariddi"})
            for info in matches.get("infos") or matches.get("Infos") or []:
                if isinstance(info, dict):
                    juicy.append({"url": url, "name": info.get("name", "info"),
                                  "match": str(info.get("match", ""))})
        return endpoints, secrets, parameters, juicy

    # ── LinkFinder ───────────────────────────────────────────────────────────────
    def _run_linkfinder(self, lf_cmd: list[str], cfg: dict) -> set[str]:
        js_urls = self._js_urls(cfg)
        if not js_urls:
            self.info("LinkFinder: no JavaScript URLs to scan")
            return set()
        self.info(f"LinkFinder over {len(js_urls)} JS bundle(s)")
        timeout = int(cfg.get("timeout", 300))
        found: set[str] = set()
        for index, js in enumerate(js_urls, start=1):
            out = self.module_dir / "linkfinder" / f"run_{index:03d}.txt"
            self._exec_to_file(lf_cmd + ["-i", js, "-o", "cli"], out, timeout, f"linkfinder {js}")
            base = f"{urlparse(js).scheme}://{urlparse(js).netloc}"
            for line in self.load_lines(out):
                ep = line.strip()
                # LinkFinder `-o cli` prints one endpoint per line; skip blanks,
                # banner text (contains spaces) and comment markers.
                if not ep or " " in ep or ep.startswith("#"):
                    continue
                if ep.startswith("http"):
                    found.add(ep)
                elif ep.startswith("/"):
                    found.add(urljoin(base + "/", ep.lstrip("/")))
        scoped = set(self.filter_in_scope_urls(found))
        self.save_text(sorted(scoped), "linkfinder/endpoints.txt")
        return scoped

    # ── xnLinkFinder ───────────────────────────────────────────────────────────
    def _run_xnlinkfinder(self, xn_cmd: list[str], cfg: dict) -> tuple[set[str], list]:
        self.info("xnLinkFinder over seed list")
        seeds_file = self.module_dir / "seeds.txt"
        links_out = self.module_dir / "xnlinkfinder" / "links.txt"
        params_out = self.module_dir / "xnlinkfinder" / "parameters.txt"
        self.exec(
            xn_cmd + ["-i", str(seeds_file), "-o", str(links_out),
                      "-op", str(params_out), "-sf", self.domain],
            timeout=int(cfg.get("timeout", 300)),
            label="xnLinkFinder",
        )
        endpoints: set[str] = set()
        base = self.live_http_root()
        for ep in self.load_lines(links_out):
            if ep.startswith("http"):
                endpoints.add(ep)
            elif ep.startswith("/") and base:
                endpoints.add(urljoin(base, ep))
        params = [{"url": "", "param": p, "source": "xnlinkfinder"}
                  for p in self.load_lines(params_out)]
        scoped = set(self.filter_in_scope_urls(endpoints))
        return scoped, params

    # ── kiterunner ───────────────────────────────────────────────────────────────
    def _run_kiterunner(self, kr_bin: str, cfg: dict) -> set[str]:
        hosts = self.filter_in_scope_urls(
            [item.get("url", "") if isinstance(item, dict) else str(item)
             for item in self.live_hosts]
        )
        if not hosts:
            hosts = [self.live_http_root()] if self.live_http_root() else []
        if not hosts:
            self.info("kiterunner: no live hosts to scan")
            return set()
        hosts_file = self.module_dir / "kiterunner" / "hosts.txt"
        self.save_text(hosts, "kiterunner/hosts.txt")
        self.info(f"kiterunner API brute-force over {len(hosts)} host(s)")

        args = [kr_bin, "scan", str(hosts_file),
                "-x", str(int(cfg.get("kiterunner_concurrency", 10)))]
        wordlist = str(cfg.get("kiterunner_wordlist", "")).strip()
        if wordlist and Path(wordlist).exists():
            args += ["-w", wordlist]
        else:
            alias = "apiroutes-large" if cfg.get("kiterunner_intensive") else "apiroutes-220628"
            args += [f"-A={alias}"]
        if cfg.get("kiterunner_max_routes"):
            args += ["-d", str(int(cfg["kiterunner_max_routes"]))]

        out = self.module_dir / "kiterunner" / "scan.txt"
        self._exec_to_file(args, out, int(cfg.get("timeout", 600)), "kiterunner")
        found: set[str] = set()
        for line in self.load_lines(out):
            for url in KR_LINE_RE.findall(line):
                found.add(url)
        scoped = set(self.filter_in_scope_urls(found))
        self.save_text(sorted(scoped), "kiterunner/routes.txt")
        return scoped

    # ── Classification & findings ────────────────────────────────────────────────
    def _classify(self, urls: list[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {cat: [] for cat in ENDPOINT_PATTERNS}
        result["with_params"] = []
        for url in urls:
            for cat, pattern in ENDPOINT_PATTERNS.items():
                if re.search(pattern, url, re.IGNORECASE):
                    result[cat].append(url)
            if PARAM_RE.search(url):
                result["with_params"].append(url)
        # api/auth should not be polluted by static asset paths.
        for cat in ("api", "auth"):
            result[cat] = [u for u in result[cat]
                           if not re.search(ENDPOINT_PATTERNS["static"], u, re.I)]
        for cat, items in result.items():
            uniq = sorted(set(items))
            result[cat] = uniq
            if uniq:
                self.save_text(uniq, f"merged/{cat}.txt")
        return result

    def _build_findings(self, classified: dict, secrets: list, parameters: list) -> list[dict]:
        findings: list[dict] = []

        for sec in secrets:
            findings.append(build_finding(
                self.name, "endpoint_secret_exposed",
                url=sec.get("url", ""),
                evidence={"secret_name": sec.get("name", ""), "match": sec.get("match", ""),
                          "source": "cariddi"},
                title=f"Secret exposed in crawled response: {sec.get('name', 'secret')}",
            ))

        admin = classified.get("admin", [])
        if admin:
            findings.append(build_finding(
                self.name, "endpoint_admin_surface",
                url=admin[0],
                evidence={"count": len(admin), "sample": admin[:15]},
            ))

        sensitive = classified.get("sensitive_files", [])
        if sensitive:
            findings.append(build_finding(
                self.name, "endpoint_sensitive_file_reference",
                url=sensitive[0],
                evidence={"count": len(sensitive), "sample": sensitive[:15]},
            ))

        api = classified.get("api", [])
        if api:
            findings.append(build_finding(
                self.name, "endpoint_api_surface",
                url=api[0],
                evidence={"count": len(api), "sample": api[:20],
                          "params_discovered": len(parameters)},
            ))
        return findings

    # ── Tool resolution helpers ────────────────────────────────────────────────
    def _linkfinder_command(self, cfg: dict) -> list[str] | None:
        return self._resolve_script(
            "linkfinder", cfg.get("linkfinder_path"),
            ["/opt/LinkFinder/linkfinder.py", "/usr/share/LinkFinder/linkfinder.py"],
        )

    def _xnlinkfinder_command(self, cfg: dict) -> list[str] | None:
        return self._resolve_script(
            "xnLinkFinder", cfg.get("xnlinkfinder_path"),
            ["/opt/xnLinkFinder/xnLinkFinder.py"],
        )

    def _resolve_script(self, binary: str, configured: str | None,
                         candidates: list[str]) -> list[str] | None:
        """Resolve a tool to either an on-PATH binary or a `python3 <script.py>` call."""
        if self.has_tool(binary):
            return [binary]
        for path in [configured] + candidates:
            if path and Path(path).exists():
                return ["python3", path]
        return None

    def _kiterunner_binary(self) -> str | None:
        for name in ("kr", "kiterunner"):
            if self.has_tool(name):
                return name
        return None

    # ── Small utilities ──────────────────────────────────────────────────────────
    def live_http_root(self) -> str:
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s/]+", line)
            if m:
                return m.group(0)
        if self.domain:
            return f"https://{self.domain}"
        return ""

    def _reuse_output(self, path: Path, cfg: dict) -> bool:
        if not cfg.get("reuse_outputs", True):
            return False
        if path.exists() and path.stat().st_size > 0:
            self.info(f"  resume checkpoint → {path.name}")
            return True
        return False

    @staticmethod
    def _dedupe_params(parameters: list[dict]) -> list[dict]:
        seen: set = set()
        out: list[dict] = []
        for p in parameters:
            key = (p.get("url", ""), p.get("param", ""))
            if p.get("param") and key not in seen:
                seen.add(key)
                out.append(p)
        return out

    @staticmethod
    def _redact(value: str) -> str:
        value = value.strip()
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"
