"""
ReconX — Module: Web Application Detection
Tools: httpx (status, title, tech), gowitness (screenshots, optional)
Input:  subdomains list + port scan HTTP ports
Output: live_hosts list used by all downstream modules
"""

import re
import json
from pathlib import Path

from modules.base import BaseModule


class WebdetectModule(BaseModule):
    name = "webdetect"
    description = "Web Application Detection (httpx)"
    required_tools = ["httpx"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        # live_hosts from recon.py httpx step (if already done there)
        self._prior_live = live_hosts or []

    def run(self) -> dict:
        # Build candidate list: subdomains + HTTP ports from portscan
        candidates = self._collect_candidates()
        if not candidates:
            self.warn("No candidates to probe")
            return {"live_hosts": [], "counts": {}}

        candidates_file = self.module_dir / "candidates.txt"
        self.save_text(candidates, "candidates.txt")

        # Run httpx
        live = self._run_httpx(candidates_file)

        # Screenshots (optional)
        if self.config.get("scan", {}).get("http", {}).get("screenshots", False):
            if self.has_tool("gowitness"):
                self._run_gowitness(candidates_file)

        counts = {
            "total":          len(live),
            "status_200":     sum(1 for h in live if h.get("status") == 200),
            "status_redirect":sum(1 for h in live if h.get("status") in (301, 302, 307, 308)),
            "status_auth":    sum(1 for h in live if h.get("status") in (401, 403)),
        }

        # Write clean URL list for downstream modules
        live_urls = [h["url"] for h in live]
        self.save_text(live_urls, "live_urls.txt")
        self.save_json(live, "live_hosts.json")

        self.success(f"{len(live)} live web apps found")
        return {"live_hosts": live, "live_urls": live_urls, "counts": counts}

    # ── collect candidates ────────────────────────────────────────────────────

    def _collect_candidates(self) -> list[str]:
        cands: set[str] = set()

        # From recon subdomains
        sub_file = self.session_path("recon", "all_subdomains.txt")
        for sub in self.load_lines(sub_file):
            cands.add(f"http://{sub}")
            cands.add(f"https://{sub}")

        # From port scan — add HTTP-ish ports
        ps_file = self.session_path("portscan", "ports_by_host.json")
        if ps_file.exists():
            HTTP_PORTS  = {80, 8000, 8080, 8081, 8082, 8083, 8088, 8090}
            HTTPS_PORTS = {443, 8443, 8444, 9443, 4443}
            try:
                hosts_data = json.loads(ps_file.read_text())
                for h in hosts_data:
                    ip = h.get("ip", "")
                    for p in h.get("open_ports", []):
                        port = p.get("port", 0)
                        if port in HTTP_PORTS:
                            cands.add(f"http://{ip}:{port}")
                        elif port in HTTPS_PORTS:
                            cands.add(f"https://{ip}:{port}")
            except Exception:
                pass

        return sorted(cands)

    def session_path(self, module: str, filename: str) -> Path:
        return self.output_dir / module / filename

    # ── httpx ─────────────────────────────────────────────────────────────────

    def _run_httpx(self, candidates_file: Path) -> list[dict]:
        if not self.has_tool("httpx"):
            self.warn("httpx not found — using curl fallback")
            return self._curl_probe(self.load_lines(candidates_file))

        out_jsonl = self.module_dir / "httpx_raw.jsonl"
        threads   = self.config.get("scan", {}).get("threads", 50)

        self.exec(
            ["httpx",
             "-l", str(candidates_file),
             "-status-code", "-title", "-tech-detect",
             "-server", "-content-length", "-follow-redirects",
             "-threads", str(threads),
             "-silent", "-no-color", "-json",
             "-o", str(out_jsonl)],
            timeout=600,
        )

        live: list[dict] = []
        if not out_jsonl.exists():
            return live

        for line in out_jsonl.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                live.append({
                    "url":            e.get("url", ""),
                    "status":         e.get("status-code", 0),
                    "title":          e.get("title", ""),
                    "server":         e.get("webserver", ""),
                    "content_length": e.get("content-length", 0),
                    "technologies":   e.get("technologies", []),
                    "final_url":      e.get("final-url", e.get("url", "")),
                    "ip":             e.get("host", ""),
                    "screenshot":     "",
                })
            except json.JSONDecodeError:
                # plain text fallback: "https://example.com [200] [Title Here]"
                m = re.match(r"(https?://\S+)\s+\[(\d+)\]", line)
                if m:
                    live.append({"url": m.group(1), "status": int(m.group(2)),
                                 "title": "", "server": "", "content_length": 0,
                                 "technologies": [], "final_url": m.group(1),
                                 "ip": "", "screenshot": ""})
        return live

    def _curl_probe(self, urls: list[str]) -> list[dict]:
        """Minimal fallback when httpx is missing."""
        import subprocess
        live: list[dict] = []
        for url in urls[:200]:  # cap to 200 for curl
            try:
                r = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "8", "-L", "-k", url],
                    capture_output=True, text=True, timeout=12,
                )
                code = r.stdout.strip()
                if code and code != "000":
                    live.append({"url": url, "status": int(code), "title": "",
                                 "server": "", "content_length": 0,
                                 "technologies": [], "final_url": url,
                                 "ip": "", "screenshot": ""})
            except Exception:
                pass
        return live

    # ── gowitness ─────────────────────────────────────────────────────────────

    def _run_gowitness(self, candidates_file: Path) -> None:
        shots_dir = self.module_dir / "screenshots"
        shots_dir.mkdir(exist_ok=True)
        self.info("Taking screenshots (gowitness)...")
        self.exec(
            ["gowitness", "file",
             "-f", str(candidates_file),
             "--screenshot-path", str(shots_dir),
             "--threads", "5",
             "--timeout", "15",
             "--disable-logging"],
            timeout=600,
        )
        count = len(list(shots_dir.glob("*.png")))
        self.success(f"Screenshots: {count}")
