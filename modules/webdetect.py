"""
ReconX — Module: Web Application Detection
Tools: httpx (status, title, tech), gowitness (screenshots, optional)
Input:  subdomains list + port scan HTTP ports
Output: live_hosts list used by all downstream modules
"""

import re
import json
from pathlib import Path
from urllib.parse import urlparse

from modules.base import BaseModule


class WebdetectModule(BaseModule):
    name = "webdetect"
    description = "Web Application Detection (httpx)"
    required_tools = []

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

        counts = {
            "total":          len(live),
            "status_200":     sum(1 for h in live if h.get("status") == 200),
            "status_redirect":sum(1 for h in live if h.get("status") in (301, 302, 307, 308)),
            "status_auth":    sum(1 for h in live if h.get("status") in (401, 403)),
        }

        # Write clean URL list for downstream modules
        live_urls = [h["url"] for h in live]
        self.save_text(live_urls, "live_urls.txt")

        screenshots: list[dict] = []
        if live_urls and self.config.get("scan", {}).get("http", {}).get("screenshots", False):
            if self.has_tool("gowitness"):
                screenshots = self._run_gowitness(self.module_dir / "live_urls.txt")
                self._attach_screenshots(live, screenshots)
            else:
                self.warn("gowitness not found - screenshots skipped")

        self.save_json(live, "live_hosts.json")
        if screenshots:
            self.save_json(screenshots, "screenshots.json")

        self.success(f"{len(live)} live web apps found")
        return {
            "live_hosts": live,
            "live_urls": live_urls,
            "counts": counts,
            "screenshots": screenshots,
        }

    # ── collect candidates ────────────────────────────────────────────────────

    def _collect_candidates(self) -> list[str]:
        cands: set[str] = set()

        for url in self._prior_live:
            if isinstance(url, dict):
                url = url.get("url", "")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                cands.add(url.split()[0])

        # From recon subdomains (file is at recon/subdomains/all_subdomains.txt)
        sub_file = self.session_path("recon", "subdomains", "all_subdomains.txt")
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

        return self.filter_in_scope_urls(cands)

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
                url = e.get("url", "")
                final_url = e.get("final-url", url)
                if not self.is_in_scope(url) or (final_url and not self.is_in_scope(final_url)):
                    continue
                live.append({
                    "url":            url,
                    "status":         e.get("status-code", 0),
                    "title":          e.get("title", ""),
                    "server":         e.get("webserver", ""),
                    "content_length": e.get("content-length", 0),
                    "technologies":   e.get("technologies", []),
                    "final_url":      final_url,
                    "ip":             e.get("host", ""),
                    "screenshot":     "",
                })
            except json.JSONDecodeError:
                # plain text fallback: "https://example.com [200] [Title Here]"
                m = re.match(r"(https?://\S+)\s+\[(\d+)\]", line)
                if m:
                    if not self.is_in_scope(m.group(1)):
                        continue
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
            if not self.is_in_scope(url):
                continue
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

    def _run_gowitness(self, urls_file: Path) -> list[dict]:
        shots_dir = self.module_dir / "screenshots"
        shots_dir.mkdir(exist_ok=True)
        self.info("Taking screenshots (gowitness)...")
        self.exec(
            ["gowitness", "file",
             "-f", str(urls_file),
             "--screenshot-path", str(shots_dir),
             "--threads", "5",
             "--timeout", "15",
             "--disable-logging"],
            timeout=600,
        )
        shots = [
            {
                "path": str(path),
                "relative_path": str(path.relative_to(self.output_dir)),
                "filename": path.name,
            }
            for path in sorted(shots_dir.glob("*.png"))
        ]
        count = len(shots)
        self.success(f"Screenshots: {count}")
        return shots

    def _attach_screenshots(self, live: list[dict], screenshots: list[dict]) -> None:
        unused = list(screenshots)
        for host in live:
            url = host.get("url", "")
            match = self._match_screenshot(url, unused)
            if not match:
                continue
            host["screenshot"] = match["relative_path"]
            match["url"] = url
            unused.remove(match)

    @staticmethod
    def _match_screenshot(url: str, screenshots: list[dict]) -> dict | None:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        host_token = WebdetectModule._compact_token(hostname)
        if not host_token:
            return None
        port = parsed.port
        default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
        netloc_token = f"{host_token}{port}" if port and not default_port else host_token

        scored: list[tuple[int, dict]] = []
        for shot in screenshots:
            filename = shot.get("filename", "")
            file_host_token = WebdetectModule._screenshot_host_token(filename)
            file_token = WebdetectModule._compact_token(filename)
            if port is None and WebdetectModule._looks_like_port_variant(file_host_token, host_token):
                continue
            if file_host_token == netloc_token:
                scored.append((0, shot))
            elif file_host_token == host_token:
                scored.append((1, shot))
            elif file_host_token.startswith(netloc_token):
                scored.append((2, shot))
            elif file_host_token.startswith(host_token):
                scored.append((3, shot))
            elif file_token.startswith((f"http{host_token}", f"https{host_token}")):
                scored.append((4, shot))
            elif hostname.count(".") >= 2 and host_token in file_token:
                scored.append((5, shot))

        if not scored:
            return None
        scored.sort(key=lambda item: item[0])
        return scored[0][1]

    @staticmethod
    def _compact_token(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

    @staticmethod
    def _screenshot_host_token(filename: str) -> str:
        stem = Path(str(filename or "")).stem.lower()
        stem = re.sub(r"^(?:https?|httpx?)[^a-z0-9]+", "", stem)
        stem = stem.strip("._- ")
        return WebdetectModule._compact_token(stem)

    @staticmethod
    def _looks_like_port_variant(file_host_token: str, host_token: str) -> bool:
        if not file_host_token.startswith(host_token):
            return False
        suffix = file_host_token[len(host_token):]
        return bool(suffix) and suffix.isdigit()
