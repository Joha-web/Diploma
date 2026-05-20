"""
ReconX - Module: virtual host enumeration with ffuf.
"""

import random
import re
from pathlib import Path

from modules.base import BaseModule


class VHostEnumModule(BaseModule):
    name = "vhost_enum"
    description = "Virtual Host Enumeration"
    required_tools = ["ffuf"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 resolved_ips: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.resolved_ips = resolved_ips or []
        self._vhost_baseline_redirect = False

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("vhost_enum", {})
        if not cfg.get("enabled", True):
            return {"found": [], "total": 0, "status": "disabled"}

        ips = self._target_ips()[: int(cfg.get("max_ips", 40))]
        wordlist = self._wordlist(cfg.get("wordlist", "subdomains-top1million-5000.txt"))
        if not ips or not wordlist:
            self.warn("No IPs or wordlist for vhost enumeration")
            return {"found": [], "total": 0}

        found: list[dict] = []
        rate = str(cfg.get("rate", 50))
        for ip in ips:
            self._vhost_baseline_redirect = False
            baseline = self._baseline_size(ip)
            out = self.module_dir / f"vhost_{ip.replace('.', '_')}.json"
            cmd = [
                "ffuf", "-u", f"http://{ip}/",
                "-H", f"Host: FUZZ.{self.domain}",
                "-w", wordlist,
                "-mc", "200,201,204,401,403",
                "-t", "30", "-rate", rate,
                "-of", "json", "-o", str(out), "-s",
            ]
            if baseline != "0":
                cmd.extend(["-fs", baseline])
            if self._vhost_baseline_redirect:
                cmd.extend(["-fc", "301,302,307,308"])
            self.exec(cmd, timeout=int(cfg.get("timeout", 600)), label=f"ffuf vhost {ip}")

            data = self.load_json(out)
            for row in data.get("results", []) if isinstance(data, dict) else []:
                fuzz = row.get("input", {}).get("FUZZ", "")
                if not fuzz:
                    continue
                vhost = f"{fuzz}.{self.domain}"
                if not self._verify_vhost(vhost, ip):
                    self.info(f"VHost {vhost} failed HTTP verification — skipped")
                    continue
                found.append({
                    "ip": ip,
                    "vhost": vhost,
                    "status": row.get("status", 0),
                    "size": row.get("length", 0),
                    "url": f"http://{vhost}/",
                })
                self.warn(f"VHost found: {vhost} -> {ip}")

        self.save_json(found, "vhosts.json")
        return {"found": found, "total": len(found)}

    def _target_ips(self) -> list[str]:
        ips = set(str(ip) for ip in self.resolved_ips if self._is_ip(str(ip)))
        for item in self.live_hosts:
            if isinstance(item, dict) and self._is_ip(str(item.get("ip", ""))):
                ips.add(str(item["ip"]))
        return sorted(ips)

    def _baseline_size(self, ip: str) -> str:
        resp = self.http_get(
            f"http://{ip}/",
            enforce_scope=False,
            headers={"Host": f"nxvhost-{random.randint(10000, 99999)}.{self.domain}"},
            timeout=8,
            verify=False,
            allow_redirects=False,
        )
        if resp is not None and resp.status_code in (301, 302, 307, 308):
            self._vhost_baseline_redirect = True
        return str(len(resp.content)) if resp is not None else "0"

    def _verify_vhost(self, vhost: str, ip: str) -> bool:
        """Verify that a discovered vhost serves meaningful content."""
        resp = self.http_get(
            f"http://{ip}/",
            enforce_scope=False,
            headers={"Host": vhost},
            timeout=6,
            verify=False,
            allow_redirects=False,
        )
        if resp is None or resp.status_code not in (200, 201, 204, 401, 403):
            return False
        # 401/403 with the configured Host header is meaningful — accept directly.
        if resp.status_code in (401, 403):
            return True
        # Minimum content size — not an empty/error page
        return len(resp.content) > 200

    def _wordlist(self, filename: str) -> str:
        paths = self.config.get("wordlists", {}).get("search_paths", [])
        for base in paths:
            for candidate in Path(base).rglob(filename) if Path(base).exists() else []:
                if candidate.is_file():
                    return str(candidate)
        return ""
