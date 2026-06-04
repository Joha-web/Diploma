"""
ReconX — Module: CMS Vulnerability Scanning
Auto-detects CMS from techstack results, then runs the right scanner:
  WordPress → wpscan
  Joomla    → joomscan
  Drupal    → droopescan
  Moodle    → droopescan
"""

import json
import os
import re
import shlex
from modules.base import BaseModule

# wpscan -e value enumerating everything: all plugins/themes, timthumbs,
# config backups, db exports, users and media IDs. Aggressive but thorough.
WPSCAN_FULL_ENUMERATE = "ap,at,tt,cb,dbe,u,m"

CMS_SCANNERS: dict[str, dict] = {
    "WordPress": {
        "tool": "wpscan",
        "build": lambda url, cfg: [
            "wpscan", "--url", url,
            # -e with the full enumeration set (configurable via scan.cms.enumerate)
            "-e", cfg.get("enumerate", WPSCAN_FULL_ENUMERATE),
            "--random-user-agent", "--no-banner",
            "--format", "json",
            *(["--plugins-detection", cfg["plugins_detection"]]
              if cfg.get("plugins_detection") else []),
            # Pull live vulnerability data from the WPScan API when a token exists.
            *(["--api-token", cfg["wpscan_api_token"]]
              if cfg.get("wpscan_api_token") else []),
        ],
    },
    "Joomla": {
        "tool": "joomscan",
        # -ec → full component enumeration
        "build": lambda url, cfg: ["joomscan", "-u", url, "-ec"],
    },
    "Drupal": {
        "tool": "droopescan",
        # -e a → enumerate all (version, plugins, themes, interesting URLs)
        "build": lambda url, cfg: [
            "droopescan", "scan", "drupal", "-u", url, "-e", "a", "-t", "8"
        ],
    },
    "Moodle": {
        "tool": "droopescan",
        "build": lambda url, cfg: [
            "droopescan", "scan", "moodle", "-u", url, "-e", "a", "-t", "8"
        ],
    },
}


class CMSScanModule(BaseModule):
    name = "cmscan"
    description = "CMS Vulnerability Scanning"
    required_tools = ["wpscan", "joomscan", "droopescan"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 tech_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.tech_results = tech_results or {}

    def run(self) -> dict:
        cms_targets = self._detect_cms()
        if not cms_targets:
            self.info("No CMS detected — skipping")
            return {"scans": [], "total_findings": 0}

        cms_cfg = dict(self.config.get("scan", {}).get("cms", {}))
        wpscan_token = self._wpscan_api_token(cms_cfg)
        if wpscan_token:
            cms_cfg["wpscan_api_token"] = wpscan_token
        wordpress_detected = "WordPress" in cms_targets
        if wordpress_detected and not wpscan_token:
            self.warn("No WPScan API token — CVE/vulnerability data will be limited "
                      "(set api_keys.wpscan, WPSCAN_API_TOKEN, or scan.cms.wpscan_api_token)")
        scans: list[dict] = []

        for cms_name, urls in cms_targets.items():
            info = CMS_SCANNERS.get(cms_name)
            if not info:
                continue
            if not self.has_tool(info["tool"]):
                self.warn(f"{info['tool']} not installed — skipping {cms_name}")
                continue

            for url in urls:
                self.info(f"{cms_name} @ {url}")
                cmd  = info["build"](url, cms_cfg)
                safe = re.sub(r"https?://|[/:]", "_", url)
                raw  = self.module_dir / f"{cms_name.lower()}_{safe}.txt"

                # Stream tool stdout straight to the file. wpscan with full
                # enumeration (ap,at) is slow and can outlast the timeout; exec()
                # discards stdout on a timeout-kill, so a confirmed CMS finding
                # would be lost. Reading the file keeps whatever was written.
                shell_cmd = " ".join(shlex.quote(c) for c in cmd) + f" > {shlex.quote(str(raw))} 2>/dev/null"
                self.exec(shell_cmd, timeout=int(cms_cfg.get("timeout", 600)), shell=True,
                          label=f"{info['tool']} {url}")
                output = raw.read_text(encoding="utf-8", errors="replace") if raw.exists() else ""

                findings = self._parse(cms_name, info["tool"], output, url)
                # Surface the missing-token limitation directly in the report.
                if cms_name == "WordPress" and not wpscan_token:
                    findings.insert(0, self._no_token_finding())

                scans.append({
                    "cms":            cms_name,
                    "url":            url,
                    "tool":           info["tool"],
                    "findings":       findings,
                    "findings_count": len(findings),
                    "api_token_used": bool(wpscan_token) if cms_name == "WordPress" else None,
                })

                if findings:
                    self.warn(f"  {len(findings)} finding(s) for {url}")
                else:
                    self.success(f"  No findings for {url}")

        total = sum(s["findings_count"] for s in scans)
        self.save_json(scans, "cms_scan_results.json")
        if total:
            self.warn(f"⚠  Total CMS findings: {total}")

        return {
            "scans": scans,
            "total_findings": total,
            "wordpress_detected": wordpress_detected,
            "wpscan_api_token_used": bool(wpscan_token),
        }

    @staticmethod
    def _no_token_finding() -> dict:
        return {
            "type": "wpscan_no_api_token",
            "severity": "INFO",
            "name": "WPScan API token",
            "title": ("No WPScan API token configured — wpscan ran without the WPScan "
                      "Vulnerability Database, so plugin/theme/core CVE data is limited. "
                      "Set api_keys.wpscan, the WPSCAN_API_TOKEN env var, or "
                      "scan.cms.wpscan_api_token to enable full vulnerability lookups."),
        }

    # ── CMS detection ─────────────────────────────────────────────────────────

    def _detect_cms(self) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for h in self.tech_results.get("hosts", []):
            url = h.get("url", "")
            if url and not self.is_in_scope(url):
                continue
            for t in h.get("technologies", []):
                name = t.get("name", "")
                # Normalize name
                for known in CMS_SCANNERS:
                    if known.lower() in name.lower():
                        found.setdefault(known, [])
                        if url not in found[known]:
                            found[known].append(url)
                        break
        # Also check cms_detected from techstack summary
        for entry in self.tech_results.get("cms_detected", []):
            name = entry.get("name", "")
            url  = entry.get("url", "")
            if url and not self.is_in_scope(url):
                continue
            for known in CMS_SCANNERS:
                if known.lower() in name.lower():
                    found.setdefault(known, [])
                    if url not in found[known]:
                        found[known].append(url)
                    break

        for cms, urls in found.items():
            self.info(f"Detected {cms} on {len(urls)} host(s)")
        return found

    def _wpscan_api_token(self, cms_cfg: dict) -> str:
        """Resolve WPScan token from CMS config, shared API keys, or environment."""
        return (
            cms_cfg.get("wpscan_api_token")
            or self.config.get("api_keys", {}).get("wpscan")
            or os.getenv("WPSCAN_API_TOKEN", "")
        )

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse(self, cms: str, tool: str, output: str, url: str) -> list[dict]:
        if tool == "wpscan":
            return self._parse_wpscan(output)
        return self._parse_generic(output)

    def _parse_wpscan(self, output: str) -> list[dict]:
        findings: list[dict] = []
        # Try JSON parse first (--format json)
        try:
            data = json.loads(output)

            # Vulnerable plugins
            for name, info in data.get("plugins", {}).items():
                for v in info.get("vulnerabilities", []):
                    findings.append({
                        "type":     "vulnerable_plugin",
                        "severity": self._cvss_severity(v.get("cvss", {})),
                        "name":     name,
                        "title":    v.get("title", ""),
                        "cve":      v.get("references", {}).get("cve", []),
                    })

            # Vulnerable themes
            for name, info in data.get("themes", {}).items():
                for v in info.get("vulnerabilities", []):
                    findings.append({
                        "type":     "vulnerable_theme",
                        "severity": "MEDIUM",
                        "name":     name,
                        "title":    v.get("title", ""),
                    })

            # Outdated WordPress core
            version = data.get("version", {})
            if version.get("status") == "insecure":
                findings.append({
                    "type":     "outdated_core",
                    "severity": "HIGH",
                    "name":     "WordPress core",
                    "title":    f"Outdated version: {version.get('number', '?')}",
                })

            # Users
            for uid, info in data.get("users", {}).items():
                findings.append({
                    "type":     "user_enumerated",
                    "severity": "LOW",
                    "name":     info.get("username", uid),
                    "title":    "User enumerated",
                })

        except (json.JSONDecodeError, Exception):
            return self._parse_generic(output)

        return findings

    def _parse_generic(self, output: str) -> list[dict]:
        findings: list[dict] = []
        keywords = re.compile(
            r"(vulnerab|CVE-\d{4}|exploit|outdated|insecure|CRITICAL|WARNING|FOUND)",
            re.IGNORECASE,
        )
        for line in output.splitlines():
            if keywords.search(line):
                sev = "CRITICAL" if "CRITICAL" in line.upper() else \
                      "HIGH"     if "CVE-"    in line          else "MEDIUM"
                findings.append({
                    "type":     "raw_finding",
                    "severity": sev,
                    "title":    line.strip()[:200],
                })
        return findings

    @staticmethod
    def _cvss_severity(cvss) -> str:
        score = cvss.get("score", 0) if isinstance(cvss, dict) else 0
        if score >= 9:  return "CRITICAL"
        if score >= 7:  return "HIGH"
        if score >= 4:  return "MEDIUM"
        return "LOW"
