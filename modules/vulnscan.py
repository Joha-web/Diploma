"""
ReconX — Module: Vulnerability Scanning (Nuclei)
Runs nuclei against all live web hosts using configurable
severity levels and template categories.
"""

import re
import json
from pathlib import Path
from modules.base import BaseModule


class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "Vulnerability Scanning (Nuclei)"
    required_tools = ["nuclei"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 parameter_results: dict | None = None,
                 openapi_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.parameter_results = parameter_results or {}
        self.openapi_results = openapi_results or {}

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self.config.get("scan", {}).get("nuclei", {}).get("enabled", True):
            self.info("Nuclei disabled in config")
            return {"findings": [], "by_severity": {}, "total": 0, "status": "disabled"}

        urls = self._extract_urls()
        if not urls:
            self.warn("No URLs for vulnerability scanning")
            return {"findings": [], "by_severity": {}, "total": 0}

        url_file = self.module_dir / "target_urls.txt"
        self.save_text(urls, "target_urls.txt")

        # Update nuclei templates before scanning (best practice)
        self._update_templates()

        out_file = self.module_dir / "nuclei_results.jsonl"
        self._run_nuclei(url_file, out_file)

        findings = self._parse_results(out_file)
        by_sev   = self._group_by_severity(findings)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = len(by_sev.get(sev, []))
            if count:
                icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
                self.warn(f"{icon} {sev}: {count} finding(s)")

        self.save_json(findings, "nuclei_findings.json")

        return {
            "findings":    findings,
            "by_severity": {k: len(v) for k, v in by_sev.items()},
            "total":       len(findings),
        }

    def summary(self) -> str:
        total = self.results.get("total", 0)
        by_sev = self.results.get("by_severity", {})
        parts = [f"{k}: {v}" for k, v in by_sev.items() if v > 0]
        return f"🚨 {total} findings ({', '.join(parts) or 'none'})"

    # ── Nuclei runner ─────────────────────────────────────────────────────────

    def _update_templates(self):
        """Update nuclei templates. Uses BaseModule.exec() for safety."""
        self.info("Updating Nuclei templates...")
        r = self.exec(["nuclei", "-update-templates", "-silent"], timeout=120)
        if r.returncode == 0:
            self.success("Templates up to date")
        else:
            self.warn("Template update failed — continuing with existing templates")

    def _run_nuclei(self, url_file: Path, out_file: Path):
        ncfg = self.config.get("scan", {}).get("nuclei", {})
        severity  = ",".join(ncfg.get("severity", ["critical", "high", "medium"]))
        rate      = str(ncfg.get("rate_limit", 150))
        templates = ncfg.get("templates", ["cves", "exposures", "misconfiguration",
                                           "takeovers"])
        enable_risky = ncfg.get("enable_risky", False)
        if not enable_risky:
            risky_templates = {"default-logins", "fuzzing", "workflows"}
            templates = [t for t in templates if t not in risky_templates]
        exclude_tags = ncfg.get("exclude_tags", ["dos", "intrusive", "bruteforce", "destructive"])

        cmd = [
            "nuclei",
            "-l",        str(url_file),
            "-severity", severity,
            "-rl",       rate,
            "-jsonl",
            "-o",        str(out_file),
            "-silent",
            "-no-color",
            "-timeout",  "10",
            "-retries",  "1",
        ]
        for t in templates:
            cmd.extend(["-t", t])
        if exclude_tags and not enable_risky:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        if ncfg.get("dashboard_upload") and self.config.get("api_keys", {}).get("pdcp"):
            cmd.append("-dashboard")

        timeout = ncfg.get("nuclei_timeout", 3600)
        self.info(f"nuclei → {self._line_count(url_file)} URLs | severity: {severity}")
        self.exec(cmd, timeout=timeout)
        self.success(f"nuclei finished → {self._line_count(out_file)} raw findings")

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_results(self, out_file: Path) -> list[dict]:
        findings: list[dict] = []
        if not out_file.exists():
            return findings

        for line in out_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                matched_url = obj.get("matched-at", "")
                if matched_url and not self.is_in_scope(matched_url):
                    continue
                cves = sorted({
                    cve.upper()
                    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", json.dumps(obj, default=str), re.I)
                })
                findings.append({
                    "template_id":   obj.get("template-id", ""),
                    "name":          info.get("name", ""),
                    "severity":      info.get("severity", "info").upper(),
                    "description":   info.get("description", "")[:400],
                    "matched_url":   matched_url,
                    "type":          obj.get("type", ""),
                    "tags":          info.get("tags", []),
                    "cves":          cves,
                    "reference":     info.get("reference", [])[:3],
                    "curl_command":  obj.get("curl-command", "")[:500],
                    "extracted":     obj.get("extracted-results", [])[:5],
                    "confidence":    0.95 if obj.get("matcher-status") else 0.85,
                })
            except json.JSONDecodeError:
                continue

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: order.get(x["severity"], 5))
        return findings

    @staticmethod
    def _group_by_severity(findings: list[dict]) -> dict[str, list]:
        groups: dict[str, list] = {}
        for f in findings:
            groups.setdefault(f["severity"], []).append(f)
        return groups

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        for item in self.parameter_results.get("parameterized_targets", []) or []:
            if isinstance(item, str):
                urls.add(item)
        for item in self.openapi_results.get("endpoints", []) or []:
            if isinstance(item, dict) and item.get("url"):
                urls.add(item["url"])
        return self.filter_in_scope_urls(urls)

    def _line_count(self, path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for _ in path.read_text(errors="replace").splitlines() if _.strip())
