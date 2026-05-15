"""
ReconX - Module: CORS misconfiguration checks.

The module sends read-only GET probes with controlled Origin headers and reports
only concrete CORS header evidence.
"""

from urllib.parse import urlparse

import requests

from modules.base import BaseModule


class CORSCheckerModule(BaseModule):
    name = "cors_checker"
    description = "CORS Misconfiguration Scanner"
    required_tools: list[str] = []

    ORIGIN_PROBES = [
        ("reflected_origin", "https://attacker-reconx.com", "HIGH"),
        ("null_origin", "null", "HIGH"),
        ("prefix_bypass", "https://{domain}.attacker-reconx.com", "HIGH"),
        ("suffix_bypass", "https://evil{domain}", "HIGH"),
        ("unrelated_domain", "https://notexample.com", "HIGH"),
    ]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("cors_checker", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        urls = self._extract_urls()[: int(cfg.get("max_urls", 200))]
        if not urls:
            self.warn("No URLs for CORS checks")
            return {"findings": [], "total": 0}

        sess = requests.Session()
        sess.verify = False
        findings: list[dict] = []
        for url in urls:
            findings.extend(self._check_url(url, sess))
        findings = self._dedup(findings)

        self.save_json(findings, "cors_findings.json")
        if findings:
            self.warn(f"CORS findings: {len(findings)}")
        else:
            self.success("No CORS misconfigurations detected")
        return {"findings": findings, "total": len(findings)}

    def _check_url(self, url: str, sess: requests.Session) -> list[dict]:
        findings: list[dict] = []
        domain = urlparse(url).hostname or self.domain

        for probe_name, origin_template, severity in self.ORIGIN_PROBES:
            origin = origin_template.format(domain=domain)
            resp = self.http_get(
                url,
                session=sess,
                headers={"Origin": origin, "User-Agent": "ReconX/2.0"},
                timeout=8,
                verify=False,
            )
            if resp is None:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if not acao:
                continue

            finding_type = ""
            actual_severity = severity
            if acao == "*":
                finding_type = "cors_wildcard_origin"
                actual_severity = "MEDIUM"
            elif origin == "null" and acao == "null":
                finding_type = "cors_null_origin"
            elif acao == origin:
                finding_type = f"cors_{probe_name}"

            if not finding_type:
                continue
            if acao != "*" and acac == "true" and actual_severity != "CRITICAL":
                actual_severity = "CRITICAL"

            findings.append({
                "source": self.name,
                "id": finding_type,
                "type": finding_type,
                "name": "CORS policy trusts untrusted origin",
                "title": "CORS policy trusts untrusted origin",
                "severity": actual_severity,
                "url": url,
                "matched_url": url,
                "description": (
                    "The application returned permissive CORS headers for a "
                    "controlled untrusted Origin value."
                ),
                "evidence": {
                    "origin_sent": origin,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                    "browser_note": (
                        "Browsers reject credentialed CORS reads when ACAO is '*'."
                        if acao == "*" and acac == "true" else ""
                    ),
                },
                "poc": self._poc(url, origin, acac == "true"),
                "confidence": 0.95,
            })

        return self._dedup(findings)

    @staticmethod
    def _poc(url: str, origin: str, credentialed: bool) -> str:
        creds = "credentials: 'include', " if credentialed else ""
        return (
            f"// Host this page on {origin}; the browser will set the Origin header.\n"
            f"fetch('{url}', {{{creds}}})"
            ".then(r => r.text()).then(console.log)"
        )

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            evidence = finding.get("evidence", {}) or {}
            key = (
                finding.get("id", ""),
                finding.get("url", ""),
                evidence.get("access_control_allow_origin", ""),
                evidence.get("access_control_allow_credentials", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return result

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        return self.filter_in_scope_urls(urls)
