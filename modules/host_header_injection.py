"""
ReconX - Module: Host header injection and reset poisoning indicators.
"""

import uuid
from urllib.parse import urlparse

import requests

from modules.base import BaseModule


RESET_KEYWORDS = ("reset", "forgot", "password", "recover", "account")


class HostHeaderInjectionModule(BaseModule):
    name = "host_header_injection"
    description = "Host Header Injection / Password Reset Poisoning"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 fuzzer_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.fuzzer_results = fuzzer_results or {}
        self.marker = f"reconx-host-{uuid.uuid4().hex[:8]}.invalid"

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("host_header_injection", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._targets()[: int(cfg.get("max_urls", 80))]
        if not targets:
            self.warn("No URLs for Host header injection checks")
            return {"findings": [], "total": 0}

        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for url in targets:
            findings.extend(self._probe(url, session, cfg))

        findings = self._dedup(findings)
        self.save_json(findings, "host_header_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _probe(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        findings: list[dict] = []
        parsed = urlparse(url)
        if not parsed.hostname:
            return findings
        header_sets = [
            {"Host": self.marker},
            {"X-Forwarded-Host": self.marker},
            {"X-Host": self.marker},
            {"X-Original-Host": self.marker},
            # NOTE: X-Forwarded-Proto: http is intentionally excluded — it does
            # not carry the random marker so it can never trigger a confirmed finding.
        ]
        baseline = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        baseline_text = (baseline.text or "") if baseline else ""
        for headers in header_sets:
            resp = self.http_get(
                url, session=session, headers=headers, allow_redirects=False,
                timeout=float(cfg.get("timeout", 10)), verify=False,
            )
            if resp is None:
                continue
            body = resp.text or ""
            location = resp.headers.get("Location", "")
            evidence = {
                "headers": headers,
                "status_code": resp.status_code,
                "location": location[:300],
                "marker": self.marker,
            }
            if self.marker in location:
                findings.append(self._finding("host_header_redirect", "HIGH", url, "Host header reflected in redirect Location", evidence))
            elif self.marker in body and self.marker not in baseline_text:
                evidence["excerpt"] = self._excerpt(body, self.marker)
                is_reset = self._looks_like_reset(url)
                findings.append(self._finding(
                    "password_reset_poisoning_indicator" if is_reset else "host_header_reflection",
                    "HIGH" if is_reset else "MEDIUM",
                    url,
                    "Password reset poisoning indicator" if is_reset else "Host header reflected in response body",
                    evidence,
                ))
        return findings

    def _targets(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("auth", "with_params"):
            urls.update(str(url) for url in classified.get(key, []) or [])
        urls.update(self.load_lines(self.session_path("webdetect", "live_urls.txt")))
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def _looks_like_reset(url: str) -> bool:
        lowered = url.lower()
        return any(keyword in lowered for keyword in RESET_KEYWORDS)

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 100) -> str:
        idx = body.find(marker)
        if idx < 0:
            return body[:200]
        return body[max(0, idx - radius): idx + len(marker) + radius]

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            key = (finding.get("id", ""), finding.get("url", ""), str(finding.get("evidence", {}).get("headers", {})))
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result

    def _finding(self, finding_id: str, severity: str, url: str, title: str, evidence: dict) -> dict:
        return {
            "source": self.name,
            "id": finding_id,
            "type": finding_id,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": (
                "The application appears to trust attacker-controlled host override headers. "
                "On account recovery flows this can enable password reset poisoning."
            ),
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/host-header"],
            "confidence": 0.8,
        }
