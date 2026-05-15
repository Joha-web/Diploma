"""
ReconX - Module: generic open redirect probes.
"""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from modules.base import BaseModule


REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_url", "return", "returnUrl", "continue", "dest", "destination")
REDIRECT_PARAM_NAMES = {name.lower() for name in REDIRECT_PARAMS}


class OpenRedirectProbeModule(BaseModule):
    name = "open_redirect_probe"
    description = "Generic Open Redirect Detection"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 fuzzer_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("open_redirect_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._targets()[: int(cfg.get("max_targets", 120))]
        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for url in targets:
            finding = self._probe(url, session, cfg)
            if finding:
                findings.append(finding)
        findings = self._dedup(findings)
        self.save_json(findings, "open_redirect_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _probe(self, url: str, session: requests.Session, cfg: dict) -> dict | None:
        parsed = urlparse(url)
        params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        names = [name for name in params if name.lower() in REDIRECT_PARAM_NAMES]
        if not names:
            names = [name for name in REDIRECT_PARAMS if name.lower() in parsed.path.lower()]
        if not names:
            return None
        for name in names[:3]:
            probe_url = self._replace_or_add(url, name, "https://attacker.reconx.invalid/")
            resp = self.http_get(
                probe_url, session=session, allow_redirects=False,
                timeout=float(cfg.get("timeout", 8)), verify=False,
            )
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if self._location_is_attacker(location):
                return self._finding("open_redirect", "HIGH", probe_url, "Open redirect parameter accepted", {
                    "param": name,
                    "location": location,
                    "status_code": resp.status_code,
                })
        return None

    def _targets(self) -> list[str]:
        urls: set[str] = set()
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls.update(str(url) for url in classified.get("with_params", []) or [])
        urls.update(str(url) for url in classified.get("auth", []) or [])
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def _replace_or_add(url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        result = []
        for key, existing in pairs:
            if key == name:
                result.append((key, value))
                replaced = True
            else:
                result.append((key, existing))
        if not replaced:
            result.append((name, value))
        return urlunparse(parsed._replace(query=urlencode(result)))

    @staticmethod
    def _location_is_attacker(location: str) -> bool:
        parsed = urlparse(str(location or ""))
        return (parsed.hostname or "").lower() == "attacker.reconx.invalid"

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            key = (finding.get("id", ""), finding.get("url", ""))
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
            "description": "An attacker-controlled URL was accepted in a redirect parameter.",
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/open-redirection"],
            "confidence": 0.85,
        }
