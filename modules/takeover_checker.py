"""
ReconX - Module: subdomain takeover candidate checks.
"""

import re

import requests

from modules.base import BaseModule

try:
    import dns.resolver
except ImportError:  # pragma: no cover - dependency is declared.
    dns = None


FINGERPRINTS = {
    "github_pages": {
        "cname": ["github.io"],
        "body": ["There isn't a GitHub Pages site here"],
    },
    "heroku": {
        "cname": ["herokuapp.com", "herokudns.com"],
        "body": ["No such app"],
    },
    "netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "body": ["Not Found - Request ID"],
    },
    "vercel": {
        "cname": ["vercel-dns.com", "vercel.app"],
        "body": ["The deployment could not be found"],
    },
    "azure": {
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "body": ["404 Web Site not found"],
    },
    "fastly": {
        "cname": ["fastly.net"],
        "body": ["Fastly error: unknown domain"],
    },
}


class TakeoverCheckerModule(BaseModule):
    name = "takeover_checker"
    description = "Subdomain Takeover Candidate Checks"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 recon_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.recon_results = recon_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("takeover_checker", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "checked": 0, "status": "disabled"}
        if dns is None:
            self.warn("dnspython not installed - takeover checks skipped")
            return {"findings": [], "checked": 0, "status": "dependency_missing"}

        subdomains = self.recon_results.get("subdomains", [])[: int(cfg.get("max_hosts", 500))]
        findings: list[dict] = []
        for host in subdomains:
            if not self.is_in_scope(host):
                continue
            cnames = self._cnames(host)
            if not cnames:
                continue
            finding = self._match_cname(host, cnames)
            if finding:
                body_match = self._body_fingerprint(host, finding["provider"])
                finding["evidence"]["body_fingerprint"] = body_match
                finding["confidence"] = 0.85 if body_match else 0.65
                findings.append(finding)

        self.save_json(findings, "takeover_findings.json")
        return {"findings": findings, "checked": len(subdomains), "total": len(findings)}

    def _cnames(self, host: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(host, "CNAME")
            return [str(answer.target).rstrip(".").lower() for answer in answers]
        except Exception:
            return []

    def _match_cname(self, host: str, cnames: list[str]) -> dict | None:
        for cname in cnames:
            for provider, fp in FINGERPRINTS.items():
                if any(marker in cname for marker in fp["cname"]):
                    return {
                        "source": self.name,
                        "id": "potential_subdomain_takeover",
                        "type": "potential_subdomain_takeover",
                        "name": "Potential subdomain takeover candidate",
                        "title": "Potential subdomain takeover candidate",
                        "severity": "HIGH",
                        "url": f"https://{host}",
                        "matched_url": f"https://{host}",
                        "provider": provider,
                        "description": (
                            "Subdomain points to a third-party platform. Manual validation is "
                            "required before claiming takeover risk."
                        ),
                        "evidence": {"host": host, "cnames": cnames},
                        "confidence": 0.65,
                    }
        return None

    def _body_fingerprint(self, host: str, provider: str) -> str:
        markers = FINGERPRINTS.get(provider, {}).get("body", [])
        if not markers:
            return ""
        sess = requests.Session()
        sess.verify = False
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            resp = self.http_get(url, session=sess, timeout=8, verify=False)
            if resp is None:
                continue
            body = (resp.text or "")[:5000]
            for marker in markers:
                if re.search(re.escape(marker), body, re.I):
                    return marker
        return ""
