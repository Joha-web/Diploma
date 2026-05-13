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

FINGERPRINTS.update({
    "pantheon": {
        "cname": ["pantheonsite.io"],
        "body": ["The gods are wise", "404 error unknown site"],
    },
    "readme": {
        "cname": ["readme.io"],
        "body": ["Project doesnt exist", "The project you are looking for could not be found"],
    },
    "helpjuice": {
        "cname": ["helpjuice.com"],
        "body": ["We could not find what you're looking for"],
    },
    "statuspage": {
        "cname": ["statuspage.io"],
        "body": ["This page is not configured", "There is no status page configured"],
    },
    "surge": {
        "cname": ["surge.sh"],
        "body": ["project not found", "project you were looking for wasn't found"],
    },
    "fly": {
        "cname": ["fly.dev"],
        "body": ["could not find app", "App not found"],
    },
    "bitbucket": {
        "cname": ["bitbucket.io"],
        "body": ["Repository not found"],
    },
    "shopify": {
        "cname": ["myshopify.com"],
        "body": ["Sorry, this shop is currently unavailable"],
    },
    "desk": {
        "cname": ["desk.com"],
        "body": ["Please try again or try Desk.com free"],
    },
    "freshdesk": {
        "cname": ["freshdesk.com"],
        "body": ["We couldn't find", "Freshdesk Support Desk"],
    },
    "zendesk": {
        "cname": ["zendesk.com"],
        "body": ["Help Center Closed", "this help center no longer exists"],
    },
    "helpdocs": {
        "cname": ["helpdocs.io"],
        "body": ["HelpDocs account not found"],
    },
    "helpscout_docs": {
        "cname": ["helpscoutdocs.com"],
        "body": ["No settings were found for this company"],
    },
    "unbounce": {
        "cname": ["unbouncepages.com"],
        "body": ["The requested URL was not found on this server"],
    },
    "instapage": {
        "cname": ["pageserve.co", "instapage.com"],
        "body": ["The page you are looking for doesn't exist"],
    },
    "tumblr": {
        "cname": ["domains.tumblr.com"],
        "body": ["There's nothing here"],
    },
    "squarespace": {
        "cname": ["squarespace.com"],
        "body": ["No Such Account"],
    },
    "cargo": {
        "cname": ["cargocollective.com"],
        "body": ["404 Not Found"],
    },
    "webflow": {
        "cname": ["proxy.webflow.com", "webflow.io"],
        "body": ["The page you are looking for doesn't exist"],
    },
    "ghost": {
        "cname": ["ghost.io"],
        "body": ["The thing you were looking for is no longer here"],
    },
    "wordpress": {
        "cname": ["wordpress.com"],
        "body": ["Do you want to register"],
    },
    "wpengine": {
        "cname": ["wpengine.com"],
        "body": ["The site you were looking for couldn't be found"],
    },
    "acquia": {
        "cname": ["acquia-sites.com"],
        "body": ["The site you are looking for could not be found"],
    },
    "readthedocs": {
        "cname": ["readthedocs.io"],
        "body": ["unknown to Read the Docs"],
    },
    "gitbook": {
        "cname": ["gitbook.io"],
        "body": ["If you need help, contact support@gitbook.com"],
    },
    "tilda": {
        "cname": ["tilda.ws"],
        "body": ["Please renew your subscription"],
    },
    "launchrock": {
        "cname": ["launchrock.com"],
        "body": ["It looks like you may have taken a wrong turn"],
    },
    "uservoice": {
        "cname": ["uservoice.com"],
        "body": ["This UserVoice subdomain is currently available"],
    },
    "campaignmonitor": {
        "cname": ["createsend.com"],
        "body": ["Trying to access your account"],
    },
    "smartjobboard": {
        "cname": ["mysmartjobboard.com"],
        "body": ["This job board website is either expired"],
    },
    "teamwork": {
        "cname": ["teamwork.com"],
        "body": ["Oops - We didn't find your site"],
    },
    "frontify": {
        "cname": ["frontify.com"],
        "body": ["404 - Page Not Found"],
    },
    "shortio": {
        "cname": ["short.io"],
        "body": ["Link does not exist"],
    },
    "getresponse": {
        "cname": ["gr8.com"],
        "body": ["With GetResponse Landing Pages"],
    },
    "kinsta": {
        "cname": ["kinsta.cloud"],
        "body": ["No Site For Domain"],
    },
    "azure_static_web_apps": {
        "cname": ["azurestaticapps.net"],
        "body": ["This static web app has been successfully created"],
    },
    "firebase": {
        "cname": ["firebaseapp.com", "web.app"],
        "body": ["Site Not Found", "Firebase Hosting Setup Complete"],
    },
    "cloudflare_pages": {
        "cname": ["pages.dev"],
        "body": ["The deployment could not be found", "No such deployment"],
    },
    "render": {
        "cname": ["onrender.com"],
        "body": ["Not Found", "no such app"],
    },
    "railway": {
        "cname": ["railway.app"],
        "body": ["Application not found"],
    },
})


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
