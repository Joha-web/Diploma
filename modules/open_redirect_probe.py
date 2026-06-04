"""
ReconX - Module: generic open redirect probes.
"""

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from modules.base import BaseModule
from modules.url_utils import redirect_host


# Common redirect-parameter names — superset of PayloadsAllTheThings/Open Redirect.
REDIRECT_PARAMS = (
    "next", "url", "redirect", "redirect_uri", "redirect_url",
    "return", "returnto", "return_to", "returnurl", "return_url",
    "continue", "dest", "destination", "forward", "forwardurl",
    "goto", "go", "target", "view", "image_url",
    "rurl", "out", "link", "site", "to",
)
REDIRECT_PARAM_NAMES = {name.lower() for name in REDIRECT_PARAMS}

# Payload variants — each tries a common filter-bypass technique. The detector
# verifies success by checking that the response Location header resolves to the
# attacker domain. Reference: PayloadsAllTheThings/Open Redirect#filter-bypass.
ATTACKER_HOST = "attacker.reconx.invalid"
REDIRECT_PAYLOADS = (
    f"https://{ATTACKER_HOST}/",
    f"//{ATTACKER_HOST}/",         # scheme-relative
    f"////{ATTACKER_HOST}/",       # multi-slash bypass
    f"https:{ATTACKER_HOST}/",     # missing slashes
    f"/\\{ATTACKER_HOST}/",        # backslash bypass
    f"//{ATTACKER_HOST}\\@example.com/",  # @-bypass — attacker is the actual host
    f"https://example.com@{ATTACKER_HOST}/",  # userinfo @-bypass
)

# Client-side redirect sinks: many open redirects fire via meta-refresh or a JS
# location assignment rather than an HTTP Location header. Extract the target URL
# from each so we can check whether it resolves to the attacker host.
META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)""",
    re.I,
)
JS_REDIRECT_RE = re.compile(
    r"""(?:location\s*\.\s*(?:href|replace|assign)\s*\(?\s*|window\s*\.\s*location\s*=\s*|location\s*=\s*)["']([^"']+)["']""",
    re.I,
)


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
        max_payloads = int(cfg.get("max_payloads_per_param", len(REDIRECT_PAYLOADS)))
        for name in names[:3]:
            for payload in REDIRECT_PAYLOADS[:max_payloads]:
                probe_url = self._replace_or_add(url, name, payload)
                resp = self.http_get(
                    probe_url, session=session, allow_redirects=False,
                    timeout=float(cfg.get("timeout", 8)), verify=False,
                )
                if resp is None:
                    continue
                # 1. HTTP Location header redirect (server-side).
                location = resp.headers.get("Location", "")
                if self._location_is_attacker(location):
                    return self._finding("open_redirect", "HIGH", probe_url, "Open redirect parameter accepted", {
                        "param": name,
                        "payload": payload,
                        "location": location,
                        "status_code": resp.status_code,
                        "technique": "http_location",
                    })
                # 2. Client-side redirect: meta-refresh / JS location to attacker.
                if cfg.get("detect_client_side", True):
                    client = self._body_redirect_to_attacker(resp.text or "")
                    if client:
                        technique, target = client
                        return self._finding(
                            "open_redirect", "HIGH", probe_url,
                            "Client-side open redirect parameter accepted",
                            {
                                "param": name, "payload": payload,
                                "redirect_target": target, "technique": technique,
                                "status_code": resp.status_code,
                            },
                            confidence=0.80,  # client-side: needs a victim browser to fire
                        )
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

    @classmethod
    def _location_is_attacker(cls, location: str) -> bool:
        return cls._redirect_host(location) == ATTACKER_HOST

    _redirect_host = staticmethod(redirect_host)  # browser-style host resolver (shared)

    def _body_redirect_to_attacker(self, body: str) -> tuple[str, str] | None:
        for rx, technique in ((META_REFRESH_RE, "meta_refresh"), (JS_REDIRECT_RE, "javascript_location")):
            for match in rx.finditer(body or ""):
                target = match.group(1)
                if self._redirect_host(target) == ATTACKER_HOST:
                    return technique, target[:200]
        return None

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

    def _finding(self, finding_id: str, severity: str, url: str, title: str,
                 evidence: dict, confidence: float = 0.85) -> dict:
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
            "confidence": confidence,
        }
