"""
ReconX - Module: OAuth 2.0 / OpenID Connect security audit.
"""

from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

from modules.base import BaseModule
from modules.url_utils import redirect_host


OAUTH_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/oauth2/authorize",
    "/connect/authorize",
    "/login/oauth/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
]

REDIRECT_URI_PAYLOADS = [
    "https://attacker.reconx.invalid/callback",
    "//attacker.reconx.invalid/callback",
    "https://{domain}.attacker.reconx.invalid/callback",
    "https://{domain}%40attacker.reconx.invalid/callback",
]

WEAK_ALGORITHMS = {"none", "rs256_noverify", "hs256"}


class OAuthProbeModule(BaseModule):
    name = "oauth_probe"
    description = "OAuth 2.0 / OpenID Connect Security Audit"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("oauth_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        bases = self._extract_bases()[: int(cfg.get("max_hosts", 40))]
        if not bases:
            self.warn("No live hosts for OAuth probes")
            return {"findings": [], "total": 0, "endpoints_found": []}

        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"

        findings: list[dict] = []
        discovered: list[str] = []
        for base in bases:
            endpoints = self._discover_endpoints(base, session, cfg)
            discovered.extend(endpoints["authorize"] + endpoints["token"])
            if endpoints.get("oidc_config"):
                findings.extend(self._audit_oidc_config(endpoints["oidc_config"], endpoints["oidc_config_url"]))
            for auth_ep in endpoints["authorize"]:
                findings.extend(self._check_open_redirect(auth_ep, session, cfg))
                findings.extend(self._check_state_required(auth_ep, session, cfg))
                findings.extend(self._check_implicit_flow(auth_ep, session, cfg))
                findings.extend(self._check_pkce(auth_ep, session, cfg))
            for token_ep in endpoints["token"]:
                findings.extend(self._check_token_endpoint(token_ep, session, cfg))

        findings = self._dedup(findings)
        self.save_json(findings, "oauth_findings.json")
        self.save_json(sorted(set(discovered)), "oauth_endpoints.json")
        return {"findings": findings, "total": len(findings), "endpoints_found": sorted(set(discovered))}

    def _discover_endpoints(self, base: str, session: requests.Session, cfg: dict) -> dict:
        result = {"authorize": [], "token": [], "oidc_config": None, "oidc_config_url": ""}
        for path in OAUTH_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            if not self.is_in_scope(url):
                continue
            resp = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 8)), verify=False)
            if resp is None or resp.status_code not in (200, 302, 400, 401, 405):
                continue

            if "well-known" in path and resp.status_code == 200:
                data = self._json(resp)
                if isinstance(data, dict):
                    result["oidc_config"] = data
                    result["oidc_config_url"] = url
                    auth_ep = data.get("authorization_endpoint", "")
                    token_ep = data.get("token_endpoint", "")
                    if auth_ep and self.is_in_scope(auth_ep):
                        result["authorize"].append(auth_ep)
                    if token_ep and self.is_in_scope(token_ep):
                        result["token"].append(token_ep)
                continue
            if "authorize" in path:
                result["authorize"].append(url)
            elif "token" in path:
                result["token"].append(url)
        result["authorize"] = sorted(set(result["authorize"]))
        result["token"] = sorted(set(result["token"]))
        return result

    def _audit_oidc_config(self, data: dict, url: str) -> list[dict]:
        findings: list[dict] = []
        issuer = str(data.get("issuer", ""))
        if issuer and not issuer.startswith("https://"):
            findings.append(self._finding("oidc_http_issuer", "HIGH", url, "OIDC issuer uses HTTP", {"issuer": issuer}))
        algs = data.get("id_token_signing_alg_values_supported", []) or []
        weak = [alg for alg in algs if str(alg).lower() in WEAK_ALGORITHMS]
        if weak:
            findings.append(self._finding("oidc_weak_algorithms", "HIGH", url, "OIDC supports weak signing algorithms", {
                "weak_algorithms": weak,
                "all_algorithms": algs,
            }))
        grant_types = data.get("grant_types_supported", []) or []
        if "implicit" in grant_types:
            findings.append(self._finding("oidc_implicit_grant_supported", "MEDIUM", url, "OIDC advertises implicit grant", {
                "grant_types": grant_types,
            }))
        if not data.get("code_challenge_methods_supported"):
            findings.append(self._finding("oidc_pkce_not_advertised", "MEDIUM", url, "OIDC does not advertise PKCE support", {}))
        if data.get("request_uri_parameter_supported"):
            findings.append(self._finding("oidc_request_uri_supported", "MEDIUM", url, "OIDC request_uri parameter is supported", {
                "request_uri_parameter_supported": True,
            }))
        return findings

    def _check_open_redirect(self, auth_ep: str, session: requests.Session, cfg: dict) -> list[dict]:
        parsed = urlparse(auth_ep)
        domain = parsed.hostname or self.domain
        for template in REDIRECT_URI_PAYLOADS:
            payload = template.format(domain=domain)
            test_url = auth_ep + "?" + urlencode({
                "response_type": "code",
                "client_id": "reconx_test_client",
                "redirect_uri": payload,
                "scope": "openid profile email",
            })
            resp = self.http_get(
                test_url, session=session, allow_redirects=False,
                timeout=float(cfg.get("timeout", 8)), verify=False,
            )
            if resp is None:
                continue
            location = self._absolute_location(auth_ep, resp.headers.get("Location", ""))
            if self._location_is_attacker(location):
                return [self._finding("oauth_open_redirect", "HIGH", auth_ep, "OAuth redirect_uri appears unvalidated", {
                    "payload": payload,
                    "location": location,
                    "status_code": resp.status_code,
                })]
        return []

    @staticmethod
    def _location_is_attacker(location: str) -> bool:
        # Browser-style host resolution so reflected redirect-filter bypasses
        # (////host, https:host, //host\@other) aren't missed — same fix as
        # open_redirect_probe.
        host = redirect_host(location)
        return host == "attacker.reconx.invalid" or host.endswith(".attacker.reconx.invalid")

    def _check_state_required(self, auth_ep: str, session: requests.Session, cfg: dict) -> list[dict]:
        test_url = auth_ep + "?" + urlencode({
            "response_type": "code",
            "client_id": "reconx_test_client",
            "redirect_uri": f"https://{self.domain}/callback",
            "scope": "openid",
        })
        resp = self.http_get(test_url, session=session, allow_redirects=False, timeout=float(cfg.get("timeout", 8)), verify=False)
        if resp is None or resp.status_code not in (200, 302, 303):
            return []
        location = self._absolute_location(auth_ep, resp.headers.get("Location", ""))
        if self._location_points_to_callback(location) and not self._location_has_param(location, "state"):
            return [self._finding("oauth_missing_state", "MEDIUM", auth_ep, "OAuth request accepted without state parameter", {
                "status_code": resp.status_code,
                "location": location[:200],
            })]
        return []

    def _check_implicit_flow(self, auth_ep: str, session: requests.Session, cfg: dict) -> list[dict]:
        test_url = auth_ep + "?" + urlencode({
            "response_type": "token",
            "client_id": "reconx_test_client",
            "redirect_uri": f"https://{self.domain}/callback",
            "scope": "openid",
        })
        resp = self.http_get(test_url, session=session, allow_redirects=False, timeout=float(cfg.get("timeout", 8)), verify=False)
        if resp is None or resp.status_code not in (200, 302, 303):
            return []
        location = self._absolute_location(auth_ep, resp.headers.get("Location", ""))
        combined = ((resp.text or "") + location).lower()
        if "access_token" in combined and "unsupported_response_type" not in combined:
            return [self._finding("oauth_implicit_flow_supported", "MEDIUM", auth_ep, "OAuth implicit flow appears supported", {
                "status_code": resp.status_code,
                "location": location[:200],
            })]
        return []

    def _check_pkce(self, auth_ep: str, session: requests.Session, cfg: dict) -> list[dict]:
        test_url = auth_ep + "?" + urlencode({
            "response_type": "code",
            "client_id": "reconx_test_client",
            "redirect_uri": f"https://{self.domain}/callback",
            "scope": "openid",
            "state": "reconx_state_test",
        })
        resp = self.http_get(test_url, session=session, allow_redirects=False, timeout=float(cfg.get("timeout", 8)), verify=False)
        if resp is None or resp.status_code not in (200, 302, 303):
            return []
        location = self._absolute_location(auth_ep, resp.headers.get("Location", ""))
        combined = ((resp.text or "") + location).lower()
        if self._location_points_to_callback(location) and "code_challenge" not in combined and "invalid_request" not in combined:
            return [self._finding("oauth_pkce_not_required", "MEDIUM", auth_ep, "OAuth authorization endpoint may not require PKCE", {
                "status_code": resp.status_code,
            })]
        return []

    def _location_points_to_callback(self, location: str) -> bool:
        parsed = urlparse(str(location or ""))
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        return host == self.domain or host.endswith(f".{self.domain}")

    @staticmethod
    def _absolute_location(base_url: str, location: str) -> str:
        location = str(location or "").strip()
        return urljoin(base_url, location) if location else ""

    @staticmethod
    def _location_has_param(location: str, name: str) -> bool:
        parsed = urlparse(str(location or ""))
        values = parse_qs(parsed.query, keep_blank_values=True)
        values.update(parse_qs(parsed.fragment, keep_blank_values=True))
        return name in values

    def _check_token_endpoint(self, token_ep: str, session: requests.Session, cfg: dict) -> list[dict]:
        findings: list[dict] = []
        resp = self.http_get(token_ep, session=session, timeout=float(cfg.get("timeout", 8)), verify=False)
        data = self._json(resp) if resp is not None else {}
        if isinstance(data, dict) and data.get("access_token"):
            findings.append(self._finding("oauth_token_via_get", "CRITICAL", token_ep, "OAuth token endpoint returned a token via GET", {
                "response_keys": sorted(data.keys()),
            }))
        resp = self.http_request(
            "POST", token_ep, session=session, safe_readonly=True,
            data={"grant_type": "client_credentials", "client_id": "reconx_test"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=float(cfg.get("timeout", 8)), verify=False,
        )
        data = self._json(resp) if resp is not None else {}
        if isinstance(data, dict) and data.get("access_token"):
            findings.append(self._finding("oauth_token_no_secret", "CRITICAL", token_ep, "OAuth token endpoint issued token without client_secret", {
                "grant_type": "client_credentials",
            }))
        return findings

    def _extract_bases(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        urls.update(self.load_lines(self.session_path("webdetect", "live_urls.txt")))
        bases = []
        for url in self.filter_in_scope_urls(urls):
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                bases.append(f"{parsed.scheme}://{parsed.netloc}")
        return sorted(set(bases))

    @staticmethod
    def _json(resp):
        try:
            return resp.json()
        except Exception:
            return {}

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
            "description": title,
            "evidence": evidence,
            "references": [
                "https://portswigger.net/web-security/oauth",
                "https://oauth.net/2/security-best-current-practice/",
            ],
            "confidence": 0.8,
        }
