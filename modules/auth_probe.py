"""
ReconX - Module: lightweight authentication surface checks.

Performs passive JWT inspection and cookie flag auditing. It does not attempt
login, brute-force accounts, or submit state-changing requests.
"""

import base64
import json
import re
import time
from http.cookies import SimpleCookie

import requests

from modules.base import BaseModule

try:
    import jwt
except ImportError:  # pragma: no cover - dependency is declared, fallback is defensive.
    jwt = None


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme",
    "supersecret", "qwerty", "letmein", "admin",
]


class AuthProbeModule(BaseModule):
    name = "auth_probe"
    description = "JWT and Cookie Security Checks"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("auth_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "jwt_findings": [], "cookie_findings": [], "status": "disabled"}

        urls = self._extract_urls()[: int(cfg.get("max_urls", 150))]
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "ReconX/2.0"

        jwt_findings: list[dict] = []
        cookie_findings: list[dict] = []
        seen_tokens: set[str] = set()

        for url in urls:
            resp = self.http_get(url, session=sess, timeout=10, verify=False)
            if resp is None:
                continue

            cookies = self._set_cookie_headers(resp)
            cookie_findings.extend(self._audit_cookies(url, cookies))

            token_candidates = set(JWT_RE.findall(resp.text or ""))
            for header in cookies:
                token_candidates.update(JWT_RE.findall(header))

            for token in token_candidates:
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                jwt_findings.extend(self._analyse_jwt(token, url))

        findings = cookie_findings + jwt_findings
        self.save_json(cookie_findings, "cookie_findings.json")
        self.save_json(jwt_findings, "jwt_findings.json")
        self.save_json(findings, "auth_findings.json")
        if findings:
            self.warn(f"Auth findings: {len(findings)}")
        else:
            self.success("No JWT or cookie issues detected")

        return {
            "findings": findings,
            "jwt_findings": jwt_findings,
            "cookie_findings": cookie_findings,
            "total": len(findings),
        }

    def _analyse_jwt(self, token: str, url: str) -> list[dict]:
        findings: list[dict] = []
        header, payload = self._decode_unverified(token)
        if not header:
            return findings

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append(self._finding(
                "jwt_alg_none", "CRITICAL", url,
                "JWT uses alg=none",
                {"alg": header.get("alg"), "claims": self._safe_claims(payload)},
            ))

        exp = payload.get("exp") if isinstance(payload, dict) else None
        if isinstance(exp, (int, float)) and exp < time.time():
            findings.append(self._finding(
                "jwt_expired_token_seen", "LOW", url,
                "Expired JWT observed in application response",
                {"exp": exp},
            ))

        if jwt is not None and alg.startswith("hs"):
            candidates = WEAK_SECRETS + [self.domain, self.target]
            for secret in candidates:
                try:
                    jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
                    findings.append(self._finding(
                        "jwt_weak_secret", "CRITICAL", url,
                        "JWT signature validated with a weak secret",
                        {"secret": secret, "alg": header.get("alg")},
                    ))
                    break
                except Exception:
                    continue

        return findings

    # Cookies that are intentionally accessible via JavaScript — missing HttpOnly
    # on these is expected behaviour, not a vulnerability.
    ANALYTICS_COOKIE_PREFIXES = (
        "_ga", "_gid", "_gat", "_gcl_", "_fbp", "_fbc",
        "__utm", "_hjid", "_hjSession", "ajs_", "mp_",
        "amplitude_id", "mixpanel", "intercom-",
    )

    def _audit_cookies(self, url: str, headers: list[str]) -> list[dict]:
        findings: list[dict] = []
        seen_cookie_issues: set[tuple[str, str]] = set()
        for raw in headers:
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                continue
            for name, morsel in cookie.items():
                # Skip analytics/tracking cookies for HttpOnly checks — they are
                # intentionally JS-readable; flagging them produces false positives.
                is_analytics = any(
                    name.lower().startswith(prefix.lower())
                    for prefix in self.ANALYTICS_COOKIE_PREFIXES
                )

                if url.startswith("https://") and not morsel["secure"]:
                    key = ("cookie_missing_secure", name)
                    if key not in seen_cookie_issues:
                        seen_cookie_issues.add(key)
                        findings.append(self._finding(
                            "cookie_missing_secure", "MEDIUM", url,
                            "HTTPS cookie missing Secure flag",
                            {"cookie": name},
                        ))
                if not morsel["httponly"] and not is_analytics:
                    key = ("cookie_missing_httponly", name)
                    if key not in seen_cookie_issues:
                        seen_cookie_issues.add(key)
                        findings.append(self._finding(
                            "cookie_missing_httponly", "MEDIUM", url,
                            "Cookie missing HttpOnly flag",
                            {"cookie": name},
                        ))
                samesite = str(morsel["samesite"] or "").lower()
                if not samesite or samesite == "none":
                    key = ("cookie_weak_samesite", name)
                    if key not in seen_cookie_issues:
                        seen_cookie_issues.add(key)
                        findings.append(self._finding(
                            "cookie_weak_samesite", "LOW", url,
                            "Cookie missing strict SameSite protection",
                            {"cookie": name},
                        ))
        return findings

    @staticmethod
    def _set_cookie_headers(resp: requests.Response) -> list[str]:
        raw = getattr(resp, "raw", None)
        headers = getattr(raw, "headers", None)
        if headers is not None:
            for method in ("get_all", "getlist"):
                getter = getattr(headers, method, None)
                if getter:
                    values = getter("Set-Cookie")
                    if values:
                        return list(values)
        value = resp.headers.get("Set-Cookie", "")
        return [value] if value else []

    @staticmethod
    def _decode_unverified(token: str) -> tuple[dict, dict]:
        if jwt is not None:
            try:
                return (
                    jwt.get_unverified_header(token),
                    jwt.decode(token, options={"verify_signature": False}),
                )
            except Exception:
                return {}, {}
        try:
            header_raw, payload_raw, _ = token.split(".", 2)
            return (
                json.loads(AuthProbeModule._b64decode(header_raw)),
                json.loads(AuthProbeModule._b64decode(payload_raw)),
            )
        except Exception:
            return {}, {}

    @staticmethod
    def _b64decode(value: str) -> str:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode("utf-8", errors="replace")

    @staticmethod
    def _safe_claims(payload: dict) -> dict:
        if not isinstance(payload, dict):
            return {}
        keep = {"alg", "exp", "iss", "aud", "sub", "iat", "nbf"}
        return {k: payload.get(k) for k in keep if k in payload}

    def _finding(self, finding_type: str, severity: str, url: str,
                 title: str, evidence: dict) -> dict:
        # Cookie/header best-practice observations are not confirmed exploitable
        # vulnerabilities — use a lower confidence to reflect that.
        is_cookie_observation = finding_type in (
            "cookie_missing_httponly", "cookie_missing_secure",
            "cookie_weak_samesite", "jwt_expired_token_seen",
        )
        confidence = 0.5 if finding_type == "jwt_expired_token_seen" else (
            0.6 if is_cookie_observation else 0.8
        )
        return {
            "source": self.name,
            "id": finding_type,
            "type": finding_type,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": title,
            "evidence": evidence,
            "confidence": confidence,
        }

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        return self.filter_in_scope_urls(urls)
