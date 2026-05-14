"""
ReconX - Module: deeper JWT security audit.
"""

from __future__ import annotations

import base64
import json
import re
import time
from urllib.parse import urlparse

import requests

from modules.active_probe_base import ActiveProbeBase

try:
    import jwt
except ImportError:  # pragma: no cover - dependency is declared, fallback is defensive.
    jwt = None


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
DEFAULT_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "changeme",
    "supersecret",
    "qwerty",
    "letmein",
    "admin",
    "jwtsecret",
    "your-256-bit-secret",
]


class JWTAuditModule(ActiveProbeBase):
    name = "jwt_audit"
    description = "Deep JWT Security Audit"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        live_hosts: list | None = None,
        fuzzer_results: dict | None = None,
        auth_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.fuzzer_results = fuzzer_results or {}
        self.auth_results = auth_results or {}

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "tokens": [], "total": 0, "status": "disabled"}

        tokens = self.limit(self._collect_tokens(), "max_tokens", 100)
        findings: list[dict] = []
        inventory: list[dict] = []
        for item in tokens:
            token = item["token"]
            header, payload = self._decode_unverified(token)
            if not header:
                continue
            inventory.append({
                "token": self._redact_token(token),
                "source": item.get("source", ""),
                "url": item.get("url", ""),
                "header": self._safe_header(header),
                "claims": self._safe_claims(payload),
            })
            findings.extend(self._audit_header(token, header, payload, item))
            findings.extend(self._audit_claims(header, payload, item))
            findings.extend(self._audit_hmac_secret(token, header, item))

        findings = self.dedup_findings(findings)
        self.save_json(inventory, "jwt_inventory.json")
        self.save_json(findings, "jwt_audit_findings.json")
        return {
            "findings": findings,
            "tokens": inventory,
            "total": len(findings),
            "token_count": len(inventory),
        }

    def _collect_tokens(self) -> list[dict]:
        tokens: dict[str, dict] = {}

        def add(token: str, source: str, url: str = "") -> None:
            token = str(token or "").strip()
            if not JWT_RE.fullmatch(token):
                return
            tokens.setdefault(token, {"token": token, "source": source, "url": url})

        cfg = self.module_config()
        for token in cfg.get("tokens", []) or []:
            if isinstance(token, dict):
                add(token.get("token", ""), token.get("source", "config"), token.get("url", ""))
            else:
                add(str(token), "config")

        for name in self.configured_profile_names():
            profile = self.profile(name)
            token = profile.get("token", "")
            if token:
                add(self._bearer_value(str(token)), f"auth_profile:{name}")
            for value in self.profile_headers(name).values():
                for candidate in JWT_RE.findall(str(value)):
                    add(candidate, f"auth_profile:{name}")

        for finding in self.auth_results.get("tokens", []) or []:
            if isinstance(finding, dict):
                add(finding.get("token", ""), "auth_probe", finding.get("url", ""))

        classified = self.fuzzer_results.get("classified", {}) or {}
        for secret in classified.get("js_secrets", []) or []:
            if not isinstance(secret, dict):
                continue
            for candidate in JWT_RE.findall(str(secret.get("match", ""))):
                add(candidate, "js_secret", secret.get("file", ""))

        if cfg.get("collect_from_responses", False):
            self._collect_response_tokens(add)

        return sorted(tokens.values(), key=lambda item: (item.get("source", ""), item["token"]))

    def _collect_response_tokens(self, add) -> None:
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        timeout = self.request_timeout()
        for url in self.collect_live_urls(self.live_hosts)[: int(self.module_config().get("max_response_urls", 50))]:
            resp = self.http_get(url, session=session, timeout=timeout, verify=False)
            if resp is None:
                continue
            text = (resp.text or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            for token in JWT_RE.findall(text):
                add(token, "http_response", url)

    def _audit_header(self, token: str, header: dict, payload: dict, item: dict) -> list[dict]:
        findings: list[dict] = []
        url = item.get("url", "")
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append(self.make_finding(
                "jwt_alg_none",
                url,
                evidence={"alg": header.get("alg"), "token": self._redact_token(token), "claims": self._safe_claims(payload)},
            ))

        kid = str(header.get("kid", "") or "")
        if self._kid_has_traversal(kid):
            findings.append(self.make_finding(
                "jwt_kid_path_traversal",
                url,
                evidence={"kid": kid, "token": self._redact_token(token)},
            ))

        for field in ("jku", "x5u"):
            value = str(header.get(field, "") or "")
            if value and self._untrusted_key_url(value):
                findings.append(self.make_finding(
                    "jwt_untrusted_jku_x5u",
                    url,
                    evidence={"header": field, "value": value, "token": self._redact_token(token)},
                ))
        return findings

    def _audit_claims(self, header: dict, payload: dict, item: dict) -> list[dict]:
        if not isinstance(payload, dict):
            return []

        findings: list[dict] = []
        url = item.get("url", "")
        for claim in ("exp", "iss", "aud"):
            if payload.get(claim) in (None, "", []):
                findings.append(self.make_finding(
                    "jwt_missing_claim",
                    url,
                    evidence={"claim": claim, "alg": header.get("alg"), "claims": self._safe_claims(payload)},
                    severity="HIGH" if claim == "exp" else "MEDIUM",
                    confidence=0.78 if claim == "exp" else 0.70,
                ))

        exp = self._numeric_claim(payload.get("exp"))
        iat = self._numeric_claim(payload.get("iat"))
        if exp and iat and exp > iat:
            lifetime = exp - iat
            max_ttl = int(self.module_config().get("max_token_ttl_seconds", 7 * 24 * 3600))
            if lifetime > max_ttl:
                findings.append(self.make_finding(
                    "jwt_long_lived_token",
                    url,
                    evidence={
                        "lifetime_seconds": int(lifetime),
                        "max_token_ttl_seconds": max_ttl,
                        "exp": exp,
                        "iat": iat,
                    },
                ))
        return findings

    def _audit_hmac_secret(self, token: str, header: dict, item: dict) -> list[dict]:
        alg = str(header.get("alg", "") or "").upper()
        if jwt is None or not alg.startswith("HS"):
            return []

        secrets = list(self.module_config().get("weak_secrets", []) or [])
        secrets.extend(DEFAULT_WEAK_SECRETS)
        secrets.extend([self.domain, self.target])
        seen: set[str] = set()
        for secret in secrets[: int(self.module_config().get("max_secret_guesses", 50))]:
            secret = str(secret)
            if not secret or secret in seen:
                continue
            seen.add(secret)
            try:
                jwt.decode(
                    token,
                    secret,
                    algorithms=[alg],
                    options={"verify_aud": False, "verify_iss": False, "verify_exp": False},
                )
            except Exception:
                continue
            return [self.make_finding(
                "jwt_weak_hmac_secret",
                item.get("url", ""),
                evidence={"alg": alg, "secret": secret, "token": self._redact_token(token)},
            )]
        return []

    def _untrusted_key_url(self, value: str) -> bool:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            return True
        if parsed.scheme == "http":
            return True
        allowed = set(self.module_config().get("trusted_key_hosts", []) or [])
        if parsed.hostname in allowed:
            return False
        return not self.is_in_scope(value)

    @staticmethod
    def _kid_has_traversal(kid: str) -> bool:
        lowered = kid.lower()
        return (
            ".." in kid
            or kid.startswith(("/", "\\"))
            or "file:" in lowered
            or lowered.startswith(("http://", "https://"))
            or "\\" in kid
        )

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
                json.loads(JWTAuditModule._b64decode(header_raw)),
                json.loads(JWTAuditModule._b64decode(payload_raw)),
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
        keep = {"exp", "iss", "aud", "sub", "iat", "nbf", "jti", "scope", "roles"}
        return {key: payload.get(key) for key in keep if key in payload}

    @staticmethod
    def _safe_header(header: dict) -> dict:
        keep = {"alg", "typ", "kid", "jku", "x5u", "x5t"}
        return {key: header.get(key) for key in keep if key in header}

    @staticmethod
    def _numeric_claim(value) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _bearer_value(value: str) -> str:
        value = value.strip()
        if value.lower().startswith("bearer "):
            return value.split(" ", 1)[1].strip()
        return value

    @staticmethod
    def _redact_token(token: str) -> str:
        if len(token) <= 24:
            return "***"
        return f"{token[:12]}...{token[-8:]}"
