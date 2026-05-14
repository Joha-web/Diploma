"""
ReconX - Module: API key classification and optional live validation.
"""

import hashlib
import re

from modules.base import BaseModule


KEY_PATTERNS = [
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_secret", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]


class APIKeyValidatorModule(BaseModule):
    name = "api_key_validator"
    description = "API Key Leak Classification / Validation"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        secret_results: dict | None = None,
        fuzzer_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.secret_results = secret_results or {}
        self.fuzzer_results = fuzzer_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("api_key_validator", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        candidates = self._candidates()[: int(cfg.get("max_candidates", 100))]
        findings: list[dict] = []
        for candidate in candidates:
            validation = self._validate(candidate, cfg) if cfg.get("live_validation", False) else {"status": "not_validated"}
            severity = "CRITICAL" if validation.get("valid") else "HIGH"
            findings.append(self._finding("api_key_leak", severity, candidate, validation))

        findings = self._dedup(findings)
        self.save_json(candidates, "api_key_candidates.json")
        self.save_json(findings, "api_key_findings.json")
        return {"findings": findings, "total": len(findings), "validated": sum(1 for f in findings if f["evidence"].get("validation", {}).get("valid"))}

    def _candidates(self) -> list[dict]:
        texts: list[dict] = []
        for finding in self.secret_results.get("findings", []) or []:
            evidence = finding.get("evidence", {}) if isinstance(finding, dict) else {}
            raw = evidence.get("raw", {}) if isinstance(evidence, dict) else {}
            for key in ("Secret", "Match", "Redacted", "secret", "match"):
                if isinstance(raw, dict) and raw.get(key):
                    texts.append({"source": "secret_scanner", "text": str(raw[key]), "location": evidence.get("file", "")})
            texts.append({"source": "secret_scanner", "text": str(evidence), "location": evidence.get("file", "") if isinstance(evidence, dict) else ""})

        for secret in self.fuzzer_results.get("classified", {}).get("js_secrets", []) or []:
            if isinstance(secret, dict):
                texts.append({"source": "fuzzer", "text": " ".join(str(secret.get(k, "")) for k in ("match", "context")), "location": secret.get("file", "")})
        for secret in self.fuzzer_results.get("js_secrets", []) or []:
            if isinstance(secret, dict):
                texts.append({"source": "fuzzer", "text": " ".join(str(secret.get(k, "")) for k in ("match", "context")), "location": secret.get("file", "")})

        candidates: list[dict] = []
        for item in texts:
            for key_type, pattern in KEY_PATTERNS:
                for match in pattern.finditer(item["text"]):
                    secret = match.group(0)
                    candidates.append({
                        "type": key_type,
                        "secret": secret,
                        "redacted": self._redact(secret),
                        "fingerprint": self._fingerprint(secret),
                        "source": item["source"],
                        "location": item.get("location", ""),
                    })
        return self._dedup_candidates(candidates)

    def _validate(self, candidate: dict, cfg: dict) -> dict:
        secret = candidate.get("secret", "")
        key_type = candidate.get("type", "")
        timeout = float(cfg.get("timeout", 10))
        if key_type == "github_token":
            resp = self.http_get(
                "https://api.github.com/user",
                enforce_scope=False,
                headers={"Authorization": f"Bearer {secret}", "Accept": "application/vnd.github+json"},
                timeout=timeout,
            )
            return self._validation_from_status(resp, valid_statuses={200})
        if key_type == "slack_token":
            resp = self.http_get(
                "https://slack.com/api/auth.test",
                enforce_scope=False,
                headers={"Authorization": f"Bearer {secret}"},
                timeout=timeout,
            )
            data = self._json(resp)
            return {"status": getattr(resp, "status_code", None), "valid": bool(isinstance(data, dict) and data.get("ok"))}
        if key_type == "stripe_secret":
            resp = self.http_get(
                "https://api.stripe.com/v1/account",
                enforce_scope=False,
                headers={"Authorization": f"Bearer {secret}"},
                timeout=timeout,
            )
            return self._validation_from_status(resp, valid_statuses={200})
        if key_type == "openai_key":
            resp = self.http_get(
                "https://api.openai.com/v1/models",
                enforce_scope=False,
                headers={"Authorization": f"Bearer {secret}"},
                timeout=timeout,
            )
            return self._validation_from_status(resp, valid_statuses={200})
        return {"status": "unsupported_validator", "valid": False}

    @staticmethod
    def _validation_from_status(resp, valid_statuses: set[int]) -> dict:
        status = getattr(resp, "status_code", None)
        return {"status": status, "valid": status in valid_statuses}

    @staticmethod
    def _json(resp):
        try:
            return resp.json()
        except Exception:
            return {}

    @staticmethod
    def _redact(secret: str) -> str:
        if len(secret) <= 10:
            return "***"
        return secret[:4] + "..." + secret[-4:]

    @staticmethod
    def _fingerprint(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()[:16]

    @staticmethod
    def _dedup_candidates(candidates: list[dict]) -> list[dict]:
        seen: set[str] = set()
        result: list[dict] = []
        for candidate in candidates:
            fp = candidate.get("fingerprint", "")
            if fp and fp not in seen:
                seen.add(fp)
                result.append(candidate)
        return result

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        result: list[dict] = []
        for finding in findings:
            fp = finding.get("evidence", {}).get("fingerprint", "")
            if fp and fp not in seen:
                seen.add(fp)
                result.append(finding)
        return result

    def _finding(self, finding_id: str, severity: str, candidate: dict, validation: dict) -> dict:
        title = f"Potential live API key leak: {candidate.get('type', 'api_key')}"
        return {
            "source": self.name,
            "id": finding_id,
            "type": candidate.get("type", "api_key"),
            "name": title,
            "title": title,
            "severity": severity,
            "url": candidate.get("location", ""),
            "matched_url": candidate.get("location", ""),
            "description": "A leaked API key pattern was found. Live validation is optional and controlled by config.",
            "evidence": {
                "key_type": candidate.get("type", ""),
                "redacted": candidate.get("redacted", ""),
                "fingerprint": candidate.get("fingerprint", ""),
                "source": candidate.get("source", ""),
                "location": candidate.get("location", ""),
                "validation": validation,
            },
            "confidence": 0.95 if validation.get("valid") else 0.75,
        }
