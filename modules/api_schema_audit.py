"""
ReconX - Module: OpenAPI schema and authorization audit.
"""

from __future__ import annotations

import re

from modules.active_probe_base import ActiveProbeBase


DANGEROUS_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_ROUTE_RE = re.compile(
    r"/(admin|internal|manage|users?|accounts?|orgs?|organizations?|tenants?|teams?|"
    r"customers?|profiles?|orders?|invoices?|payments?|subscriptions?|roles?|members?|"
    r"login|signin|password|reset|token|coupon|redeem|wallet|billing)(/|$|\?|[{])",
    re.I,
)
RATE_LIMIT_ROUTE_RE = re.compile(r"(login|signin|password|reset|forgot|token|otp|mfa|coupon|redeem)", re.I)


class APISchemaAuditModule(ActiveProbeBase):
    name = "api_schema_audit"
    description = "OpenAPI Security Schema Audit"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        openapi_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.openapi_results = openapi_results or {}

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "total": 0, "status": "disabled"}

        endpoints = self.limit(self.openapi_results.get("endpoints", []) or [], "max_endpoints", 500)
        findings: list[dict] = []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
            findings.extend(self._audit_endpoint(endpoint))

        findings = self.dedup_findings(findings)
        self.save_json(findings, "api_schema_findings.json")
        return {
            "findings": findings,
            "total": len(findings),
            "endpoints_reviewed": len(endpoints),
        }

    def _audit_endpoint(self, endpoint: dict) -> list[dict]:
        findings: list[dict] = []
        url = endpoint.get("url", "")
        path = endpoint.get("path", url)
        method = str(endpoint.get("method", "GET")).upper()
        sensitive = self._sensitive(endpoint)
        no_auth = self._no_auth(endpoint)
        security_known = self._security_known(endpoint)
        evidence = {
            "method": method,
            "path": path,
            "summary": endpoint.get("summary", ""),
            "security": endpoint.get("security"),
            "effective_security": endpoint.get("effective_security"),
            "security_defined": endpoint.get("security_defined"),
        }

        if security_known and no_auth and sensitive:
            findings.append(self.make_finding(
                "openapi_sensitive_route_without_auth",
                url,
                evidence=evidence,
            ))
        elif security_known and no_auth:
            findings.append(self.make_finding(
                "openapi_endpoint_without_security",
                url,
                evidence=evidence,
            ))

        if security_known and no_auth and method in DANGEROUS_METHODS:
            findings.append(self.make_finding(
                "openapi_dangerous_method_without_auth",
                url,
                evidence=evidence,
                severity="HIGH" if sensitive else "MEDIUM",
            ))

        schema_evidence = self._broad_schema_evidence(endpoint)
        if schema_evidence:
            schema_evidence.update(evidence)
            findings.append(self.make_finding(
                "openapi_overly_broad_schema",
                url,
                evidence=schema_evidence,
            ))

        if self._needs_rate_limit_hint(endpoint) and not self._has_rate_limit_hint(endpoint):
            findings.append(self.make_finding(
                "openapi_missing_rate_limit_hint",
                url,
                evidence={
                    **evidence,
                    "responses": sorted(str(code) for code in (endpoint.get("responses", {}) or {}).keys()),
                },
            ))

        return findings

    @staticmethod
    def _security_known(endpoint: dict) -> bool:
        return (
            "effective_security" in endpoint
            or "security" in endpoint
            or "security_defined" in endpoint
        )

    @staticmethod
    def _no_auth(endpoint: dict) -> bool:
        security = endpoint.get("effective_security", endpoint.get("security"))
        if security is None:
            return endpoint.get("security_defined") is False
        if security in ("", "none", "None"):
            return True
        if isinstance(security, (list, tuple, dict, set)):
            return len(security) == 0
        return False

    @staticmethod
    def _sensitive(endpoint: dict) -> bool:
        path = str(endpoint.get("path") or endpoint.get("url") or "")
        summary = str(endpoint.get("summary", ""))
        tags = " ".join(str(tag) for tag in endpoint.get("tags", []) or [])
        return bool(SENSITIVE_ROUTE_RE.search(path) or SENSITIVE_ROUTE_RE.search(summary) or SENSITIVE_ROUTE_RE.search(tags))

    @staticmethod
    def _needs_rate_limit_hint(endpoint: dict) -> bool:
        target = " ".join(str(endpoint.get(key, "")) for key in ("path", "url", "summary", "operation_id"))
        return bool(RATE_LIMIT_ROUTE_RE.search(target))

    @staticmethod
    def _has_rate_limit_hint(endpoint: dict) -> bool:
        responses = endpoint.get("responses", {}) or {}
        if "429" in {str(code) for code in responses.keys()}:
            return True
        text = str(responses).lower() + " " + str(endpoint.get("response_headers", {})).lower()
        return "rate-limit" in text or "ratelimit" in text or "too many requests" in text

    @staticmethod
    def _broad_schema_evidence(endpoint: dict) -> dict:
        schema = endpoint.get("request_schema") or endpoint.get("request_body_schema") or {}
        path = APISchemaAuditModule._find_broad_schema(schema)
        if not path:
            return {}
        return {"schema_path": path, "schema_excerpt": APISchemaAuditModule._schema_excerpt(schema)}

    @staticmethod
    def _find_broad_schema(schema, path: str = "$") -> str:
        if not isinstance(schema, dict):
            return ""
        schema_type = schema.get("type")
        if schema.get("additionalProperties") is True:
            return f"{path}.additionalProperties"
        if schema_type == "object" and not schema.get("properties") and not schema.get("$ref"):
            return path
        for key in ("properties", "definitions", "$defs"):
            children = schema.get(key)
            if isinstance(children, dict):
                for name, child in children.items():
                    found = APISchemaAuditModule._find_broad_schema(child, f"{path}.{key}.{name}")
                    if found:
                        return found
        for key in ("items", "allOf", "anyOf", "oneOf"):
            child = schema.get(key)
            if isinstance(child, dict):
                found = APISchemaAuditModule._find_broad_schema(child, f"{path}.{key}")
                if found:
                    return found
            elif isinstance(child, list):
                for idx, item in enumerate(child):
                    found = APISchemaAuditModule._find_broad_schema(item, f"{path}.{key}[{idx}]")
                    if found:
                        return found
        return ""

    @staticmethod
    def _schema_excerpt(schema) -> dict:
        if not isinstance(schema, dict):
            return {}
        keep = {}
        for key in ("type", "additionalProperties", "required", "$ref"):
            if key in schema:
                keep[key] = schema[key]
        if "properties" in schema and isinstance(schema["properties"], dict):
            keep["properties"] = sorted(schema["properties"].keys())[:20]
        return keep
