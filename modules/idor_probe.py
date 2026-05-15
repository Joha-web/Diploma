"""
ReconX - Module: IDOR / BOLA candidate discovery and profile comparison.
"""

from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from modules.active_probe_base import ActiveProbeBase


ID_PARAM_RE = re.compile(
    r"(^|_|\b)(id|uuid|user|user_id|account|account_id|org|org_id|organization|"
    r"tenant|tenant_id|team|team_id|company|customer|owner|profile|project|order|"
    r"invoice|payment|subscription|workspace|member|role)(_id|id)?($|\b)",
    re.I,
)
HIGH_VALUE_PARAM_RE = re.compile(
    r"(user_id|account_id|org_id|organization_id|tenant_id|owner_id|customer_id|"
    r"company_id|workspace_id|member_id|role_id)",
    re.I,
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
INTEGER_ID_RE = re.compile(r"^[1-9][0-9]{0,11}$")
PATH_ID_RE = re.compile(r"/([a-z0-9_-]{2,40})/([0-9]{1,12}|[0-9a-f-]{24,36})(?=/|$|\?)", re.I)
OPENAPI_PARAM_RE = re.compile(r"\{([^}]+)\}")
SENSITIVE_RESOURCE_RE = re.compile(
    r"(users?|accounts?|orgs?|organizations?|tenants?|teams?|customers?|profiles?|"
    r"projects?|orders?|invoices?|payments?|subscriptions?|workspaces?|members?|roles?)",
    re.I,
)


class IDORProbeModule(ActiveProbeBase):
    name = "idor_probe"
    description = "IDOR / BOLA Candidate Analysis"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        parameter_results: dict | None = None,
        fuzzer_results: dict | None = None,
        openapi_results: dict | None = None,
        live_hosts: list | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "candidates": [], "total": 0, "status": "disabled"}

        candidates = self.limit(self._candidates(), "max_candidates", 200)
        findings = self._classify_candidates(candidates)
        profile_findings: list[dict] = []
        if self.module_config().get("compare_profiles", False):
            profile_findings = self._compare_profiles(candidates)
            findings.extend(profile_findings)
        if self.module_config().get("check_anonymous", False):
            anon_findings = self._check_anonymous_access(candidates)
            findings.extend(anon_findings)

        findings = self.dedup_findings(findings)
        self.save_json(candidates, "idor_candidates.json")
        self.save_json(findings, "idor_findings.json")
        return {
            "findings": findings,
            "candidates": candidates,
            "total": len(findings),
            "candidate_count": len(candidates),
            "profile_comparisons": len(profile_findings),
            "profiles_available": self.profile_names_with_auth(),
        }

    def _candidates(self) -> list[dict]:
        candidates: dict[tuple[str, str, str], dict] = {}

        def add(item: dict) -> None:
            url = str(item.get("url", "") or "").strip()
            if not url.startswith(("http://", "https://")) or not self.is_in_scope(url):
                return
            kind = str(item.get("kind", "url"))
            subject = str(item.get("param") or item.get("path_param") or item.get("resource") or "")
            key = (url, kind, subject)
            existing = candidates.setdefault(key, dict(item, sources=[]))
            source = item.get("source")
            if source and source not in existing["sources"]:
                existing["sources"].append(source)
            for field in ("method", "path", "summary", "security", "effective_security"):
                if item.get(field) and not existing.get(field):
                    existing[field] = item[field]

        for item in self.parameter_results.get("parameters", []) or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            param = item.get("param") or item.get("name", "")
            if self._interesting_param(param):
                add({"url": url, "kind": "query", "param": param, "source": item.get("source", "parameter_discovery")})

        for url in self.parameter_results.get("parameterized_targets", []) or []:
            self._add_url_candidates(str(url), "parameterized_target", add)

        classified = self.fuzzer_results.get("classified", {}) or {}
        for bucket in ("with_params", "api", "auth"):
            for url in classified.get(bucket, []) or []:
                self._add_url_candidates(str(url), f"fuzzer:{bucket}", add)
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            self._add_url_candidates(str(url), "fuzzer", add)

        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if not isinstance(endpoint, dict):
                continue
            url = endpoint.get("url", "")
            path = endpoint.get("path", urlparse(url).path)
            method = str(endpoint.get("method", "GET")).upper()
            path_params = OPENAPI_PARAM_RE.findall(str(path))
            for param in path_params:
                if self._interesting_param(param) or SENSITIVE_RESOURCE_RE.search(str(path)):
                    add({
                        "url": url,
                        "kind": "openapi_path_param",
                        "path_param": param,
                        "source": "openapi",
                        "method": method,
                        "path": path,
                        "summary": endpoint.get("summary", ""),
                        "security": endpoint.get("security"),
                        "effective_security": endpoint.get("effective_security"),
                    })
            self._add_url_candidates(url, "openapi", add, method=method)

        result = []
        for item in candidates.values():
            item["sources"] = sorted(set(item.get("sources", [])))
            result.append(item)
        return sorted(result, key=lambda value: (value.get("url", ""), value.get("kind", "")))

    def _add_url_candidates(self, url: str, source: str, add, method: str = "GET") -> None:
        if not url.startswith(("http://", "https://")):
            return
        for param, value in self.query_pairs(url):
            if self._interesting_param(param) or self._interesting_value(value):
                add({
                    "url": url,
                    "kind": "query",
                    "param": param,
                    "value_shape": self._value_shape(value),
                    "source": source,
                    "method": method,
                })

        path = urlparse(url).path
        for resource, value in PATH_ID_RE.findall(path):
            if SENSITIVE_RESOURCE_RE.search(resource) or self._interesting_value(value):
                add({
                    "url": url,
                    "kind": "path",
                    "resource": resource,
                    "value_shape": self._value_shape(value),
                    "source": source,
                    "method": method,
                })

    def _classify_candidates(self, candidates: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for item in candidates:
            kind = item.get("kind")
            evidence = {
                "kind": kind,
                "param": item.get("param") or item.get("path_param"),
                "resource": item.get("resource"),
                "value_shape": item.get("value_shape"),
                "method": item.get("method", "GET"),
                "path": item.get("path"),
                "sources": item.get("sources", []),
                "effective_security": item.get("effective_security"),
            }
            if kind == "query":
                severity = "HIGH" if HIGH_VALUE_PARAM_RE.search(str(item.get("param", ""))) else "MEDIUM"
                findings.append(self.make_finding(
                    "idor_query_identifier_candidate",
                    item["url"],
                    evidence=evidence,
                    severity=severity,
                    confidence=0.76 if severity == "HIGH" else 0.70,
                ))
            elif kind == "path":
                findings.append(self.make_finding("idor_path_identifier_candidate", item["url"], evidence=evidence))
            elif kind == "openapi_path_param":
                findings.append(self.make_finding("idor_openapi_object_endpoint", item["url"], evidence=evidence))
        return findings

    def _compare_profiles(self, candidates: list[dict]) -> list[dict]:
        profiles = self.profile_names_with_auth()
        profile_a = self.module_config().get("profile_a", "user_a")
        profile_b = self.module_config().get("profile_b", "user_b")
        if profile_a not in profiles or profile_b not in profiles:
            self.warn("IDOR profile comparison needs auth_profiles.user_a and auth_profiles.user_b")
            return []

        findings: list[dict] = []
        timeout = self.request_timeout()
        max_requests = int(self.module_config().get("max_compare_requests", 40))
        sent = 0
        for item in candidates:
            method = str(item.get("method", "GET")).upper()
            if method not in ("GET", "HEAD") or sent + 2 > max_requests:
                continue
            url = item["url"]
            resp_a = self.get_with_profile(url, profile_a, timeout=timeout, verify=False)
            self.jitter_sleep()
            resp_b = self.get_with_profile(url, profile_b, timeout=timeout, verify=False)
            sent += 2
            if resp_a is None or resp_b is None:
                continue
            if not self._successful(resp_a) or not self._successful(resp_b):
                continue
            similarity = self._response_similarity(resp_a, resp_b)
            if similarity < float(self.module_config().get("similarity_threshold", 0.92)):
                continue
            findings.append(self.make_finding(
                "idor_profile_response_overlap",
                url,
                evidence={
                    "profile_a": profile_a,
                    "profile_b": profile_b,
                    "status_a": resp_a.status_code,
                    "status_b": resp_b.status_code,
                    "length_a": len(resp_a.text or ""),
                    "length_b": len(resp_b.text or ""),
                    "similarity": similarity,
                    "body_sha256": self._body_hash(resp_a.text or ""),
                    "candidate": item,
                },
                confidence=min(0.90, 0.60 + (similarity * 0.30)),
            ))
        return findings

    def _check_anonymous_access(self, candidates: list[dict]) -> list[dict]:
        findings: list[dict] = []
        timeout = self.request_timeout()
        max_requests = int(self.module_config().get("max_anonymous_requests", 20))
        sent = 0
        for item in candidates:
            method = str(item.get("method", "GET")).upper()
            if method not in ("GET", "HEAD") or sent >= max_requests:
                continue
            resp = self.get_with_profile(item["url"], "anonymous", timeout=timeout, verify=False)
            sent += 1
            if resp is None or not self._successful(resp):
                continue
            findings.append(self.make_finding(
                "idor_anonymous_object_access",
                item["url"],
                evidence={
                    "status": resp.status_code,
                    "length": len(resp.text or ""),
                    "candidate": item,
                    "body_sha256": self._body_hash(resp.text or ""),
                },
            ))
        return findings

    @staticmethod
    def _interesting_param(param: str) -> bool:
        return bool(ID_PARAM_RE.search(str(param or "")))

    @staticmethod
    def _interesting_value(value: str) -> bool:
        value = str(value or "").strip()
        return bool(UUID_RE.match(value) or INTEGER_ID_RE.match(value))

    @staticmethod
    def _value_shape(value: str) -> str:
        value = str(value or "").strip()
        if UUID_RE.match(value):
            return "uuid"
        if INTEGER_ID_RE.match(value):
            return "integer"
        if re.match(r"^[0-9a-f]{24,36}$", value, re.I):
            return "hex_identifier"
        return "unknown"

    @staticmethod
    def _successful(resp) -> bool:
        return 200 <= int(getattr(resp, "status_code", 0)) < 300

    @staticmethod
    def _response_similarity(resp_a, resp_b) -> float:
        body_a = resp_a.text or ""
        body_b = resp_b.text or ""
        json_similarity = IDORProbeModule._json_response_similarity(resp_a, resp_b)
        if json_similarity is not None:
            return json_similarity
        if not body_a and not body_b:
            return 1.0
        if IDORProbeModule._body_hash(body_a) == IDORProbeModule._body_hash(body_b):
            return 1.0
        larger = max(len(body_a), len(body_b), 1)
        smaller = min(len(body_a), len(body_b))
        return smaller / larger

    @staticmethod
    def _json_response_similarity(resp_a, resp_b) -> float | None:
        try:
            data_a = resp_a.json()
            data_b = resp_b.json()
        except Exception:
            return None

        scalars_a = IDORProbeModule._flatten_scalar_values(data_a)
        scalars_b = IDORProbeModule._flatten_scalar_values(data_b)
        if not scalars_a and not scalars_b:
            return 1.0
        if not scalars_a or not scalars_b:
            return 0.0

        exact_overlap = len(scalars_a & scalars_b) / max(len(scalars_a | scalars_b), 1)
        canonical_a = IDORProbeModule._canonical_json(data_a)
        canonical_b = IDORProbeModule._canonical_json(data_b)
        text_similarity = SequenceMatcher(None, canonical_a, canonical_b).ratio()
        return (exact_overlap * 0.70) + (text_similarity * 0.30)

    @staticmethod
    def _flatten_scalar_values(value, prefix: str = "") -> set[str]:
        values: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                values.update(IDORProbeModule._flatten_scalar_values(child, name))
        elif isinstance(value, list):
            for idx, child in enumerate(value[:5]):
                name = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                values.update(IDORProbeModule._flatten_scalar_values(child, name))
        else:
            values.add(f"{prefix}={json.dumps(value, sort_keys=True, default=str)}")
        return values

    @staticmethod
    def _canonical_json(value) -> str:
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except TypeError:
            return str(value)

    @staticmethod
    def _body_hash(body: str) -> str:
        return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
