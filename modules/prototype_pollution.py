"""
ReconX - Module: server-side prototype pollution probes.
"""

import json
import re
import uuid
from urllib.parse import quote, urlparse

import requests

from modules.base import BaseModule


ERROR_SIGNATURES = [
    r"Cannot set properties of",
    r"Cannot read properties of",
    r"prototype.*pollution",
    r"Prototype Pollution",
    r"circular.*structure",
]


class PrototypePollutionModule(BaseModule):
    name = "prototype_pollution"
    description = "Server-Side Prototype Pollution (SSPP)"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        fuzzer_results: dict | None = None,
        openapi_results: dict | None = None,
        live_hosts: list | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}
        self.live_hosts = live_hosts or []
        self.marker_key = "reconx_pp_probe"
        self.marker_value = f"reconx_{uuid.uuid4().hex[:8]}"

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("prototype_pollution", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._select_targets()[: int(cfg.get("max_targets", 80))]
        if not targets:
            self.warn("No API targets for prototype pollution probes")
            return {"findings": [], "total": 0}

        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for url in targets:
            findings.extend(self._probe_query(url, session, cfg))
            if cfg.get("body_probes", False) or self.config.get("scan", {}).get("allow_write", False):
                findings.extend(self._probe_json_body(url, session, cfg))
                findings.extend(self._probe_form_body(url, session, cfg))

        findings = self._dedup(findings)
        self.save_json(findings, "prototype_pollution_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _probe_query(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        baseline = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        baseline_body = baseline.text or "" if baseline else ""
        payloads = [
            (f"__proto__[{self.marker_key}]", self.marker_value),
            (f"__proto__.{self.marker_key}", self.marker_value),
            (f"constructor[prototype][{self.marker_key}]", self.marker_value),
            (f"constructor.prototype.{self.marker_key}", self.marker_value),
        ]
        for param, value in payloads:
            probe_url = self._append_qs(url, param, value)
            resp = self.http_get(probe_url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
            if resp is None:
                continue
            body = resp.text or ""
            if self.marker_value in body and self.marker_value not in baseline_body:
                if self._reflection_is_uri_echo_only(body, self.marker_value, param):
                    # Marker only appears as the request URI echoed back inside an error
                    # page / debug response (e.g. Laravel debugbar JSON). Not pollution.
                    continue
                return [self._finding("sspp_qs_reflection", "HIGH", probe_url, "Prototype pollution marker reflected from query string", {
                    "param": param,
                    "value": value,
                    "vector": "query_string",
                    "marker": self.marker_value,
                    "excerpt": self._excerpt(body, self.marker_value),
                })]
            error = self._match_error(body)
            if error and error not in baseline_body:
                return [self._finding("sspp_qs_error", "MEDIUM", probe_url, "Prototype pollution error signature from query string", {
                    "param": param,
                    "value": value,
                    "vector": "query_string",
                    "error_signature": error,
                })]
        return []

    def _probe_json_body(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        payloads = [
            {"__proto__": {self.marker_key: self.marker_value}},
            {"constructor": {"prototype": {self.marker_key: self.marker_value}}},
        ]
        for payload in payloads:
            resp = self.http_request(
                "POST", url, session=session, safe_readonly=True,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=float(cfg.get("timeout", 10)), verify=False,
            )
            if resp is None:
                continue
            body = resp.text or ""
            if self.marker_value in body:
                return [self._finding("sspp_json_reflection", "HIGH", url, "Prototype pollution marker reflected from JSON body", {
                    "payload": payload,
                    "vector": "json_body",
                    "marker": self.marker_value,
                    "excerpt": self._excerpt(body, self.marker_value),
                })]
            error = self._match_error(body)
            if error:
                return [self._finding("sspp_json_error", "MEDIUM", url, "Prototype pollution error signature from JSON body", {
                    "payload": payload,
                    "vector": "json_body",
                    "error_signature": error,
                })]
        return []

    def _probe_form_body(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        payload = f"__proto__[{self.marker_key}]={quote(self.marker_value)}"
        resp = self.http_request(
            "POST", url, session=session, safe_readonly=True,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=payload,
            timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        if resp and self.marker_value in (resp.text or ""):
            return [self._finding("sspp_form_reflection", "HIGH", url, "Prototype pollution marker reflected from form body", {
                "payload": payload,
                "vector": "form_body",
                "marker": self.marker_value,
                "excerpt": self._excerpt(resp.text or "", self.marker_value),
            })]
        return []

    def _select_targets(self) -> list[str]:
        candidates: set[str] = set()
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("api", "auth", "with_params"):
            candidates.update(str(url) for url in classified.get(key, []) or [])
        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if isinstance(endpoint, dict) and endpoint.get("url"):
                candidates.add(endpoint["url"])
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")) and self._looks_api_like(url):
                candidates.add(url)
        return self.filter_in_scope_urls(candidates)

    @staticmethod
    def _looks_api_like(url: str) -> bool:
        parsed = urlparse(url)
        return any(token in parsed.path.lower() for token in ("/api", "/graphql", "/rest", "/v1", "/v2"))

    @staticmethod
    def _append_qs(url: str, param: str, value: str) -> str:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{quote(param, safe='[].')}={quote(value)}"

    @staticmethod
    def _match_error(body: str) -> str:
        for pattern in ERROR_SIGNATURES:
            match = re.search(pattern, body or "", re.I)
            if match:
                return match.group(0)
        return ""

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 100) -> str:
        idx = body.find(marker)
        if idx < 0:
            return body[:200]
        return body[max(0, idx - radius): idx + len(marker) + radius]

    @staticmethod
    def _reflection_is_uri_echo_only(body: str, marker: str, param: str) -> bool:
        r"""Return True if every occurrence of the marker is just the request URI being
        echoed back (debug bars, JSON 404 responses, access-log style traces).

        We look at a short window of bytes immediately before each marker hit and detect
        signatures like "uri":"\/...?param=...", request_uri=..., GET /path?param=...
        If at least one occurrence is in a meaningful context (HTML body, JSON property
        value bound to a real key), we keep the finding.
        """
        if not body or marker not in body:
            return False
        body_l = body
        idx = 0
        any_match = False
        # Tokens that strongly suggest a URI echo (the marker is part of the request path/query).
        uri_echo_tokens = (
            '"uri"', "'uri'", "request_uri", "REQUEST_URI",
            '"url"', "'url'",
            '"path"', "'path'",
            '"path_info"', "PATH_INFO",
            '"query_string"', "QUERY_STRING",
            "GET /", "POST /", "PUT /", "PATCH /", "DELETE /",
            "HTTP_REQUEST_URI", "fullUrl", '"originalUrl"',
            '"requestUri"', "request-uri",
        )
        # The marker key (e.g. "__proto__[reconx_pp_probe]") inside an HTML link or a
        # rendered error trace looking like ?__proto__[...]=... — typical URI echo.
        # Build a list of param-related substrings to check appears right before the marker.
        param_l = param
        while True:
            pos = body_l.find(marker, idx)
            if pos < 0:
                break
            any_match = True
            window_start = max(0, pos - 300)
            window = body_l[window_start: pos]
            # If the marker is preceded (within ~300 chars) by the param= or %5D= pattern
            # AND the window contains a uri-echo signature, treat this occurrence as echo.
            param_seen = (f"{param_l}=" in window) or (f"%5D={marker[:1]}" in window and "%5B" in window) or (param_l in window)
            echo_seen = any(tok in window for tok in uri_echo_tokens)
            if param_seen and echo_seen:
                idx = pos + len(marker)
                continue
            return False
        return any_match

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
            "description": (
                "Server-side JavaScript object prototype pollution indicators were observed. "
                "Validate parser behavior and downstream impact manually."
            ),
            "evidence": evidence,
            "references": [
                "https://portswigger.net/research/server-side-prototype-pollution",
                "https://cwe.mitre.org/data/definitions/1321.html",
            ],
            "confidence": 0.85 if "reflection" in finding_id else 0.65,
        }
