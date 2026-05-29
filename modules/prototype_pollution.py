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
        # Control probe: same shape as a pollution payload but using a benign param
        # name so framework 404 / not-found error pages that always emit a generic
        # "Cannot read properties of" signature don't get classified as pollution.
        control_param = f"reconx_probe_normal_{self.marker_key}"
        control_url = self._append_qs(url, control_param, self.marker_value)
        control_resp = self.http_get(control_url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        control_body = (control_resp.text or "") if control_resp is not None else ""
        control_error = self._match_error(control_body)
        # Payload variants from PayloadsAllTheThings/Prototype Pollution. Each tries
        # a different syntax recognised by qs / express-query / lodash-style mergers.
        payloads = [
            (f"__proto__[{self.marker_key}]", self.marker_value),
            (f"__proto__.{self.marker_key}", self.marker_value),
            (f"constructor[prototype][{self.marker_key}]", self.marker_value),
            (f"constructor.prototype.{self.marker_key}", self.marker_value),
            # Deep / chained access patterns observed in real-world exploits.
            (f"a[constructor][prototype][{self.marker_key}]", self.marker_value),
            (f"__proto__[constructor][prototype][{self.marker_key}]", self.marker_value),
        ]
        for param, value in payloads:
            probe_url = self._append_qs(url, param, value)
            resp = self.http_get(probe_url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
            if resp is None:
                continue
            body = resp.text or ""
            if self.marker_value in body and self.marker_value not in baseline_body:
                if self._reflection_is_uri_echo_only(body, self.marker_value, param, probe_url):
                    # Marker only appears as the request URI echoed back inside an error
                    # page / debug response (e.g. Laravel debugbar JSON, Express 404). Not pollution.
                    continue
                return [self._finding("sspp_qs_reflection", "HIGH", probe_url, "Prototype pollution marker reflected from query string", {
                    "param": param,
                    "value": value,
                    "vector": "query_string",
                    "marker": self.marker_value,
                    "excerpt": self._excerpt(body, self.marker_value),
                })]
            error = self._match_error(body)
            # Only fire on an error signature that is specific to the probe — i.e. NOT
            # present in either the unmodified baseline OR the benign-param control
            # response. This filters out framework default error pages (Express 404,
            # NestJS unhandled route, etc.) that emit the same TypeError regardless.
            if error and error not in baseline_body and error != control_error:
                return [self._finding("sspp_qs_error", "MEDIUM", probe_url, "Prototype pollution error signature from query string", {
                    "param": param,
                    "value": value,
                    "vector": "query_string",
                    "error_signature": error,
                    "control_url": control_url,
                })]
        return []

    def _probe_json_body(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        # Baseline POST to know the response status against an unpolluted body.
        baseline = self.http_request(
            "POST", url, session=session, safe_readonly=True,
            headers={"Content-Type": "application/json"},
            data="{}",
            timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        baseline_status = baseline.status_code if baseline is not None else 0

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

        # Status-code-change probe: Express respects Object.prototype.status when set
        # via prototype pollution. Sending `{"__proto__":{"status":510}}` and observing
        # the response come back as 510 is a strong, high-confidence pollution signal.
        # Reference: PayloadsAllTheThings/Prototype Pollution#prototype-pollution-payloads.
        if baseline_status and 200 <= baseline_status < 300:
            status_payload = {"__proto__": {"status": 510}}
            resp = self.http_request(
                "POST", url, session=session, safe_readonly=True,
                headers={"Content-Type": "application/json"},
                data=json.dumps(status_payload),
                timeout=float(cfg.get("timeout", 10)), verify=False,
            )
            if resp is not None and resp.status_code == 510 and baseline_status != 510:
                return [self._finding(
                    "sspp_json_status_change",
                    "HIGH",
                    url,
                    "Prototype pollution reflected as HTTP status override",
                    {
                        "payload": status_payload,
                        "vector": "json_body_status",
                        "baseline_status": baseline_status,
                        "polluted_status": resp.status_code,
                    },
                )]
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
    def _reflection_is_uri_echo_only(body: str, marker: str, param: str, probe_url: str = "") -> bool:
        r"""Return True if every occurrence of the marker is just the request URI being
        echoed back (debug bars, JSON 404 responses, access-log style traces, framework
        "Not Found" pages that print the request path).

        Strategy: for each marker hit, look at a short window of bytes immediately
        before it and decide whether the marker is part of an echo of the request URI.
        Signals we accept:
          * The literal probe URL or its path+query appears in the window (raw or
            URL-encoded form).
          * The param=marker pair appears in the window AND the window contains a
            known URI-echo token (`"uri"`, `request_uri`, `GET /`, error-page phrases
            like `Unexpected path`, `Cannot GET`, `Not Found:`, etc).

        If at least one occurrence is in a meaningful context (HTML body text, JSON
        property value bound to a real key, etc.) we keep the finding.
        """
        if not body or marker not in body:
            return False
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
            # Express / NestJS / generic framework 404 phrasing
            "Unexpected path", "Cannot GET", "Cannot POST", "Cannot PUT",
            "Cannot DELETE", "Cannot PATCH",
            "Not Found:", "Not found:", "<title>Error",
            "ENOENT", "ENOTFOUND",
        )
        # Build a set of URI fragments derived from the actual probe URL — both raw
        # and percent-encoded variants. If any of these appear in the window before
        # the marker, treat the marker as a URI echo. We deliberately build fragments
        # WITHOUT the marker value because the window stops just before the marker,
        # so a fragment that ends with the marker would never match. We instead look
        # for the prefix "..path?...param=" which sits immediately to the left of
        # the marker when the request URL is echoed back.
        uri_fragments: list[str] = []
        if probe_url:
            try:
                parsed = urlparse(probe_url)
                if parsed.path:
                    uri_fragments.append(parsed.path)
                    # Path with the param= prefix, both raw and percent-encoded for [].
                    prefix = parsed.path + "?" + param + "="
                    uri_fragments.append(prefix)
                    uri_fragments.append(quote(prefix, safe="/?&=[]."))
                    uri_fragments.append(quote(prefix, safe="/?&="))
            except Exception:
                pass
        # Also include the param=  prefix on its own (in raw + percent-encoded forms),
        # so a stripped-down echo like ?__proto__%5B...%5D=marker still matches.
        prefix2 = param + "="
        uri_fragments.append(prefix2)
        uri_fragments.append(quote(prefix2, safe="[]=."))
        uri_fragments.append(quote(prefix2, safe="="))
        param_l = param
        while True:
            pos = body.find(marker, idx)
            if pos < 0:
                break
            any_match = True
            window_start = max(0, pos - 400)
            window = body[window_start: pos]
            # Strong signal: an adjacent URI fragment ends exactly where the marker
            # starts. In a URL echo the bytes immediately preceding the marker are
            # the request URL with the param= prefix (raw or percent-encoded). A real
            # pollution would typically emit the marker tied to a JSON property name
            # or HTML attribute, not as a continuation of the request URI.
            adjacent_uri_echo = any(frag and window.endswith(frag) for frag in uri_fragments)
            # Weaker signal: the param= appears anywhere in the window AND the window
            # carries a known URI-echo phrase (error page / access log style).
            param_seen = (
                f"{param_l}=" in window
                or (f"%5D={marker[:1]}" in window and "%5B" in window)
                or param_l in window
            )
            echo_seen = any(tok in window for tok in uri_echo_tokens)
            if adjacent_uri_echo or (param_seen and echo_seen):
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
