"""
ReconX - Module: GraphQL batching, depth, alias-amplification, CSRF and IDE-exposure audit.
"""

import json
import re

import requests

from modules.base import BaseModule


# "Did you mean" patterns — even when introspection is disabled, many GraphQL
# servers leak field/type names in error suggestions. Sourced from
# PayloadsAllTheThings/GraphQL Injection. Tolerates JSON-escaped quotes
# (e.g. `Did you mean \"user\"`) and Unicode smart quotes.
FIELD_SUGGESTION_RE = re.compile(
    r"[Dd]id you mean[\s\\'\"`‘’“”]+([A-Za-z_][A-Za-z0-9_]*)",
)

# Common GraphQL IDE endpoints that ship enabled in dev builds and get left on
# in production. Any 200 response containing the IDE bootstrap script is a leak.
IDE_PATHS = (
    "/graphiql", "/graphql/graphiql", "/playground", "/graphql-playground",
    "/altair", "/voyager",
)
IDE_BODY_SIGNATURES = (
    "GraphiQL", "GraphQL Playground", "altair-graphql", "graphql-voyager",
    "subscriptionEndpoint", "subscriptions-transport-ws",
)


class GraphQLAuditModule(BaseModule):
    name = "graphql_audit"
    description = "GraphQL Batching / Depth Limit Audit"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 fuzzer_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("graphql_audit", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        endpoints = self._endpoints()[: int(cfg.get("max_endpoints", 30))]
        if not endpoints:
            self.warn("No GraphQL endpoints for audit")
            return {"findings": [], "total": 0, "endpoints": []}

        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for endpoint in endpoints:
            findings.extend(self._check_batching(endpoint, session, cfg))
            findings.extend(self._check_depth(endpoint, session, cfg))
            findings.extend(self._check_field_suggestions(endpoint, session, cfg))
            findings.extend(self._check_alias_amplification(endpoint, session, cfg))
            findings.extend(self._check_get_mutation(endpoint, session, cfg))
            findings.extend(self._check_ide_exposure(endpoint, session, cfg))

        findings = self._dedup(findings)
        self.save_json(findings, "graphql_audit_findings.json")
        return {"findings": findings, "total": len(findings), "endpoints": endpoints}

    def _check_field_suggestions(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        """Even with introspection disabled, many servers leak field/type names
        in error responses via 'Did you mean ...' suggestions.
        """
        if not cfg.get("field_suggestions", True):
            return []
        # Intentionally malformed query — references a field that almost certainly
        # doesn't exist. Servers with suggestions enabled reply with "Did you mean".
        probe = {"query": "{ reconxNonExistentField0123 }"}
        resp = self.http_post(
            endpoint, session=session, safe_readonly=True,
            json=probe, timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        if resp is None:
            return []
        body = resp.text or ""
        match = FIELD_SUGGESTION_RE.search(body)
        if not match:
            return []
        suggestions = [m.group(1) for m in FIELD_SUGGESTION_RE.finditer(body)][:10]
        return [self._finding(
            "graphql_field_suggestions_enabled",
            "MEDIUM",
            endpoint,
            "GraphQL leaks schema field names via error suggestions",
            {
                "suggestions": suggestions,
                "probe": probe["query"],
                "status_code": resp.status_code,
            },
        )]

    def _check_alias_amplification(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        """Aliased fields let a single request issue many resolver calls. If the
        server accepts a large alias count without rate-limiting, it's a vector
        for resolver-side DoS and brute-force amplification.
        """
        if not cfg.get("alias_amplification", True):
            return []
        alias_count = int(cfg.get("alias_count", 100))
        # Build a single query with N aliased __typename calls.
        aliases = " ".join(f"a{i}: __typename" for i in range(alias_count))
        probe = {"query": "{ " + aliases + " }"}
        resp = self.http_post(
            endpoint, session=session, safe_readonly=True,
            json=probe, timeout=float(cfg.get("timeout", 15)), verify=False,
        )
        if resp is None:
            return []
        data = self._json(resp)
        text = (resp.text or "").lower()
        rate_markers = ("alias", "complexity", "too many", "rate limit", "throttle")
        if (
            resp.status_code < 400
            and isinstance(data, dict)
            and isinstance(data.get("data"), dict)
            # All N aliases must have resolved — partial failure suggests a cap.
            and len(data["data"]) >= alias_count
            and not any(marker in text for marker in rate_markers)
        ):
            return [self._finding(
                "graphql_alias_amplification",
                "MEDIUM",
                endpoint,
                "GraphQL accepts large alias batches without limit",
                {
                    "alias_count": alias_count,
                    "status_code": resp.status_code,
                    "resolved_count": len(data["data"]),
                },
            )]
        return []

    def _check_get_mutation(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        """Mutations accepted via GET are CSRF-able — an attacker can use an
        <img src="…?query=mutation{…}"> to force state-changing requests.
        """
        if not cfg.get("get_mutation_check", True):
            return []
        # Use __typename as a no-side-effect mutation probe. A truly safe server
        # rejects mutations over GET (HTTP 405 or 400) regardless of body content.
        params = {"query": "mutation { __typename }"}
        resp = self.http_get(
            endpoint, session=session, params=params,
            timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        if resp is None:
            return []
        data = self._json(resp)
        body_lower = (resp.text or "").lower()
        if resp.status_code >= 400:
            return []
        # A safe server returns an error mentioning that mutations must be POST.
        safe_markers = ("mutations are not supported", "must be a post", "must be sent over post",
                         "method not allowed", "only post", "must use post")
        if any(marker in body_lower for marker in safe_markers):
            return []
        # If the server resolves the mutation in `data` we have a CSRF vector.
        if isinstance(data, dict) and data.get("data") and not data.get("errors"):
            return [self._finding(
                "graphql_mutation_over_get",
                "MEDIUM",
                endpoint,
                "GraphQL accepts mutations over HTTP GET (CSRF vector)",
                {
                    "status_code": resp.status_code,
                    "probe": params["query"],
                },
            )]
        return []

    def _check_ide_exposure(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        """Probe well-known GraphQL IDE paths next to the endpoint root and look
        for IDE bootstrap markers (GraphiQL, Playground, Altair, Voyager).
        """
        if not cfg.get("ide_exposure", True):
            return []
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(endpoint)
        # Try the endpoint itself AND each IDE path mounted on the same origin.
        candidates = [endpoint]
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        for path in IDE_PATHS:
            candidates.append(origin + path)
        findings: list[dict] = []
        seen_signatures: set[str] = set()
        for url in candidates[: int(cfg.get("max_ide_paths", 8))]:
            resp = self.http_get(
                url, session=session,
                timeout=float(cfg.get("timeout", 10)), verify=False,
                headers={"Accept": "text/html"},
            )
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            matched = [sig for sig in IDE_BODY_SIGNATURES if sig in body]
            if not matched or matched[0] in seen_signatures:
                continue
            seen_signatures.add(matched[0])
            findings.append(self._finding(
                "graphql_ide_exposed",
                "MEDIUM",
                url,
                "GraphQL IDE / playground reachable",
                {
                    "ide_markers": matched[:3],
                    "status_code": resp.status_code,
                },
            ))
        return findings

    def _check_batching(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        payload = [{"query": "{ __typename }"} for _ in range(int(cfg.get("batch_size", 8)))]
        resp = self.http_post(
            endpoint, session=session, safe_readonly=True,
            json=payload, timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        if resp is None:
            return []
        data = self._json(resp)
        if isinstance(data, list) and len(data) >= 2:
            return [self._finding("graphql_batching_enabled", "MEDIUM", endpoint, "GraphQL query batching appears enabled", {
                "batch_size": len(payload),
                "status_code": resp.status_code,
                "responses": len(data),
            })]
        return []

    def _check_depth(self, endpoint: str, session: requests.Session, cfg: dict) -> list[dict]:
        depth = int(cfg.get("depth", 12))
        query = self._nested_typename_query(depth)
        resp = self.http_post(
            endpoint, session=session, safe_readonly=True,
            json={"query": query}, timeout=float(cfg.get("timeout", 10)), verify=False,
        )
        if resp is None:
            return []
        data = self._json(resp)
        text = (resp.text or "").lower()
        if (
            resp.status_code < 500
            and isinstance(data, dict)
            and data.get("data")
            and not data.get("errors")
            and not any(marker in text for marker in ("depth", "complexity", "too deep", "maximum"))
        ):
            return [self._finding("graphql_depth_limit_not_observed", "LOW", endpoint, "GraphQL depth limit was not observed", {
                "depth": depth,
                "status_code": resp.status_code,
            })]
        return []

    def _endpoints(self) -> list[str]:
        endpoints: set[str] = set()
        endpoints.update(str(url) for url in self.fuzzer_results.get("graphql_endpoints", []) or [])
        for detail in self.fuzzer_results.get("graphql_details", []) or []:
            if isinstance(detail, dict) and detail.get("endpoint"):
                endpoints.add(detail["endpoint"])
        classified = self.fuzzer_results.get("classified", {}) or {}
        endpoints.update(str(url) for url in classified.get("graphql", []) or [])
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if "graphql" in url:
                endpoints.add(url)
        return self.filter_in_scope_urls(endpoints)

    @staticmethod
    def _nested_typename_query(depth: int) -> str:
        inner = "__typename"
        for idx in range(depth):
            inner = f"f{idx}: __typename\nnested{idx} {{ {inner} }}"
        return "{ " + inner + " }"

    @staticmethod
    def _json(resp):
        try:
            return resp.json()
        except Exception:
            try:
                return json.loads(resp.text or "")
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
            "references": ["https://portswigger.net/web-security/graphql"],
            "confidence": 0.75,
        }
