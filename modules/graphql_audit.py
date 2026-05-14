"""
ReconX - Module: GraphQL batching and depth-limit audit.
"""

import json

import requests

from modules.base import BaseModule


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

        findings = self._dedup(findings)
        self.save_json(findings, "graphql_audit_findings.json")
        return {"findings": findings, "total": len(findings), "endpoints": endpoints}

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
