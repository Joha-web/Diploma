"""
ReconX - Module: cross-finding correlation rules.

The correlator consumes completed module outputs and emits manual-review
priorities when separate weak signals become stronger together.
"""

import re
from urllib.parse import urlparse

from modules.base import BaseModule


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class CorrelatorModule(BaseModule):
    name = "correlator"
    description = "Cross-Finding Correlation"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 all_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.all_results = all_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("correlator", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "rules": [], "total": 0, "status": "disabled"}

        findings: list[dict] = []
        for rule in (
            self._rule_admin_port_no_waf_cve,
            self._rule_public_cloud_listing,
            self._rule_graphql_mutations,
            self._rule_email_spoofing,
            self._rule_exposed_datastore,
            self._rule_docker_api_exposed,
            self._rule_high_confidence_takeover,
            self._rule_cors_with_auth,
            self._rule_xss_with_auth,
        ):
            result = rule()
            if result:
                findings.append(result)

        findings.sort(key=lambda item: SEVERITY_ORDER.get(item.get("severity", "INFO"), 5))
        self.save_json(findings, "correlated_findings.json")
        if findings:
            self.warn(f"Correlated priority items: {len(findings)}")
        else:
            self.success("No cross-finding priority rules matched")
        return {
            "findings": findings,
            "rules": [item.get("rule_id", "") for item in findings],
            "total": len(findings),
        }

    def _rule_admin_port_no_waf_cve(self) -> dict | None:
        admin_urls = self._admin_urls()
        admin_ports = self._admin_ports()
        wafs = self._wafs()
        cve_evidence = self._cve_evidence()
        if not (admin_urls and admin_ports and not wafs and cve_evidence):
            return None

        return self._finding(
            rule_id="admin_panel_exposed_port_no_waf_cve",
            severity="HIGH",
            title="Admin surface exposed with risky port, no WAF signal, and CVE context",
            description=(
                "Admin-like endpoints, administrative HTTP ports, missing WAF evidence, "
                "and CVE/ExploitDB correlation were observed in the same scan. Prioritize "
                "manual validation of access control and patch level."
            ),
            evidence={
                "admin_urls": admin_urls[:20],
                "admin_ports": admin_ports[:20],
                "waf_detected": False,
                "cve_context": cve_evidence[:20],
            },
            confidence=0.8,
        )

    def _rule_public_cloud_listing(self) -> dict | None:
        public_assets = [
            asset for asset in self.all_results.get("fuzzer", {}).get("cloud_assets", []) or []
            if asset.get("listing", {}).get("public")
        ]
        if not public_assets:
            return None
        return self._finding(
            rule_id="public_cloud_storage_listing",
            severity="CRITICAL",
            title="Public cloud storage listing exposed",
            description=(
                "A cloud storage URL discovered during crawling or JavaScript analysis "
                "allowed anonymous object listing."
            ),
            evidence={"assets": public_assets[:20]},
            confidence=0.95,
        )

    def _rule_graphql_mutations(self) -> dict | None:
        exposed = []
        for detail in self.all_results.get("fuzzer", {}).get("graphql_details", []) or []:
            if detail.get("introspection_enabled") and detail.get("mutation_fields"):
                exposed.append({
                    "endpoint": detail.get("endpoint", ""),
                    "mutation_type": detail.get("mutation_type", ""),
                    "mutation_fields": detail.get("mutation_fields", [])[:30],
                    "schema_file": detail.get("schema_file", ""),
                })
        if not exposed:
            return None
        return self._finding(
            rule_id="graphql_introspection_mutations_exposed",
            severity="HIGH",
            title="GraphQL introspection exposes mutation surface",
            description=(
                "GraphQL introspection returned schema data and mutation field names. "
                "Review authentication and authorization on mutation resolvers."
            ),
            evidence={"graphql": exposed[:10]},
            confidence=0.9,
        )

    def _rule_email_spoofing(self) -> dict | None:
        email = self.all_results.get("recon", {}).get("email_security", {}) or {}
        types = {finding.get("type") for finding in email.get("findings", []) or []}
        if not {"missing_spf", "missing_dmarc"}.issubset(types):
            return None
        return self._finding(
            rule_id="missing_spf_and_dmarc",
            severity="MEDIUM",
            title="Email spoofing and phishing controls missing",
            description="Both SPF and DMARC records are absent for the target domain.",
            evidence={
                "has_spf": email.get("has_spf", False),
                "has_dmarc": email.get("has_dmarc", False),
                "findings": email.get("findings", []),
            },
            confidence=0.9,
        )

    def _rule_exposed_datastore(self) -> dict | None:
        ports = self._open_ports({6379: "Redis", 9200: "Elasticsearch"})
        if not ports:
            return None

        evidence_text = "\n".join(self._evidence_strings()).lower()
        auth_markers = (
            "no auth", "no-auth", "no authentication", "without authentication",
            "unauthenticated", "authentication disabled", "anonymous access",
        )
        datastore_markers = ("redis", "elasticsearch", "_cluster", "_cat/indices")
        port_text = "\n".join(
            " ".join(str(port.get(key, "")) for key in ("service", "product", "extrainfo"))
            for port in ports
        ).lower()
        has_datastore_marker = any(
            marker in evidence_text or marker in port_text
            for marker in datastore_markers
        )
        has_no_auth_marker = any(marker in evidence_text for marker in auth_markers)
        elastic_http_open = any(port.get("port") == 9200 for port in ports) and any(
            host.get("status") == 200 for host in self._web_hosts_on_port(9200)
        )
        if not has_datastore_marker or not (has_no_auth_marker or elastic_http_open):
            return None

        return self._finding(
            rule_id="exposed_datastore_no_auth_indicators",
            severity="HIGH",
            title="Datastore port exposed with no-auth indicators",
            description=(
                "A Redis or Elasticsearch service is exposed and scan evidence suggests "
                "anonymous or unauthenticated access. Validate access controls immediately."
            ),
            evidence={
                "ports": ports,
                "web_hosts": self._web_hosts_on_port(9200),
                "matched_markers": [
                    marker for marker in auth_markers + datastore_markers
                    if marker in evidence_text
                ][:20],
            },
            confidence=0.85,
        )

    def _rule_docker_api_exposed(self) -> dict | None:
        ports = self._open_ports({2375: "Docker API"})
        if not ports:
            return None

        evidence_text = "\n".join(self._evidence_strings()).lower()
        normalized_text = evidence_text.replace('\\"', '"')
        docker_marker = '"message":"page not found"'
        if not (
            re.search(r'"message"\s*:\s*"page not found"', normalized_text)
            or "docker api" in normalized_text
        ):
            return None

        return self._finding(
            rule_id="docker_api_exposed",
            severity="CRITICAL",
            title="Docker API exposure indicators detected",
            description=(
                "TCP/2375 is open and scan evidence matches Docker API behavior. "
                "Unauthenticated Docker API access can lead to host compromise."
            ),
            evidence={
                "ports": ports,
                "matched_marker": docker_marker if "page not found" in normalized_text else "docker api",
            },
            confidence=0.9,
        )

    def _rule_high_confidence_takeover(self) -> dict | None:
        matches = []
        for finding in self.all_results.get("takeover_checker", {}).get("findings", []) or []:
            evidence = finding.get("evidence", {}) or {}
            cnames = evidence.get("cnames", []) or []
            body = evidence.get("body_fingerprint", "")
            confidence = float(finding.get("confidence", 0) or 0)
            if finding.get("severity") == "HIGH" and confidence >= 0.8 and cnames and body:
                matches.append({
                    "host": evidence.get("host", finding.get("url", "")),
                    "url": finding.get("url", ""),
                    "provider": finding.get("provider", ""),
                    "cnames": cnames,
                    "body_fingerprint": body,
                    "confidence": confidence,
                })
        if not matches:
            return None

        return self._finding(
            rule_id="high_confidence_subdomain_takeover",
            severity="CRITICAL",
            title="High-confidence subdomain takeover candidate",
            description=(
                "A takeover checker finding has both third-party CNAME evidence and "
                "a provider body fingerprint. Treat this as a priority manual validation item."
            ),
            evidence={"takeover": matches[:20]},
            confidence=0.95,
        )

    def _rule_cors_with_auth(self) -> dict | None:
        """CORS CRITICAL + auth findings on same host = very high risk."""
        cors_crits = [
            f for f in self.all_results.get("cors_checker", {}).get("findings", []) or []
            if f.get("severity") == "CRITICAL"
        ]
        auth_findings = self.all_results.get("auth_probe", {}).get("findings", []) or []
        if not cors_crits or not auth_findings:
            return None

        cors_hosts = {urlparse(f.get("url", "")).hostname for f in cors_crits} - {None}
        auth_hosts = {urlparse(f.get("url", "")).hostname for f in auth_findings} - {None}
        overlap = cors_hosts & auth_hosts
        if not overlap:
            return None

        return self._finding(
            rule_id="cors_critical_with_session_cookies",
            severity="CRITICAL",
            title="Critical CORS + session cookies on same host",
            description=(
                "A host with critical CORS misconfiguration (reflects arbitrary origin "
                "with credentials=true) also sets session cookies. An attacker can read "
                "authenticated API responses from any website."
            ),
            evidence={
                "cors_findings": [f.get("url") for f in cors_crits[:5]],
                "auth_findings": [f.get("url") for f in auth_findings[:5]],
                "affected_hosts": sorted(overlap),
            },
            confidence=0.95,
        )

    def _rule_xss_with_auth(self) -> dict | None:
        """XSS + application with sessions = account takeover risk."""
        xss_findings = [
            f for f in self.all_results.get("xss", {}).get("findings", []) or []
            if f.get("severity") in ("CRITICAL", "HIGH")
        ]
        if not xss_findings:
            return None
        auth_exists = bool(self.all_results.get("auth_probe", {}).get("findings"))
        if not auth_exists:
            return None
        return self._finding(
            rule_id="xss_with_active_sessions",
            severity="CRITICAL",
            title="Reflected XSS in authenticated application",
            description=(
                "XSS findings combined with active session management indicate "
                "account takeover risk."
            ),
            evidence={"xss_urls": [f.get("url") for f in xss_findings[:5]]},
            confidence=0.88,
        )

    def _admin_urls(self) -> list[str]:
        classified = self.all_results.get("fuzzer", {}).get("classified", {}) or {}
        urls = []
        for item in classified.get("admin_panels", []) or []:
            url = str(item)
            if url.startswith(("http://", "https://")):
                if self.is_in_scope(url):
                    urls.append(url)
            elif url.startswith("/"):
                urls.append(url)
        return sorted(set(urls))

    def _admin_ports(self) -> list[dict]:
        configured = self.config.get("scan", {}).get("correlator", {}).get("admin_ports")
        admin_port_set = {int(p) for p in (configured or [8080, 8081, 8443, 9000, 9443, 10000])}
        return self._open_ports({port: "admin" for port in admin_port_set})

    def _open_ports(self, interesting_ports: dict[int, str]) -> list[dict]:
        matches: list[dict] = []
        for host in self.all_results.get("portscan", {}).get("hosts", []) or []:
            ip = str(host.get("ip", ""))
            for port in host.get("open_ports", []) or []:
                try:
                    port_num = int(port.get("port", 0))
                except (TypeError, ValueError):
                    continue
                if port_num in interesting_ports:
                    matches.append({
                        "ip": ip,
                        "port": port_num,
                        "service": port.get("service", "") or interesting_ports[port_num],
                        "product": port.get("product", ""),
                        "version": port.get("version", ""),
                        "extrainfo": port.get("extrainfo", ""),
                    })
        return matches

    def _web_hosts_on_port(self, port: int) -> list[dict]:
        matches: list[dict] = []
        for host in self.all_results.get("webdetect", {}).get("live_hosts", []) or []:
            url = str(host.get("url", ""))
            parsed = urlparse(url)
            if parsed.port == port:
                matches.append({
                    "url": url,
                    "status": host.get("status", 0),
                    "title": host.get("title", ""),
                    "server": host.get("server", ""),
                })
        return matches

    def _evidence_strings(self) -> list[str]:
        values: list[str] = []
        for module_name in (
            "portscan", "webdetect", "fuzzer", "endpoint_harvester", "vulnscan", "cve_check",
            "takeover_checker", "openapi_parser", "parameter_discovery",
            "cors_checker", "auth_probe", "xss", "sql_injection",
            "host_header_injection", "idor_probe", "ssrf_probe", "error_analyzer", "jwt_audit",
            "oauth_probe", "http_smuggling",
            "prototype_pollution", "xxe_probe",
            "injection_probe", "api_key_validator",
        ):
            data = self.all_results.get(module_name, {})
            if data:
                values.extend(self._string_values(data))
        return values

    @classmethod
    def _string_values(cls, value) -> list[str]:
        if isinstance(value, dict):
            result: list[str] = []
            for key, item in value.items():
                result.append(str(key))
                result.extend(cls._string_values(item))
            return result
        if isinstance(value, (list, tuple, set)):
            result: list[str] = []
            for item in value:
                result.extend(cls._string_values(item))
            return result
        if value is None:
            return []
        return [str(value)]

    def _wafs(self) -> list[str]:
        wafs: set[str] = set()
        for host in self.all_results.get("techstack", {}).get("hosts", []) or []:
            for waf in host.get("waf", []) or []:
                if waf:
                    wafs.add(str(waf))
            for tech in host.get("technologies", []) or []:
                category = str(tech.get("category", "")).lower()
                name = str(tech.get("name", ""))
                if "waf" in category:
                    wafs.add(name)
        return sorted(wafs)

    def _cve_evidence(self) -> list[dict]:
        evidence: list[dict] = []
        for item in self.all_results.get("cve_check", {}).get("cves", []) or []:
            evidence.append({
                "cve": item.get("cve", ""),
                "severity": item.get("severity", ""),
                "url": item.get("matched_url", ""),
                "exploit_available": item.get("exploit_available", False),
            })
        for item in self.all_results.get("cve_check", {}).get("technology_matches", []) or []:
            evidence.append({
                "component": item.get("component", ""),
                "version": item.get("version", ""),
                "urls": item.get("urls", [])[:5],
                "exploit_available": item.get("exploit_available", False),
            })
        return [item for item in evidence if any(item.values())]

    def _finding(self, rule_id: str, severity: str, title: str, description: str,
                 evidence: dict, confidence: float) -> dict:
        return {
            "source": self.name,
            "id": rule_id,
            "rule_id": rule_id,
            "type": "correlated_priority",
            "name": title,
            "title": title,
            "severity": severity,
            "url": self._primary_url(evidence),
            "matched_url": self._primary_url(evidence),
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
        }

    @staticmethod
    def _primary_url(evidence: dict) -> str:
        for key in (
            "admin_urls", "assets", "graphql", "takeover",
            "cors_findings", "auth_findings", "xss_urls",
        ):
            values = evidence.get(key, [])
            if not values:
                continue
            first = values[0]
            if isinstance(first, str):
                return first
            if isinstance(first, dict):
                return first.get("url") or first.get("endpoint") or ""
        for item in evidence.get("ports", []) or []:
            if isinstance(item, dict) and item.get("ip") and item.get("port"):
                return f"{item.get('ip')}:{item.get('port')}"
        for item in evidence.get("cve_context", []) or []:
            url = item.get("url", "") if isinstance(item, dict) else ""
            if url:
                return urlparse(url).geturl()
        return ""
