"""
ReconX - Module: cross-finding correlation rules.

The correlator consumes completed module outputs and emits manual-review
priorities when separate weak signals become stronger together.
"""

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
        matches: list[dict] = []
        for host in self.all_results.get("portscan", {}).get("hosts", []) or []:
            ip = str(host.get("ip", ""))
            for port in host.get("open_ports", []) or []:
                try:
                    port_num = int(port.get("port", 0))
                except (TypeError, ValueError):
                    continue
                if port_num in admin_port_set:
                    matches.append({
                        "ip": ip,
                        "port": port_num,
                        "service": port.get("service", ""),
                        "product": port.get("product", ""),
                    })
        return matches

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
        for key in ("admin_urls", "assets", "graphql"):
            values = evidence.get(key, [])
            if not values:
                continue
            first = values[0]
            if isinstance(first, str):
                return first
            if isinstance(first, dict):
                return first.get("url") or first.get("endpoint") or ""
        for item in evidence.get("cve_context", []) or []:
            url = item.get("url", "") if isinstance(item, dict) else ""
            if url:
                return urlparse(url).geturl()
        return ""
