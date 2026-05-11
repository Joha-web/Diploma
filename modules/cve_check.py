"""
ReconX — Module: CVE and ExploitDB correlation.

This module correlates discovered CVEs and technology versions with local
ExploitDB metadata through searchsploit. It does not execute public exploit code.
"""

import json
import re

from modules.base import BaseModule

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CVECheckModule(BaseModule):
    name = "cve_check"
    description = "CVE & ExploitDB Correlation"
    required_tools = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        live_hosts: list | None = None,
        tech_results: dict | None = None,
        vuln_results: dict | None = None,
        all_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.tech_results = tech_results or {}
        self.vuln_results = vuln_results or {}
        self.all_results = all_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("cve_check", {})
        if not cfg.get("enabled", True):
            return {"cves": [], "exploitdb_matches": [], "summary": {}, "status": "disabled"}

        cves = self._collect_cves_from_findings()
        components = self._collect_components()

        search_enabled = cfg.get("searchsploit", True) and self.has_tool("searchsploit")
        max_queries = int(cfg.get("max_queries", 40))
        exploitdb_by_term: dict[str, list[dict]] = {}

        if search_enabled:
            queries = self._build_search_queries(cves, components)[:max_queries]
            self.info(f"searchsploit correlation ({len(queries)} query/queries)")
            for term in queries:
                matches = self._searchsploit(term)
                if matches:
                    exploitdb_by_term[term] = matches
        elif cfg.get("searchsploit", True):
            self.warn("searchsploit not found — ExploitDB correlation skipped")

        cve_entries = []
        for cve_id, source in sorted(cves.items()):
            matches = exploitdb_by_term.get(cve_id, [])
            cve_entries.append({
                "cve": cve_id,
                "severity": source.get("severity", "UNKNOWN"),
                "name": source.get("name", ""),
                "matched_url": source.get("matched_url", ""),
                "template_id": source.get("template_id", ""),
                "references": source.get("references", []),
                "exploit_available": bool(matches),
                "exploitdb": matches[:5],
                "attack_simulation": self._dry_run_simulation(cve_id, bool(matches), source),
                "confidence": 0.9 if source.get("matched_url") else 0.75,
            })

        component_matches = []
        for component in components:
            term = component["query"]
            matches = exploitdb_by_term.get(term, [])
            if matches:
                component_matches.append({
                    **component,
                    "exploit_available": True,
                    "exploitdb": matches[:5],
                    "attack_simulation": self._dry_run_simulation(term, True, component),
                    "confidence": 0.55,
                })

        exploitdb_matches = []
        for term, matches in exploitdb_by_term.items():
            for match in matches[:5]:
                exploitdb_matches.append({"query": term, **match})

        summary = {
            "total_cves": len(cve_entries),
            "with_exploitdb": sum(1 for item in cve_entries if item["exploit_available"]),
            "technology_exploit_matches": len(component_matches),
            "searchsploit_available": search_enabled,
            "mode": "dry_run",
            "auto_exploit": False,
        }

        self.save_json(cve_entries, "cves.json")
        self.save_json(component_matches, "technology_exploit_matches.json")
        self.save_json(exploitdb_matches, "exploitdb_matches.json")

        if summary["with_exploitdb"] or summary["technology_exploit_matches"]:
            self.warn(
                f"ExploitDB matches: {summary['with_exploitdb']} CVE, "
                f"{summary['technology_exploit_matches']} technology"
            )
        else:
            self.success("No ExploitDB matches found")

        return {
            "cves": cve_entries,
            "technology_matches": component_matches,
            "exploitdb_matches": exploitdb_matches,
            "summary": summary,
        }

    def _collect_cves_from_findings(self) -> dict[str, dict]:
        found: dict[str, dict] = {}
        for finding in self.vuln_results.get("findings", []):
            text = json.dumps(finding, ensure_ascii=False, default=str)
            for cve in CVE_RE.findall(text):
                cve = cve.upper()
                found.setdefault(cve, {
                    "severity": finding.get("severity", "UNKNOWN"),
                    "name": finding.get("name", ""),
                    "matched_url": finding.get("matched_url", ""),
                    "template_id": finding.get("template_id", ""),
                    "references": finding.get("reference", []),
                })

        for scan in self.all_results.get("cmscan", {}).get("scans", []):
            for finding in scan.get("findings", []):
                text = json.dumps(finding, ensure_ascii=False, default=str)
                for cve in CVE_RE.findall(text):
                    cve = cve.upper()
                    found.setdefault(cve, {
                        "severity": finding.get("severity", "UNKNOWN"),
                        "name": finding.get("title") or finding.get("name", ""),
                        "matched_url": scan.get("url", ""),
                        "template_id": finding.get("type", ""),
                        "references": [],
                    })
        return found

    def _collect_components(self) -> list[dict]:
        components: dict[str, dict] = {}
        for host in self.tech_results.get("hosts", []):
            url = host.get("url", "")
            if url and not self.is_in_scope(url):
                continue
            for tech in host.get("technologies", []):
                name = str(tech.get("name", "")).strip()
                version = str(tech.get("version", "")).strip()
                if not name or not version:
                    continue
                if not re.search(r"\d", version):
                    continue
                query = f"{name} {version}".strip()
                entry = components.setdefault(query.lower(), {
                    "component": name,
                    "version": version,
                    "query": query,
                    "urls": [],
                })
                if url and url not in entry["urls"]:
                    entry["urls"].append(url)
        return list(components.values())

    @staticmethod
    def _build_search_queries(cves: dict[str, dict], components: list[dict]) -> list[str]:
        queries = list(sorted(cves))
        queries.extend(component["query"] for component in components)
        seen, result = set(), []
        for query in queries:
            key = query.lower()
            if key not in seen:
                seen.add(key)
                result.append(query)
        return result

    def _searchsploit(self, query: str) -> list[dict]:
        result = self.exec(["searchsploit", "--json", query], timeout=45)
        if result.returncode != 0 or not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        matches = []
        for item in data.get("RESULTS_EXPLOIT", [])[:10]:
            edb_id = str(item.get("EDB-ID", "")).strip()
            matches.append({
                "edb_id": edb_id,
                "title": item.get("Title", ""),
                "date": item.get("Date", ""),
                "type": item.get("Type", ""),
                "platform": item.get("Platform", ""),
                "path": item.get("Path", ""),
                "url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "",
            })
        return matches

    @staticmethod
    def _dry_run_simulation(identifier: str, exploit_available: bool, source: dict) -> dict:
        return {
            "mode": "dry_run",
            "attempted": False,
            "auto_exploit": False,
            "exploit_available": exploit_available,
            "identifier": identifier,
            "target": source.get("matched_url") or ", ".join(source.get("urls", [])[:3]),
            "safe_by_default": True,
            "blocked_reason": (
                "ReconX correlates public exploit availability but does not execute "
                "exploit code automatically. Validate manually in the authorized scope "
                "or in a lab replica."
            ),
            "recommended_validation": [
                "Confirm the affected product and exact version.",
                "Re-run safe scanner templates that produced the finding.",
                "Collect request/response evidence before any intrusive validation.",
            ],
        }
