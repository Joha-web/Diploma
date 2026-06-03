"""
ReconX — Module: CVE and ExploitDB correlation.

This module correlates discovered CVEs and technology versions with local
ExploitDB metadata through searchsploit. It does not execute public exploit code.
"""

import json
import re

from modules.base import BaseModule

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# WhatWeb / fingerprint plugins that report page metadata or HTTP headers rather
# than a software product. Feeding these to searchsploit yields substring
# nonsense — e.g. WhatWeb's "Title" plugin (the page <title>) substring-matched
# "enTITLEment" in EDB-42145 (an Apple macOS/iOS local kernel exploit).
NON_PRODUCT_TECH = frozenset({
    "title", "country", "ip", "email", "script", "frame", "html5",
    "metagenerator", "redirectlocation", "cookies", "cookie", "httponly",
    "uncommonheaders", "x-ua-compatible", "x-powered-by", "poweredby",
    "passwordfield", "meta-author", "meta-keywords", "open-graph-protocol",
    "schema.org", "allow", "via", "etag", "object",
})
# Response-header names some fingerprinters surface as "technologies".
HEADER_NAME_RE = re.compile(
    r"^(x-|access-control-|content-|sec-|strict-transport|www-authenticate|"
    r"set-cookie|referrer-policy|permissions-policy|cross-origin-)", re.I,
)
# Exploit-DB categories irrelevant to a remote external web-app correlation.
NOISE_EXPLOIT_TYPES = frozenset({"shellcode", "papers"})


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

        # Component → exploit correlation. searchsploit matches case-insensitive
        # substrings, so raw results are full of false positives (a "PHP 7.2.14"
        # query returns unrelated php-platform web apps; "Title" matches
        # "enTITLEment"). Keep only exploits whose title actually names the
        # product, and drop exploit classes irrelevant to remote web targets.
        component_matches = []
        relevant_by_term: dict[str, list[dict]] = {}
        for component in components:
            term = component["query"]
            relevant = self._relevant_matches(
                component["component"], exploitdb_by_term.get(term, [])
            )
            if relevant:
                relevant_by_term[term] = relevant
                component_matches.append({
                    **component,
                    "exploit_available": True,
                    "exploitdb": relevant[:5],
                    "attack_simulation": self._dry_run_simulation(term, True, component),
                    "confidence": 0.55,
                    "relevance": "product_name_in_exploit_title",
                })

        exploitdb_matches = []
        # CVE-derived matches are reliable — searchsploit indexes CVE ids directly.
        for cve_id in cves:
            for match in exploitdb_by_term.get(cve_id, [])[:5]:
                exploitdb_matches.append({"query": cve_id, **match})
        for term, matches in relevant_by_term.items():
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
                if not self._is_product_component(name):
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
    def _is_product_component(name: str) -> bool:
        """Reject fingerprint plugins that report metadata/headers, not products."""
        key = name.strip().lower()
        if key in NON_PRODUCT_TECH:
            return False
        if HEADER_NAME_RE.match(key):
            return False
        return True

    @staticmethod
    def _name_tokens(name: str) -> list[str]:
        """Distinctive alphabetic tokens of a product name (drops versions/short bits)."""
        return [t for t in re.split(r"[^A-Za-z0-9]+", name.lower())
                if len(t) >= 3 and not t.isdigit()]

    @staticmethod
    def _exploit_product_segment(title: str) -> str:
        """The product[+version] segment of an Exploit-DB title.

        EDB titles follow the convention ``Product Version - Description``, so the
        affected product lives before the first ` - `. Restricting matching to
        this head segment stops the product name being matched inside a
        description (e.g. "cPanel < 11.25 - ... (Add User PHP Script)" must not
        count as a PHP-runtime exploit).
        """
        return title.split(" - ", 1)[0] if " - " in title else title

    def _relevant_matches(self, component_name: str, matches: list[dict]) -> list[dict]:
        """Keep only exploits whose *product segment* names the component.

        This is the false-positive killer. searchsploit substring-matches, so
        "Title" hits "enTITLEment" and "PHP 7.2.14" returns unrelated php-platform
        web apps. Requiring a product-name token as a whole word in the title's
        head segment removes those collisions while keeping genuine product
        exploits (titled e.g. "PHP 7.x - RCE").
        """
        tokens = self._name_tokens(component_name)
        if not tokens:
            return []  # nothing distinctive to confirm against → treat as noise
        relevant: list[dict] = []
        for match in matches:
            if str(match.get("type", "")).lower() in NOISE_EXPLOIT_TYPES:
                continue
            head = self._exploit_product_segment(str(match.get("title", "")))
            head_tokens = set(re.split(r"[^a-z0-9]+", head.lower()))
            if any(tok in head_tokens for tok in tokens):
                relevant.append(match)
        return relevant

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
