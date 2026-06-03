"""
SIEM-friendly JSON report export for ReconX.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from modules.finding_registry import normalize_finding as normalize_registered_finding
from modules.finding_registry import risk_score


ACTIVE_FINDING_MODULES = (
    "secret_scanner", "fuzzer", "cors_checker", "auth_probe",
    "injection_probe", "xss", "sql_injection", "http_smuggling", "oauth_probe",
    "host_header_injection", "prototype_pollution", "xxe_probe",
    "deserialization_probe", "race_condition",
    "open_redirect_probe", "api_key_validator", "idor_probe", "ssrf_probe",
    "file_inclusion", "command_injection",
    "jwt_audit", "websocket_probe", "api_schema_audit", "js_security_audit",
    "sourcemap_analyzer", "endpoint_harvester", "error_analyzer",
    "takeover_checker", "correlator",
)


def generate_json_report(session_dir: Path, target: str, results: dict, elapsed: str = "") -> str:
    """Generate a structured JSON report and return the written path."""
    session_dir = Path(session_dir)
    findings = []

    for finding in results.get("vulnscan", {}).get("findings", []):
        findings.append({
            "source": "nuclei",
            "id": finding.get("template_id", ""),
            "title": finding.get("name", ""),
            "severity": finding.get("severity", "INFO"),
            "url": finding.get("matched_url", ""),
            "description": finding.get("description", ""),
            "evidence": {
                "curl": finding.get("curl_command", ""),
                "extracted": finding.get("extracted", []),
            },
            "references": finding.get("reference", []),
            "tags": finding.get("tags", []),
            "confidence": finding.get("confidence", 0.8),
        })

    for scan in results.get("cmscan", {}).get("scans", []):
        for finding in scan.get("findings", []):
            findings.append({
                "source": scan.get("tool", "cmscan"),
                "id": finding.get("type", ""),
                "title": finding.get("title") or finding.get("name", ""),
                "severity": finding.get("severity", "INFO"),
                "url": scan.get("url", ""),
                "description": finding.get("detail", ""),
                "evidence": {"cms": scan.get("cms", "")},
                "references": finding.get("cve", []),
                "tags": [scan.get("cms", ""), "cms"],
                "confidence": 0.75,
            })

    for cve in results.get("cve_check", {}).get("cves", []):
        findings.append({
            "source": "cve_check",
            "id": cve.get("cve", ""),
            "title": cve.get("name", "") or cve.get("cve", ""),
            "severity": cve.get("severity", "UNKNOWN"),
            "url": cve.get("matched_url", ""),
            "description": "CVE correlated with ExploitDB metadata",
            "evidence": {
                "exploit_available": cve.get("exploit_available", False),
                "exploitdb": cve.get("exploitdb", []),
                "attack_simulation": cve.get("attack_simulation", {}),
            },
            "references": cve.get("references", []),
            "tags": ["cve", "exploitdb"],
            "confidence": cve.get("confidence", 0.75),
        })

    for module_name in ACTIVE_FINDING_MODULES:
        for finding in results.get(module_name, {}).get("findings", []):
            findings.append(_normalize_finding(module_name, finding))

    for finding in results.get("recon", {}).get("email_security", {}).get("findings", []):
        findings.append(_normalize_finding("recon", finding))

    findings = [_ensure_risk(item) for item in findings]
    findings.sort(key=lambda item: item.get("risk_score", 0), reverse=True)

    report = {
        "schema_version": "reconx/v2",
        "scan_target": target,
        "scan_date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "duration": elapsed,
        "summary": _summary(results),
        "findings": findings,
        "assets": _assets(results),
        "diff": results.get("diff", {}),
        "raw_module_status": {
            name: data.get("status", "unknown")
            for name, data in results.items()
            if isinstance(data, dict)
        },
    }

    path = session_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return str(path)


def _normalize_finding(module_name: str, finding: dict) -> dict:
    return normalize_registered_finding(module_name, finding)


def _ensure_risk(finding: dict) -> dict:
    if "risk_score" not in finding:
        finding["risk_score"] = risk_score(
            finding.get("severity", "INFO"),
            finding.get("confidence", 0.75),
            finding.get("exploitability", "candidate"),
        )
    return finding


def _summary(results: dict) -> dict:
    recon = results.get("recon", {})
    web = results.get("webdetect", {})
    ports = results.get("portscan", {}).get("summary", {})
    tech = results.get("techstack", {})
    fuzz = results.get("fuzzer", {})
    vuln = results.get("vulnscan", {})
    cve = results.get("cve_check", {})
    cors = results.get("cors_checker", {})
    auth = results.get("auth_probe", {})
    secret = results.get("secret_scanner", {})
    injection = results.get("injection_probe", {})
    active_probe_modules = (
        "injection_probe", "xss", "sql_injection", "http_smuggling", "oauth_probe",
        "host_header_injection", "prototype_pollution", "xxe_probe",
        "deserialization_probe", "race_condition",
        "open_redirect_probe", "api_key_validator", "idor_probe", "ssrf_probe",
        "file_inclusion", "command_injection",
        "jwt_audit", "websocket_probe", "api_schema_audit", "js_security_audit",
    )
    active_probe_findings = sum(
        results.get(module_name, {}).get("total", len(results.get(module_name, {}).get("findings", [])))
        for module_name in active_probe_modules
    )
    sourcemaps = results.get("sourcemap_analyzer", {})
    takeover = results.get("takeover_checker", {})
    openapi = results.get("openapi_parser", {})
    params = results.get("parameter_discovery", {})
    vhosts = results.get("vhost_enum", {})
    corr = results.get("correlator", {})
    return {
        "subdomains": recon.get("subdomains_total", 0),
        "live_hosts": len(web.get("live_urls") or recon.get("live_http", [])),
        "resolved_ips": len(recon.get("resolved_ips", [])),
        "open_ports": ports.get("total_open_ports", 0),
        "technologies": len(tech.get("technologies_summary", {})),
        "endpoints": fuzz.get("total_endpoints", 0),
        "vulnerabilities": vuln.get("total", 0),
        "cves": cve.get("summary", {}).get("total_cves", 0),
        "exploitdb_matches": cve.get("summary", {}).get("with_exploitdb", 0),
        "js_secrets": fuzz.get("js_secrets_count", 0),
        "cors_findings": cors.get("total", len(cors.get("findings", []))),
        "auth_findings": auth.get("total", len(auth.get("findings", []))),
        "secret_findings": secret.get("total", len(secret.get("findings", []))),
        "injection_findings": injection.get("total", len(injection.get("findings", []))),
        "active_probe_findings": active_probe_findings,
        "sourcemap_findings": sourcemaps.get("total", len(sourcemaps.get("findings", []))),
        "takeover_findings": takeover.get("total", len(takeover.get("findings", []))),
        "openapi_specs": openapi.get("total_specs", 0),
        "parameters": params.get("total", 0),
        "vhosts": vhosts.get("total", 0),
        "correlated_findings": corr.get("total", 0),
    }


def _assets(results: dict) -> dict:
    recon = results.get("recon", {})
    web = results.get("webdetect", {})
    return {
        "subdomains": recon.get("subdomains", []),
        "resolved_ips": recon.get("resolved_ips", []),
        "scan_ips": recon.get("scan_ips", recon.get("resolved_ips", [])),
        "live_urls": web.get("live_urls") or recon.get("live_http", []),
        "ports_by_host": results.get("portscan", {}).get("hosts", []),
        "technologies": results.get("techstack", {}).get("hosts", []),
        "vhosts": results.get("vhost_enum", {}).get("found", []),
        "openapi_endpoints": results.get("openapi_parser", {}).get("endpoints", []),
        "parameters": results.get("parameter_discovery", {}).get("parameters", []),
        "sourcemaps": results.get("sourcemap_analyzer", {}).get("maps", []),
        "cloud_assets": results.get("fuzzer", {}).get("cloud_assets", []),
        "graphql": results.get("fuzzer", {}).get("graphql_details", []),
        "shodan_hosts": recon.get("shodan_hosts", []),
        "harvested_endpoints": results.get("endpoint_harvester", {}).get("all_endpoints", []),
        "harvested_parameters": results.get("endpoint_harvester", {}).get("parameters", []),
        "screenshots": web.get("screenshots", []),
    }


def build_results_diff(previous: dict, current: dict) -> dict:
    """Return a compact diff between two all_results-like dictionaries.

    Includes asset-score deltas when both snapshots ran the asset_risk module,
    so the report can call out which hosts got more or less exposed.
    """
    prev_subs = set(previous.get("recon", {}).get("subdomains", []))
    curr_subs = set(current.get("recon", {}).get("subdomains", []))
    prev_live = set(previous.get("webdetect", {}).get("live_urls", []))
    curr_live = set(current.get("webdetect", {}).get("live_urls", []))
    prev_ports = _port_set(previous)
    curr_ports = _port_set(current)
    prev_findings = _finding_set(previous)
    curr_findings = _finding_set(current)
    asset_deltas = _asset_score_deltas(previous, current)
    return {
        "new_subdomains": sorted(curr_subs - prev_subs),
        "removed_subdomains": sorted(prev_subs - curr_subs),
        "new_live_urls": sorted(curr_live - prev_live),
        "removed_live_urls": sorted(prev_live - curr_live),
        "new_open_ports": sorted(curr_ports - prev_ports),
        "closed_ports": sorted(prev_ports - curr_ports),
        "new_findings": sorted(curr_findings - prev_findings),
        "resolved_findings": sorted(prev_findings - curr_findings),
        "asset_score_deltas": asset_deltas,
        "summary": {
            "new_subdomains": len(curr_subs - prev_subs),
            "removed_subdomains": len(prev_subs - curr_subs),
            "new_findings": len(curr_findings - prev_findings),
            "resolved_findings": len(prev_findings - curr_findings),
            "new_open_ports": len(curr_ports - prev_ports),
            "closed_ports": len(prev_ports - curr_ports),
            "assets_score_up": sum(1 for a in asset_deltas if a["delta"] > 0),
            "assets_score_down": sum(1 for a in asset_deltas if a["delta"] < 0),
        },
    }


def _asset_score_deltas(previous: dict, current: dict) -> list[dict]:
    """Per-asset score delta sorted by absolute change. Limited to top 50."""
    prev_scores = {
        a.get("asset", ""): int(a.get("score", 0))
        for a in (previous.get("asset_risk", {}) or {}).get("ranked_assets", []) or []
    }
    curr_scores = {
        a.get("asset", ""): int(a.get("score", 0))
        for a in (current.get("asset_risk", {}) or {}).get("ranked_assets", []) or []
    }
    deltas: list[dict] = []
    for asset in set(prev_scores) | set(curr_scores):
        before = prev_scores.get(asset, 0)
        after = curr_scores.get(asset, 0)
        if before == after:
            continue
        deltas.append({
            "asset": asset,
            "before": before,
            "after": after,
            "delta": after - before,
        })
    deltas.sort(key=lambda d: abs(d["delta"]), reverse=True)
    return deltas[:50]


def _port_set(results: dict) -> set[str]:
    ports = set()
    for host in results.get("portscan", {}).get("hosts", []):
        ip = host.get("ip", "")
        for port in host.get("open_ports", []):
            ports.add(f"{ip}:{port.get('port')}")
    return ports


def _finding_set(results: dict) -> set[str]:
    items = set()
    for module_name in ("vulnscan", *ACTIVE_FINDING_MODULES):
        for finding in results.get(module_name, {}).get("findings", []):
            key = (
                finding.get("template_id")
                or finding.get("id")
                or finding.get("type")
                or finding.get("name", "")
            )
            url = finding.get("matched_url") or finding.get("url", "")
            items.add(f"{module_name}:{key}:{url}")
    for finding in results.get("recon", {}).get("email_security", {}).get("findings", []):
        key = finding.get("id") or finding.get("type") or finding.get("name", "")
        items.add(f"recon:{key}:")
    return items
