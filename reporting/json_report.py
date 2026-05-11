"""
SIEM-friendly JSON report export for ReconX.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


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

    report = {
        "schema_version": "reconx/v2",
        "scan_target": target,
        "scan_date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "duration": elapsed,
        "summary": _summary(results),
        "findings": findings,
        "assets": _assets(results),
        "raw_module_status": {
            name: data.get("status", "unknown")
            for name, data in results.items()
            if isinstance(data, dict)
        },
    }

    path = session_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return str(path)


def _summary(results: dict) -> dict:
    recon = results.get("recon", {})
    ports = results.get("portscan", {}).get("summary", {})
    tech = results.get("techstack", {})
    fuzz = results.get("fuzzer", {})
    vuln = results.get("vulnscan", {})
    cve = results.get("cve_check", {})
    return {
        "subdomains": recon.get("subdomains_total", 0),
        "live_hosts": len(recon.get("live_http", [])),
        "resolved_ips": len(recon.get("resolved_ips", [])),
        "open_ports": ports.get("total_open_ports", 0),
        "technologies": len(tech.get("technologies_summary", {})),
        "endpoints": fuzz.get("total_endpoints", 0),
        "vulnerabilities": vuln.get("total", 0),
        "cves": cve.get("summary", {}).get("total_cves", 0),
        "exploitdb_matches": cve.get("summary", {}).get("with_exploitdb", 0),
        "js_secrets": fuzz.get("js_secrets_count", 0),
    }


def _assets(results: dict) -> dict:
    recon = results.get("recon", {})
    web = results.get("webdetect", {})
    return {
        "subdomains": recon.get("subdomains", []),
        "resolved_ips": recon.get("resolved_ips", []),
        "live_urls": web.get("live_urls") or recon.get("live_http", []),
        "ports_by_host": results.get("portscan", {}).get("hosts", []),
        "technologies": results.get("techstack", {}).get("hosts", []),
    }
