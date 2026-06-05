#!/usr/bin/env python3
"""
ReconX — Automated Web Application Reconnaissance Framework
Usage:
    python3 main.py -t example.com
    python3 main.py -t example.com --modules recon,portscan,vulnscan
    python3 main.py -t example.com --skip cmscan --resume
"""

import argparse
import copy
import json
import os
import re
import sys
import threading
import time
import importlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from modules.base import install_ctrl_c_skip_handler

console = Console()

BANNER = r"""
[bold magenta]
    ____                       _  __
   / __ \___  _________  ____  | |/ /
  / /_/ / _ \/ ___/ __ \/ __ \ |   /
 / _, _/  __/ /__/ /_/ / / / //   |
/_/ |_|\___/\___/\____/_/ /_//_/|_|
                              v2.0.0
[/bold magenta][dim]Red Team · AppSec · Reconnaissance Framework[/dim]
"""

# Pipeline — parallel_group determines execution order.
# Modules in the same group run in parallel threads.
PIPELINE: list[dict] = [
    {"name": "recon",       "group": 1},
    {"name": "secret_scanner", "group": 1},
    {"name": "portscan",    "group": 2},   # parallel with webdetect
    {"name": "webdetect",   "group": 2},   # parallel with portscan
    {"name": "techstack",   "group": 3},
    {"name": "spa_crawler", "group": 3},   # headless-browser SPA crawl, parallel with techstack
    {"name": "fuzzer",      "group": 4},   # parallel with ssl/auth/cors
    {"name": "ssl_checker", "group": 4},
    {"name": "cors_checker","group": 4},
    {"name": "auth_probe",  "group": 4},
    {"name": "cmscan",      "group": 5},
    {"name": "endpoint_harvester", "group": 5},
    {"name": "sourcemap_analyzer", "group": 5},
    {"name": "vhost_enum",  "group": 5},
    {"name": "takeover_checker", "group": 5},
    {"name": "openapi_parser", "group": 5},
    # group 6: discovery (needed before injection probes)
    {"name": "parameter_discovery", "group": 6},
    # group 7: low-traffic probes (mostly static / offline analysis)
    {"name": "http_smuggling",  "group": 7},
    {"name": "jwt_audit",       "group": 7},
    {"name": "websocket_probe", "group": 7},
    {"name": "api_schema_audit","group": 7},
    {"name": "js_security_audit","group": 7},
    # group 8: medium-traffic active probes
    {"name": "oauth_probe",            "group": 8},
    {"name": "host_header_injection",  "group": 8},
    {"name": "open_redirect_probe",    "group": 8},
    {"name": "prototype_pollution",    "group": 8},
    {"name": "deserialization_probe",  "group": 8},
    {"name": "race_condition",         "group": 8},
    # group 9: remaining validators
    {"name": "api_key_validator", "group": 9},
    {"name": "xxe_probe",         "group": 9},
    # group 10: heavy injection testing (xss + sqli + idor + injection_probe)
    {"name": "injection_probe", "group": 10},
    {"name": "xss",             "group": 10},
    {"name": "sql_injection",   "group": 10},
    {"name": "idor_probe",      "group": 10},
    # group 11: nuclei + SSRFmap — separate from sqlmap timing in group 10
    {"name": "vulnscan",    "group": 11},
    {"name": "ssrf_probe",  "group": 11},
    {"name": "file_inclusion", "group": 11},
    {"name": "command_injection", "group": 11},
    {"name": "cve_check",   "group": 12},
    {"name": "error_analyzer", "group": 12},
    {"name": "correlator",  "group": 13},
    # group 14: reasoning pass over all findings (after correlator, before
    # asset_risk/ai_report so their output reflects triaged verdicts)
    {"name": "fp_triage",   "group": 14},
    {"name": "asset_risk",  "group": 15},
    {"name": "ai_report",   "group": 16},
]

CLASS_MAP = {
    "recon":       ("modules.recon",        "ReconModule"),
    "secret_scanner": ("modules.secret_scanner", "SecretScannerModule"),
    "portscan":    ("modules.portscan",     "PortScanModule"),
    "webdetect":   ("modules.webdetect",    "WebdetectModule"),
    "techstack":   ("modules.techstack",    "TechStackModule"),
    "spa_crawler": ("modules.spa_crawler",  "SPACrawlerModule"),
    "fuzzer":      ("modules.fuzzer",       "FuzzerModule"),
    "ssl_checker": ("modules.ssl_checker",  "SSLCheckerModule"),
    "cors_checker":("modules.cors_checker", "CORSCheckerModule"),
    "auth_probe":  ("modules.auth_probe",   "AuthProbeModule"),
    "cmscan":      ("modules.cmscan",       "CMSScanModule"),
    "endpoint_harvester": ("modules.endpoint_harvester", "EndpointHarvesterModule"),
    "sourcemap_analyzer": ("modules.sourcemap_analyzer", "SourceMapAnalyzerModule"),
    "vhost_enum":  ("modules.vhost_enum",   "VHostEnumModule"),
    "takeover_checker": ("modules.takeover_checker", "TakeoverCheckerModule"),
    "openapi_parser": ("modules.openapi_parser", "OpenAPIParserModule"),
    "parameter_discovery": ("modules.parameter_discovery", "ParameterDiscoveryModule"),
    "injection_probe": ("modules.injection_probe", "InjectionProbeModule"),
    "http_smuggling": ("modules.http_smuggling", "HTTPSmugglingModule"),
    "oauth_probe": ("modules.oauth_probe", "OAuthProbeModule"),
    "host_header_injection": ("modules.host_header_injection", "HostHeaderInjectionModule"),
    "prototype_pollution": ("modules.prototype_pollution", "PrototypePollutionModule"),
    "xxe_probe": ("modules.xxe_probe", "XXEProbeModule"),
    "deserialization_probe": ("modules.deserialization_probe", "DeserializationProbeModule"),
    "race_condition": ("modules.race_condition", "RaceConditionModule"),
    "open_redirect_probe": ("modules.open_redirect_probe", "OpenRedirectProbeModule"),
    "api_key_validator": ("modules.api_key_validator", "APIKeyValidatorModule"),
    "idor_probe": ("modules.idor_probe", "IDORProbeModule"),
    "ssrf_probe": ("modules.ssrf_probe", "SSRFProbeModule"),
    "file_inclusion": ("modules.file_inclusion", "FileInclusionModule"),
    "command_injection": ("modules.command_injection", "CommandInjectionModule"),
    "jwt_audit": ("modules.jwt_audit", "JWTAuditModule"),
    "websocket_probe": ("modules.websocket_probe", "WebSocketProbeModule"),
    "api_schema_audit": ("modules.api_schema_audit", "APISchemaAuditModule"),
    "js_security_audit": ("modules.js_security_audit", "JSSecurityAuditModule"),
    "xss": ("modules.xss", "XSSModule"),
    "sql_injection": ("modules.sql_injection", "SQLInjectionModule"),
    "vulnscan":    ("modules.vulnscan",     "VulnScanModule"),
    "cve_check":   ("modules.cve_check",    "CVECheckModule"),
    "error_analyzer": ("modules.error_analyzer", "ErrorAnalyzerModule"),
    "correlator":  ("modules.correlator",   "CorrelatorModule"),
    "fp_triage":   ("modules.fp_triage",    "FPTriageModule"),
    "asset_risk":  ("modules.asset_risk",   "AssetRiskModule"),
    "ai_report":   ("modules.ai_report",    "AIReportModule"),
}

# Module display names for Telegram and console
MODULE_LABELS = {
    "recon":       "DNS & Subdomain Enumeration",
    "secret_scanner": "Git Secret Scanning",
    "portscan":    "Port Scanning",
    "webdetect":   "Web Application Detection",
    "techstack":   "Technology Fingerprinting",
    "spa_crawler": "Headless-browser SPA Crawl",
    "fuzzer":      "Crawling & Fuzzing",
    "ssl_checker": "SSL/TLS & Headers Analysis",
    "cors_checker":"CORS Misconfiguration Scanner",
    "auth_probe":  "JWT & Cookie Security Checks",
    "cmscan":      "CMS Vulnerability Scanning",
    "endpoint_harvester": "Endpoint Harvesting",
    "sourcemap_analyzer": "JavaScript Source Map Analysis",
    "vhost_enum":  "Virtual Host Enumeration",
    "takeover_checker": "Subdomain Takeover Checks",
    "openapi_parser": "OpenAPI Discovery",
    "parameter_discovery": "Hidden Parameter Discovery",
    "injection_probe": "SSRF / SSTI / XXE Detection",
    "http_smuggling": "HTTP Request Smuggling",
    "oauth_probe": "OAuth / OIDC Audit",
    "host_header_injection": "Host Header Injection",
    "prototype_pollution": "Server-Side Prototype Pollution",
    "xxe_probe": "OOB XXE Detection",
    "deserialization_probe": "Deserialization Indicators",
    "race_condition": "Race Condition Candidates",
    "open_redirect_probe": "Open Redirect Detection",
    "api_key_validator": "API Key Leak Validation",
    "idor_probe": "IDOR / BOLA Candidate Analysis",
    "ssrf_probe": "SSRF Scoring & SSRFmap",
    "file_inclusion": "LFI / RFI Fuzzing (ffuf)",
    "command_injection": "Command Injection (commix + ffuf)",
    "jwt_audit": "Deep JWT Security Audit",
    "websocket_probe": "WebSocket Security Checks",
    "api_schema_audit": "OpenAPI Security Schema Audit",
    "js_security_audit": "Static JavaScript Security Audit",
    "xss": "Cross-Site Scripting Testing",
    "sql_injection": "SQL Injection Testing (sqlmap)",
    "vulnscan":    "Vulnerability Scanning (Nuclei)",
    "cve_check":   "CVE & ExploitDB Correlation",
    "error_analyzer": "Server-Side Error Surface",
    "correlator":  "Cross-Finding Correlation",
    "fp_triage":   "AI False-Positive Triage",
    "asset_risk":  "Per-Asset Risk Ranking",
    "ai_report":   "AI Security Analysis",
}

ACTIVE_PROBE_MODULES = (
    "injection_probe", "http_smuggling", "oauth_probe",
    "host_header_injection", "prototype_pollution", "xxe_probe",
    "deserialization_probe", "race_condition",
    "open_redirect_probe", "api_key_validator", "idor_probe",
    "jwt_audit", "websocket_probe", "api_schema_audit", "js_security_audit",
    "xss", "sql_injection", "ssrf_probe", "error_analyzer", "file_inclusion",
    "command_injection",
)

CONFIG_PRESETS = {
    "safe": {
        "scan": {
            "allow_write": False,
            "rate_limit": 25,
            "global_rate_limit": 25,
            "idor_probe": {"compare_profiles": False, "check_anonymous": False, "max_candidates": 120},
            "jwt_audit": {"collect_from_responses": False, "max_tokens": 50},
            "websocket_probe": {"active_handshake": True, "message_probe": False, "max_endpoints": 30},
            "api_schema_audit": {"max_endpoints": 300},
            "js_security_audit": {"max_js": 80},
            "xss": {"max_targets": 40, "max_requests": 120, "max_payloads": 2, "use_dalfox": False},
            "race_condition": {"active_probe": False},
            "api_key_validator": {"live_validation": False},
        },
    },
    "bug_bounty": {
        "scan": {
            "allow_write": False,
            "rate_limit": 50,
            "global_rate_limit": 50,
            "idor_probe": {"compare_profiles": True, "check_anonymous": False, "max_candidates": 200},
            "jwt_audit": {"collect_from_responses": False, "max_tokens": 100},
            "websocket_probe": {"active_handshake": True, "check_origin": True, "message_probe": False},
            "api_schema_audit": {"max_endpoints": 500},
            "js_security_audit": {"max_js": 150},
            "xss": {"max_targets": 120, "max_requests": 300, "max_payloads": 4, "use_dalfox": True},
            "race_condition": {"active_probe": False},
            "api_key_validator": {"live_validation": False},
            "endpoint_harvester": {"cariddi_intensive": True},
        },
    },
    "deep": {
        "scan": {
            "allow_write": False,
            "rate_limit": 35,
            "global_rate_limit": 35,
            "idor_probe": {"compare_profiles": True, "check_anonymous": True, "max_candidates": 400, "enumerate_ids": True},
            "jwt_audit": {"collect_from_responses": True, "max_tokens": 200, "max_response_urls": 100},
            "websocket_probe": {"active_handshake": True, "check_origin": True, "max_endpoints": 100},
            "api_schema_audit": {"max_endpoints": 1000},
            "js_security_audit": {"max_js": 300},
            "xss": {"max_targets": 250, "max_requests": 700, "max_payloads": 5, "use_dalfox": True},
            "race_condition": {"active_probe": False},
            "endpoint_harvester": {"cariddi_intensive": True, "kiterunner": True, "max_seeds": 400},
            # Deeper sqlmap: higher level/risk catches blind SQLi the level-1
            # default misses, and a lower strong_threshold sends more ranked
            # candidates to sqlmap.
            "sql_injection": {"level": 3, "risk": 2, "max_targets": 15,
                              "strong_threshold": 0.4, "technique": "BEUST"},
        },
    },
    "intrusive": {
        "scan": {
            "allow_write": True,
            "rate_limit": 20,
            "global_rate_limit": 20,
            "idor_probe": {"compare_profiles": True, "check_anonymous": True, "max_candidates": 500, "enumerate_ids": True},
            "websocket_probe": {"active_handshake": True, "check_origin": True, "message_probe": True},
            "xss": {"max_targets": 300, "max_requests": 900, "max_payloads": 5, "use_dalfox": True},
            "race_condition": {"active_probe": True},
            "api_key_validator": {"live_validation": True},
            # Maximum sqlmap depth: full level/risk, all techniques (incl. stacked
            # queries), form testing, and the widest candidate net.
            "sql_injection": {"level": 5, "risk": 3, "max_targets": 25,
                              "strong_threshold": 0.35, "technique": "BEUSTQ", "forms": True},
            "endpoint_harvester": {"cariddi_intensive": True, "kiterunner": True,
                                   "kiterunner_intensive": True, "max_seeds": 600,
                                   "retain_raw_secrets": True},
            "fuzzing": {"retain_raw_secrets": True},
            "secret_scanner": {"retain_raw_secrets": True},
            "sourcemap_analyzer": {"retain_raw_secrets": True},
        },
    },
}


def _load_cls(name: str):
    mod_path, cls_name = CLASS_MAP[name]
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def _select_active_modules(modules_arg: str | None, skip_arg: str | None) -> list[str]:
    all_names = [s["name"] for s in PIPELINE]

    if modules_arg:
        requested = [m.strip() for m in modules_arg.split(",") if m.strip()]
    else:
        requested = list(all_names)

    unknown = [name for name in requested if name not in all_names]
    if unknown:
        raise ValueError(f"Unknown module(s): {', '.join(unknown)}")

    active = [m for m in requested if m in all_names]
    if skip_arg:
        skip = {m.strip() for m in skip_arg.split(",") if m.strip()}
        unknown_skip = sorted(name for name in skip if name not in all_names)
        if unknown_skip:
            raise ValueError(f"Unknown module(s) in --skip: {', '.join(unknown_skip)}")
        active = [m for m in active if m not in skip]

    if not active:
        raise ValueError("No modules selected after applying --modules/--skip")

    return active


def _live_urls(all_results: dict) -> list[str]:
    """Return the best live URL list discovered so far."""
    web = all_results.get("webdetect", {})
    urls = web.get("live_urls") or []
    if urls:
        return urls

    web_hosts = web.get("live_hosts") or []
    urls = [
        item.get("url", "")
        for item in web_hosts
        if isinstance(item, dict) and item.get("url")
    ]
    if urls:
        return urls

    return all_results.get("recon", {}).get("live_http", [])


def _build_kwargs(name: str, all_results: dict) -> dict:
    """Build extra constructor kwargs for each module based on prior results."""
    recon  = all_results.get("recon", {})
    live   = _live_urls(all_results)
    kwargs: dict = {}
    if name == "portscan":
        kwargs["resolved_ips"] = recon.get("scan_ips") or recon.get("resolved_ips", [])
    elif name in ("webdetect", "techstack", "spa_crawler", "fuzzer", "ssl_checker",
                  "cors_checker", "auth_probe", "openapi_parser",
                  "http_smuggling", "oauth_probe"):
        kwargs["live_hosts"] = live
    elif name == "cmscan":
        kwargs["tech_results"] = all_results.get("techstack", {})
    elif name == "endpoint_harvester":
        kwargs["live_hosts"] = live
        kwargs["recon_results"] = recon
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "sourcemap_analyzer":
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "vhost_enum":
        kwargs["live_hosts"] = live
        kwargs["resolved_ips"] = recon.get("scan_ips") or recon.get("resolved_ips", [])
    elif name == "takeover_checker":
        kwargs["recon_results"] = recon
    elif name == "parameter_discovery":
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
        kwargs["endpoint_results"] = all_results.get("endpoint_harvester", {})
    elif name == "injection_probe":
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "sql_injection":
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "xss":
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "host_header_injection":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name in ("prototype_pollution", "xxe_probe"):
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
    elif name == "deserialization_probe":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "race_condition":
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
    elif name == "open_redirect_probe":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "api_key_validator":
        kwargs["secret_results"] = all_results.get("secret_scanner", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "idor_probe":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
    elif name == "jwt_audit":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["auth_results"] = all_results.get("auth_probe", {})
    elif name == "websocket_probe":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "api_schema_audit":
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
    elif name == "js_security_audit":
        kwargs["live_hosts"] = live
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "ssrf_probe":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
        kwargs["injection_results"] = all_results.get("injection_probe", {})
    elif name == "error_analyzer":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "file_inclusion":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "command_injection":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["fuzzer_results"] = all_results.get("fuzzer", {})
    elif name == "vulnscan":
        kwargs["live_hosts"] = live
        kwargs["parameter_results"] = all_results.get("parameter_discovery", {})
        kwargs["openapi_results"] = all_results.get("openapi_parser", {})
        kwargs["tech_results"] = all_results.get("techstack", {})
    elif name == "cve_check":
        kwargs["live_hosts"] = live
        kwargs["tech_results"] = all_results.get("techstack", {})
        kwargs["vuln_results"] = all_results.get("vulnscan", {})
        kwargs["all_results"] = all_results
    elif name in ("correlator", "fp_triage", "asset_risk", "ai_report"):
        kwargs["all_results"] = all_results
    return kwargs


def _module_summary(name: str, result: dict) -> str:
    """Build a one-line summary for a completed module."""
    status = result.get("status", "?")
    if status != "completed":
        return status

    if name == "recon":
        parts = [
            f"{result.get('subdomains_total', 0)} subs",
            f"{len(result.get('live_http', []))} live",
            f"{len(result.get('resolved_ips', []))} IPs",
        ]
        sibling_count = len(
            (result.get("reverse_whois") or {}).get("sibling_domains") or {}
        )
        if sibling_count:
            parts.append(f"{sibling_count} siblings")
        bucket_total = int((result.get("cloud_buckets") or {}).get("total_hits", 0))
        if bucket_total:
            parts.append(f"{bucket_total} buckets")
        origin_count = len((result.get("origin_discovery") or {}).get("origin_candidates", []) or [])
        if origin_count:
            parts.append(f"{origin_count} origins")
        cert_groups = len((result.get("cert_sans") or {}).get("groups", []) or [])
        if cert_groups:
            parts.append(f"{cert_groups} cert groups")
        return ", ".join(parts)
    elif name == "secret_scanner":
        return f"{result.get('total', 0)} git secret finding(s)"
    elif name == "portscan":
        s = result.get("summary", {})
        hr = len(s.get("high_risk", []))
        return (f"{s.get('total_open_ports', 0)} ports, "
                f"{s.get('hosts_with_ports', 0)} hosts"
                + (f", ⚠{hr} high-risk" if hr else ""))
    elif name == "techstack":
        return f"{len(result.get('technologies_summary', {}))} technologies"
    elif name == "spa_crawler":
        if result.get("status") == "skipped":
            return "skipped (playwright not installed)"
        return f"{result.get('total', 0)} SPA-rendered endpoint(s)"
    elif name == "fuzzer":
        return (f"{result.get('total_endpoints', 0)} endpoints, "
                f"{result.get('js_secrets_count', 0)} JS secrets")
    elif name == "vulnscan":
        return f"{result.get('total', 0)} vulnerabilities"
    elif name == "cve_check":
        summary = result.get("summary", {})
        return (f"{summary.get('total_cves', 0)} CVEs, "
                f"{summary.get('with_exploitdb', 0)} ExploitDB match(es)")
    elif name == "error_analyzer":
        return (f"{len(result.get('sql_errors', []))} SQL/error leak(s), "
                f"{result.get('status_5xx', {}).get('total', 0)} 5xx, "
                f"{result.get('status_401', {}).get('total', 0)} 401")
    elif name == "correlator":
        return f"{result.get('total', 0)} correlated priority item(s)"
    elif name == "fp_triage":
        return (f"{result.get('assessed', 0)} triaged, "
                f"{result.get('flagged', 0)} likely false positive(s)")
    elif name == "asset_risk":
        tier = result.get("tier_summary", {})
        return (f"{result.get('total_assets', 0)} assets, "
                f"crit={tier.get('critical', 0)}, high={tier.get('high', 0)}")
    elif name == "cmscan":
        return f"{result.get('total_findings', 0)} findings"
    elif name == "endpoint_harvester":
        return (f"{result.get('total_endpoints', 0)} endpoints, "
                f"{len(result.get('parameters', []))} params, "
                f"{len(result.get('secrets', []))} secret(s)")
    elif name in (
        "cors_checker", "auth_probe", "sourcemap_analyzer", "takeover_checker",
        "http_smuggling", "oauth_probe", "host_header_injection",
        "prototype_pollution", "xxe_probe", "deserialization_probe",
        "race_condition", "open_redirect_probe", "api_key_validator", "idor_probe",
        "jwt_audit", "websocket_probe", "api_schema_audit", "js_security_audit",
        "xss", "sql_injection",
    ):
        return f"{result.get('total', len(result.get('findings', [])))} findings"
    elif name == "vhost_enum":
        return f"{result.get('total', 0)} vhosts"
    elif name == "openapi_parser":
        return f"{result.get('total_specs', 0)} specs, {result.get('total_endpoints', 0)} endpoints"
    elif name == "parameter_discovery":
        return f"{result.get('total', 0)} parameters"
    elif name == "injection_probe":
        return f"{result.get('total', 0)} injection finding(s)"
    elif name == "file_inclusion":
        return f"{len(result.get('lfi', []))} LFI, {len(result.get('rfi', []))} RFI hit(s)"
    elif name == "command_injection":
        return f"{result.get('candidate_count', 0)} CMDi candidate(s), {result.get('confirmed', 0)} confirmed"
    elif name == "ssrf_probe":
        return f"{result.get('candidate_count', 0)} SSRF candidate(s), {result.get('total', 0)} finding(s)"
    elif name == "ssl_checker":
        return (f"{len(result.get('ssl_issues', []))} SSL issues, "
                f"{result.get('total_missing_headers', 0)} missing headers")
    elif name == "ai_report":
        return "analysis ready" if result.get("analysis") else result.get("status", "?")
    return status


# ─── Module runner ────────────────────────────────────────────────────────────

def run_one(
    name: str,
    target: str,
    session_dir: Path,
    config: dict,
    all_results: dict,
    resume: bool,
) -> tuple[str, dict]:
    try:
        Cls = _load_cls(name)
        kwargs = _build_kwargs(name, all_results)
        mod = Cls(target=target, output_dir=str(session_dir), config=config, **kwargs)
        result = mod.execute(resume=resume)
        return name, result
    except Exception as exc:
        import traceback
        console.print(f"[red]✗ Module '{name}' crashed: {exc}[/red]")
        return name, {"status": "crashed", "error": str(exc),
                      "traceback": traceback.format_exc()}


def _maybe_send_ai_advice(advisor, name: str, result: dict, target: str, tg) -> None:
    if not advisor or not advisor.should_advise(name, result):
        return

    def _worker():
        advice = advisor.analyse(name, result, target)
        if advice and tg.is_ready():
            tg.send_message(f"AI advice - {name.upper()}\n\n{advice[:3000]}", parse_mode=None)

    threading.Thread(target=_worker, daemon=True).start()


# ─── Pipeline orchestrator ────────────────────────────────────────────────────

def run_pipeline(
    target: str,
    config: dict,
    session_dir: Path,
    active: list[str],
    resume: bool,
    previous_results: dict | None = None,
) -> dict:
    from reporting.telegram import TelegramNotifier
    from modules.ai_advisor import AIAdvisor

    t0 = time.time()
    all_results: dict = {}
    master_json = session_dir / "all_results.json"

    # Initialize Telegram notifier
    tg = TelegramNotifier(config)
    advisor = AIAdvisor(config)
    tg_ready = tg.is_ready()
    if tg_ready:
        console.print("[green]✓[/green] Telegram notifications enabled")
        tg.notify_start(target, active)
    else:
        console.print("[dim]ℹ Telegram notifications disabled[/dim]")

    # On resume — pre-load all cached module results
    if resume and master_json.exists():
        try:
            all_results = json.loads(master_json.read_text(encoding="utf-8"))
            console.print(f"[cyan]Resume: {len(all_results)} cached module(s) loaded[/cyan]\n")
        except Exception:
            pass

    # Build execution groups (preserving PIPELINE order)
    groups: dict[int, list[str]] = {}
    for step in PIPELINE:
        if step["name"] in active:
            groups.setdefault(step["group"], []).append(step["name"])

    total_modules = len(active)
    completed_count = 0

    for gid in sorted(groups):
        names = groups[gid]

        # Send progress notification (not for every module to avoid spam)
        if tg_ready and completed_count > 0:
            current_name = names[0] if len(names) == 1 else f"{', '.join(names)}"
            tg.notify_progress(completed_count, total_modules, current_name)

        if len(names) == 1:
            # Sequential
            name, result = run_one(names[0], target, session_dir, config, all_results, resume)
            all_results[name] = result
            completed_count += 1

            # Telegram: module completion notification
            if tg_ready:
                status = result.get("status", "unknown")
                elapsed = result.get("elapsed_seconds", 0)
                summary = _module_summary(name, result)
                if status in ("error", "crashed"):
                    tg.notify_error(name, result.get("error", "Unknown error"))
                else:
                    tg.notify_module_complete(name, status, elapsed, summary)
            _maybe_send_ai_advice(advisor, name, result, target, tg)
        else:
            # Parallel — snapshot all_results so threads don't race
            console.print(f"\n[bold cyan]⚡ Running in parallel: {', '.join(names)}[/bold cyan]")
            snapshot = copy.deepcopy(all_results)
            with ThreadPoolExecutor(max_workers=len(names)) as pool:
                futures = {
                    pool.submit(run_one, n, target, session_dir, config, snapshot, resume): n
                    for n in names
                }
                for future in as_completed(futures):
                    n, result = future.result()
                    all_results[n] = result
                    completed_count += 1

                    # Telegram: module completion notification
                    if tg_ready:
                        status = result.get("status", "unknown")
                        elapsed = result.get("elapsed_seconds", 0)
                        summary = _module_summary(n, result)
                        if status in ("error", "crashed"):
                            tg.notify_error(n, result.get("error", "Unknown error"))
                        else:
                            tg.notify_module_complete(n, status, elapsed, summary)
                    _maybe_send_ai_advice(advisor, n, result, target, tg)

        # Persist after every group — enables resume on crash
        master_json.write_text(
            json.dumps(all_results, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    if previous_results:
        try:
            from reporting.json_report import build_results_diff
            diff = build_results_diff(previous_results, all_results)
            all_results["diff"] = diff
            (session_dir / "diff_results.json").write_text(
                json.dumps(diff, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            master_json.write_text(
                json.dumps(all_results, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            console.print(f"[yellow]![/yellow] Diff skipped: {e}")

    # Persist a per-target snapshot so the next run can auto-diff.
    _persist_snapshot(target, all_results)

    # ── Telegram: critical vulnerability alerts ───────────────────────────────
    vuln_findings = all_results.get("vulnscan", {}).get("findings", [])
    if tg_ready and vuln_findings:
        tg.notify_critical_vulns(vuln_findings)

    # ── Reports ───────────────────────────────────────────────────────────────
    elapsed = _fmt_elapsed(time.time() - t0)
    console.print(Rule("[bold magenta]Generating reports[/bold magenta]"))

    ai_text = all_results.get("ai_report", {}).get("analysis", "")
    formats = config.get("reporting", {}).get("formats", ["html", "md"])

    report_path = ""
    json_path = ""
    try:
        from reporting.json_report import generate_json_report
        json_path = generate_json_report(session_dir, target, all_results, elapsed)
        console.print(f"  [green]✓[/green]  JSON → {json_path}")
    except Exception as e:
        console.print(f"  [red]✗[/red]  JSON report: {e}")

    try:
        from reporting.html_report import HTMLReportGenerator
        gen = HTMLReportGenerator(str(session_dir), target, elapsed)
        report_path = gen.generate(all_results, ai_text)
        console.print(f"  [green]✓[/green]  HTML → {report_path}")
    except Exception as e:
        console.print(f"  [red]✗[/red]  HTML report: {e}")

    _print_summary(target, session_dir, all_results, elapsed)

    # ── Telegram: final completion notification ───────────────────────────────
    if tg_ready:
        recon = all_results.get("recon", {})
        web   = all_results.get("webdetect", {})
        ports = all_results.get("portscan", {}).get("summary", {})
        tech  = all_results.get("techstack", {})
        fuzz  = all_results.get("fuzzer", {})
        vuln  = all_results.get("vulnscan", {})
        cve   = all_results.get("cve_check", {})
        cors  = all_results.get("cors_checker", {})
        auth  = all_results.get("auth_probe", {})
        takeover = all_results.get("takeover_checker", {})

        cloud_buckets = recon.get("cloud_buckets", {}) or {}
        cert_sans = recon.get("cert_sans", {}) or {}
        origin = recon.get("origin_discovery", {}) or {}
        siblings = (recon.get("reverse_whois", {}) or {}).get("sibling_domains") or {}
        asset_graph = recon.get("asset_graph_summary", {}) or {}

        tg_summary = {
            "subdomains":      recon.get("subdomains_total", 0),
            "live_hosts":      len(web.get("live_urls") or recon.get("live_http", [])),
            "open_ports":      ports.get("total_open_ports", 0),
            "technologies":    len(tech.get("technologies_summary", {})),
            "vulnerabilities": vuln.get("total", 0),
            "cves":            cve.get("summary", {}).get("total_cves", 0),
            "endpoints":       fuzz.get("total_endpoints", 0),
            "js_secrets":      fuzz.get("js_secrets_count", 0),
            "cors_findings":   cors.get("total", len(cors.get("findings", []))),
            "auth_findings":   auth.get("total", len(auth.get("findings", []))),
            "takeover_findings": takeover.get("total", len(takeover.get("findings", []))),
            "sibling_domains":   len(siblings),
            "cloud_bucket_hits": int(cloud_buckets.get("total_hits", 0)),
            "origin_candidates": len(origin.get("origin_candidates", []) or []),
            "cert_san_groups":   len(cert_sans.get("groups", []) or []),
            "asset_graph_nodes": int(asset_graph.get("node_count", 0)),
            "elapsed":         elapsed,
        }

        report_files = [p for p in (json_path, report_path) if p]
        tg.notify_complete(target, tg_summary, report_files)

    return all_results



# ─── Console summary ──────────────────────────────────────────────────────────

def _print_summary(target: str, session_dir: Path, results: dict, elapsed: str):
    recon = results.get("recon", {})
    web   = results.get("webdetect", {})
    ports = results.get("portscan", {}).get("summary", {})
    tech  = results.get("techstack", {})
    fuzz  = results.get("fuzzer", {})
    vuln  = results.get("vulnscan", {})
    cve   = results.get("cve_check", {})
    cors  = results.get("cors_checker", {})
    auth  = results.get("auth_probe", {})
    secret = results.get("secret_scanner", {})
    injection = results.get("injection_probe", {})
    active_probe_findings = sum(
        results.get(module_name, {}).get("total", len(results.get(module_name, {}).get("findings", [])))
        for module_name in ACTIVE_PROBE_MODULES
    )
    takeover = results.get("takeover_checker", {})
    params = results.get("parameter_discovery", {})
    corr = results.get("correlator", {})
    n_vuln = vuln.get("total", 0)

    t = Table(show_header=False, border_style="dim", box=None, padding=(0, 1))
    t.add_column("k", style="bold"); t.add_column("v", style="cyan")
    t.add_row("🎯 Target",           target)
    t.add_row("📁 Output dir",       str(session_dir))
    t.add_row("⏱  Duration",         elapsed)
    t.add_row("🌐 Subdomains",       str(recon.get("subdomains_total", 0)))
    t.add_row("✅ Live HTTP",        str(len(web.get("live_urls") or recon.get("live_http", []))))
    t.add_row("🖥  Unique IPs",       str(len(recon.get("resolved_ips", []))))
    t.add_row("🔌 Open ports",       str(ports.get("total_open_ports", 0)))
    t.add_row("🧰 Technologies",     str(len(tech.get("technologies_summary", {}))))
    t.add_row("🔎 Endpoints",        str(fuzz.get("total_endpoints", 0)))
    t.add_row("🚨 Vulnerabilities",  f"[{'red' if n_vuln else 'green'}]{n_vuln}[/{'red' if n_vuln else 'green'}]")
    t.add_row("🧨 CVEs",             str(cve.get("summary", {}).get("total_cves", 0)))
    t.add_row("🔑 JS Secrets",       str(fuzz.get("js_secrets_count", 0)))
    t.add_row("Git secret findings", str(secret.get("total", len(secret.get("findings", [])))))
    t.add_row("CORS findings",       str(cors.get("total", len(cors.get("findings", [])))))
    t.add_row("Auth findings",       str(auth.get("total", len(auth.get("findings", [])))))
    t.add_row("Active probe findings", str(active_probe_findings))
    t.add_row("Takeover candidates", str(takeover.get("total", len(takeover.get("findings", [])))))
    t.add_row("Parameters",          str(params.get("total", 0)))
    t.add_row("Correlated priorities", str(corr.get("total", 0)))

    # Expanded recon coverage rows — only shown when the optional flags fired
    cloud_buckets = recon.get("cloud_buckets", {}) or {}
    cert_sans = recon.get("cert_sans", {}) or {}
    origin = recon.get("origin_discovery", {}) or {}
    siblings = (recon.get("reverse_whois", {}) or {}).get("sibling_domains") or {}
    asset_graph = recon.get("asset_graph_summary", {}) or {}

    sibling_count = len(siblings)
    bucket_total = int(cloud_buckets.get("total_hits", 0))
    bucket_listable = sum(
        1
        for hits in (cloud_buckets.get("by_provider", {}) or {}).values()
        for h in (hits or [])
        if h.get("status") == "listable"
    )
    origin_count = len(origin.get("origin_candidates", []) or [])
    cert_groups = len(cert_sans.get("groups", []) or [])
    asset_nodes = int(asset_graph.get("node_count", 0))

    if sibling_count:
        t.add_row("🪪 Sibling domains", str(sibling_count))
    if bucket_total:
        bucket_row = str(bucket_total)
        if bucket_listable:
            bucket_row += f" ([red]{bucket_listable} listable[/red])"
        t.add_row("☁  Cloud buckets", bucket_row)
    if origin_count:
        t.add_row("🎯 Origin candidates", str(origin_count))
    if cert_groups:
        t.add_row("🔐 Cert SAN groups", str(cert_groups))
    if asset_nodes:
        t.add_row("🕸 Asset graph nodes", str(asset_nodes))

    console.print(Panel(t, title="[bold magenta]ReconX — Complete[/bold magenta]",
                        border_style="magenta", padding=(1, 2)))


def _fmt_elapsed(seconds: float) -> str:
    m, s = int(seconds // 60), int(seconds % 60)
    return f"{m}m {s}s"


def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        console.print(f"[yellow]Config not found: {cfg_path}, using defaults[/yellow]")
        return {}

    with cfg_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def apply_config_preset(config: dict, preset_name: str) -> dict:
    """Apply a built-in or config-defined preset over the loaded config."""
    preset_name = str(preset_name or "").strip()
    if not preset_name:
        return config

    built_in = copy.deepcopy(CONFIG_PRESETS.get(preset_name, {}))
    custom_presets = config.get("config_presets", {}) if isinstance(config, dict) else {}
    custom = copy.deepcopy(custom_presets.get(preset_name, {})) if isinstance(custom_presets, dict) else {}
    if not built_in and not custom:
        console.print(f"[yellow]Unknown preset '{preset_name}' - using config as-is[/yellow]")
        return config

    merged = copy.deepcopy(config)
    _deep_update(merged, built_in)
    _deep_update(merged, custom)
    merged["active_preset"] = preset_name
    return merged


def _deep_update(target: dict, updates: dict) -> dict:
    for key, value in (updates or {}).items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = copy.deepcopy(value)
    return target


ENV_CONFIG_MAP = {
    "TELEGRAM_BOT_TOKEN": ("telegram", "bot_token"),
    "TELEGRAM_CHAT_ID": ("telegram", "chat_id"),
    "OPENAI_API_KEY": ("ai", "openai_api_key"),
    "OPENAI_BASE_URL": ("ai", "openai_base_url"),
    "OLLAMA_HOST": ("ai", "ollama_url"),
    "SHODAN_API_KEY": ("api_keys", "shodan"),
    "VIRUSTOTAL_API_KEY": ("api_keys", "virustotal"),
    "WPSCAN_API_TOKEN": ("api_keys", "wpscan"),
    "SECURITYTRAILS_API_KEY": ("api_keys", "securitytrails"),
    "BINARYEDGE_API_KEY": ("api_keys", "binaryedge"),
    "GITHUB_TOKEN": ("api_keys", "github"),
    "PDCP_API_KEY": ("api_keys", "pdcp"),
}


def apply_env_overrides(config: dict) -> dict:
    """Fill empty config secrets from environment variables without logging values."""
    for env_name, path in ENV_CONFIG_MAP.items():
        value = os.getenv(env_name, "").strip()
        if not value:
            continue

        section = config
        for key in path[:-1]:
            section = section.setdefault(key, {})

        leaf = path[-1]
        if not section.get(leaf):
            section[leaf] = value

    return config


def load_env_file(path: str | Path = ".env") -> None:
    """Load simple KEY=VALUE pairs from .env without overriding real environment."""
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            os.environ.setdefault(key, value)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="ReconX — Automated Web Application Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t example.com
  python3 main.py -t example.com -m recon,portscan,vulnscan
  python3 main.py -t example.com --skip cmscan
  python3 main.py -t example.com --resume       # reuse previous session
  python3 main.py -t example.com --new           # ignore previous results

Note: if a previous session exists for the same target, resume is
enabled automatically. Use --new to force a clean start.
        """,
    )
    p.add_argument("-t", "--target",  help="Domain or IP")
    p.add_argument("-c", "--config",  default="config.yaml")
    p.add_argument("-o", "--output",  default=".", help="Base output directory")
    p.add_argument("-m", "--modules", help="Comma-separated modules (default: all)")
    p.add_argument("-s", "--skip",    help="Comma-separated modules to skip")
    p.add_argument("-r", "--resume",  action="store_true",
                   help="Reuse cached module results from a previous run")
    p.add_argument("--preset", choices=sorted(CONFIG_PRESETS),
                   help="Scan profile: safe, bug_bounty, deep, or intrusive")
    p.add_argument("--diff", help="Compare against previous all_results.json or report.json")
    p.add_argument("--new", action="store_true",
                   help="Force a clean session (ignore previous results)")
    p.add_argument("--legal-acknowledgment", action="store_true",
                   help="Confirm you are authorized to scan the target")
    p.add_argument("--list-modules",  action="store_true")

    args = p.parse_args()
    console.print(BANNER)

    if args.list_modules:
        console.print("[bold]Modules (execution order):[/bold]")
        for step in PIPELINE:
            label = MODULE_LABELS.get(step['name'], '')
            console.print(f"  • {step['name']:<15} [dim]group {step['group']}[/dim]  {label}")
        sys.exit(0)

    if not args.target:
        console.print("[red]Error: -t/--target is required[/red]")
        p.print_help()
        sys.exit(1)

    try:
        active = _select_active_modules(args.modules, args.skip)
    except ValueError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        console.print("Use --list-modules to see valid module names.")
        sys.exit(1)

    load_env_file(Path(args.config).with_name(".env"))
    cfg = load_config(args.config)
    preset_name = args.preset or cfg.get("preset") or cfg.get("scan", {}).get("preset", "")
    cfg = apply_env_overrides(apply_config_preset(cfg, preset_name))
    previous_results = _load_previous_results(args.diff) if args.diff else None
    if previous_results is None:
        # Auto-pick the most recent snapshot for this target so re-scans diff out of the box.
        auto_prev = _resolve_previous_snapshot(args.target)
        if auto_prev is not None:
            previous_results = _load_previous_results(str(auto_prev))
            console.print(f"[dim]Diff baseline:[/dim] {auto_prev}")
    legal_cfg = cfg.get("legal", {})
    if legal_cfg.get("require_acknowledgment", False) and not args.legal_acknowledgment:
        console.print("[red]Error: pass --legal-acknowledgment to confirm authorization[/red]")
        sys.exit(2)

    console.print(f"[bold]Target:[/bold]  [cyan]{args.target}[/cyan]")
    console.print(f"[bold]Modules:[/bold] {', '.join(active)}")
    if cfg.get("active_preset"):
        console.print(f"[bold]Preset:[/bold]  {cfg['active_preset']}")
    if args.legal_acknowledgment:
        console.print("[green]Legal acknowledgment:[/green] authorization confirmed\n")
    else:
        console.print("[yellow]Legal notice:[/yellow] run only with written authorization and defined scope\n")

    session_dir, effective_resume = resolve_session_dir(
        args.target, args.output, args.resume, args.new
    )
    console.print(f"[bold]Resume:[/bold]  {'yes' if effective_resume else 'no'}")
    console.print(f"[bold]Output:[/bold]  {session_dir}\n")

    try:
        install_ctrl_c_skip_handler()
        run_pipeline(args.target, cfg, session_dir, active, effective_resume, previous_results)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — partial results saved.[/yellow]")
        sys.exit(1)


def find_latest_session(target: str, base: str) -> Path | None:
    """Find the most recent existing session directory for the given target.

    Searches output/ for directories whose name ends with _{target} (the
    date prefix varies).  Returns the newest match (by name sort) or None.
    """
    safe = target.replace("/", "_").replace(":", "_")
    output_root = Path(base) / "output"
    if not output_root.is_dir():
        return None
    candidates = sorted(
        (d for d in output_root.iterdir()
         if d.is_dir() and d.name.endswith(f"_{safe}")),
        key=lambda d: d.name,
        reverse=True,
    )
    # Return the latest one that actually has an all_results.json (i.e. data)
    for d in candidates:
        if (d / "all_results.json").exists():
            return d
    # If there are dirs but none has results yet, return the newest dir anyway
    return candidates[0] if candidates else None


def create_session_dir(target: str, base: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_")
    # Keep dots in domain for readability: 17-05-2026_miras.app
    date_str = datetime.now().strftime('%d-%m-%Y')
    d = Path(base) / "output" / f"{date_str}_{safe}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_session_dir(target: str, base: str, resume: bool, force_new: bool) -> tuple[Path, bool]:
    """Resolve the session directory and whether resume should be active.

    Returns (session_dir, effective_resume_flag).
    When resume is True (or auto-detected), the latest existing session is
    reused so that cached module results carry over — even across days.
    """
    if force_new:
        return create_session_dir(target, base), False

    previous = find_latest_session(target, base)

    if resume:
        if previous:
            console.print(
                f"[cyan]♻  Resuming previous session:[/cyan] {previous}"
            )
            return previous, True
        else:
            console.print("[yellow]No previous session found — starting fresh[/yellow]")
            return create_session_dir(target, base), False

    # Auto-resume: if a previous session with data exists, reuse it
    if previous and (previous / "all_results.json").exists():
        console.print(
            f"[cyan]♻  Previous session detected for [bold]{target}[/bold] → auto-resuming[/cyan]\n"
            f"   [dim]{previous}[/dim]\n"
            f"   [dim]Use --new to force a clean start[/dim]"
        )
        return previous, True

    return create_session_dir(target, base), False


def _load_previous_results(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[yellow]Could not load diff baseline: {exc}[/yellow]")
        return {}
    if "raw_module_status" in data and "assets" in data:
        return {
            "recon": {"subdomains": data.get("assets", {}).get("subdomains", [])},
            "webdetect": {"live_urls": data.get("assets", {}).get("live_urls", [])},
            "portscan": {"hosts": data.get("assets", {}).get("ports_by_host", [])},
            "vulnscan": {"findings": data.get("findings", [])},
            "asset_risk": data.get("asset_risk", {}),
        }
    return data if isinstance(data, dict) else {}


# ── Scan snapshot store (per-target history for auto-diff) ────────────────────

def _snapshot_root() -> Path:
    base = os.environ.get("RECONX_SNAPSHOT_DIR")
    if base:
        return Path(base).expanduser()
    return Path.home() / ".reconx" / "snapshots"


def _snapshot_dir(target: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    return _snapshot_root() / safe


def _resolve_previous_snapshot(target: str) -> Path | None:
    """Return the path to the most recent prior snapshot for this target."""
    sdir = _snapshot_dir(target)
    if not sdir.is_dir():
        return None
    candidates = sorted(sdir.glob("scan-*.json"))
    return candidates[-1] if candidates else None


def _persist_snapshot(target: str, all_results: dict) -> Path | None:
    """Save a compact snapshot of this scan for future diffs.

    Trims the snapshot to only what build_results_diff actually consumes so
    the per-target history stays small even after many scans.
    """
    try:
        sdir = _snapshot_dir(target)
        sdir.mkdir(parents=True, exist_ok=True)
        snapshot = {
            "recon": {
                "subdomains": all_results.get("recon", {}).get("subdomains", []),
            },
            "webdetect": {
                "live_urls": all_results.get("webdetect", {}).get("live_urls", [])
                             or all_results.get("recon", {}).get("live_http", []),
            },
            "portscan": {
                "hosts": all_results.get("portscan", {}).get("hosts", []),
            },
            "vulnscan": {
                "findings": all_results.get("vulnscan", {}).get("findings", []),
            },
            "asset_risk": {
                "ranked_assets": [
                    {"asset": a.get("asset"), "score": a.get("score")}
                    for a in all_results.get("asset_risk", {}).get("ranked_assets", [])
                ],
            },
        }
        # Mirror per-module findings so _finding_set can compute the delta
        for module_name in (
            "secret_scanner", "fuzzer", "cors_checker", "auth_probe",
            "injection_probe", "xss", "sql_injection", "http_smuggling",
            "oauth_probe", "host_header_injection",
            "prototype_pollution", "xxe_probe", "deserialization_probe",
            "race_condition", "open_redirect_probe",
            "api_key_validator", "idor_probe", "jwt_audit", "websocket_probe",
            "api_schema_audit", "js_security_audit", "sourcemap_analyzer",
            "endpoint_harvester", "ssrf_probe", "error_analyzer", "file_inclusion",
            "command_injection", "takeover_checker", "correlator",
        ):
            findings = all_results.get(module_name, {}).get("findings", [])
            if findings:
                snapshot[module_name] = {"findings": findings}

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = sdir / f"scan-{timestamp}.json"
        path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        # Keep at most 10 snapshots per target
        keep = sorted(sdir.glob("scan-*.json"))[-10:]
        for old in sdir.glob("scan-*.json"):
            if old not in keep:
                old.unlink(missing_ok=True)
        return path
    except Exception as exc:
        console.print(f"[yellow]Snapshot persist skipped: {exc}[/yellow]")
        return None


if __name__ == "__main__":
    main()
