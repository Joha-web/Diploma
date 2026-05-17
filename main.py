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
    {"name": "fuzzer",      "group": 4},   # parallel with ssl/auth/cors
    {"name": "ssl_checker", "group": 4},
    {"name": "cors_checker","group": 4},
    {"name": "auth_probe",  "group": 4},
    {"name": "cmscan",      "group": 5},
    {"name": "sourcemap_analyzer", "group": 5},
    {"name": "vhost_enum",  "group": 5},
    {"name": "takeover_checker", "group": 5},
    {"name": "openapi_parser", "group": 5},
    {"name": "parameter_discovery", "group": 6},
    {"name": "injection_probe", "group": 7},
    {"name": "http_smuggling", "group": 6},
    {"name": "oauth_probe", "group": 6},
    {"name": "cache_poison", "group": 6},
    {"name": "host_header_injection", "group": 6},
    {"name": "prototype_pollution", "group": 6},
    {"name": "xxe_probe", "group": 6},
    {"name": "deserialization_probe", "group": 6},
    {"name": "graphql_audit", "group": 6},
    {"name": "race_condition", "group": 6},
    {"name": "open_redirect_probe", "group": 6},
    {"name": "api_key_validator", "group": 6},
    {"name": "jwt_audit", "group": 6},
    {"name": "websocket_probe", "group": 6},
    {"name": "api_schema_audit", "group": 6},
    {"name": "js_security_audit", "group": 6},
    {"name": "xss", "group": 7},
    {"name": "sql_injection", "group": 7},
    {"name": "idor_probe", "group": 7},
    {"name": "vulnscan",    "group": 7},
    {"name": "cve_check",   "group": 8},
    {"name": "correlator",  "group": 9},
    {"name": "ai_report",   "group": 10},
]

CLASS_MAP = {
    "recon":       ("modules.recon",        "ReconModule"),
    "secret_scanner": ("modules.secret_scanner", "SecretScannerModule"),
    "portscan":    ("modules.portscan",     "PortScanModule"),
    "webdetect":   ("modules.webdetect",    "WebdetectModule"),
    "techstack":   ("modules.techstack",    "TechStackModule"),
    "fuzzer":      ("modules.fuzzer",       "FuzzerModule"),
    "ssl_checker": ("modules.ssl_checker",  "SSLCheckerModule"),
    "cors_checker":("modules.cors_checker", "CORSCheckerModule"),
    "auth_probe":  ("modules.auth_probe",   "AuthProbeModule"),
    "cmscan":      ("modules.cmscan",       "CMSScanModule"),
    "sourcemap_analyzer": ("modules.sourcemap_analyzer", "SourceMapAnalyzerModule"),
    "vhost_enum":  ("modules.vhost_enum",   "VHostEnumModule"),
    "takeover_checker": ("modules.takeover_checker", "TakeoverCheckerModule"),
    "openapi_parser": ("modules.openapi_parser", "OpenAPIParserModule"),
    "parameter_discovery": ("modules.parameter_discovery", "ParameterDiscoveryModule"),
    "injection_probe": ("modules.injection_probe", "InjectionProbeModule"),
    "http_smuggling": ("modules.http_smuggling", "HTTPSmugglingModule"),
    "oauth_probe": ("modules.oauth_probe", "OAuthProbeModule"),
    "cache_poison": ("modules.cache_poison", "CachePoisonModule"),
    "host_header_injection": ("modules.host_header_injection", "HostHeaderInjectionModule"),
    "prototype_pollution": ("modules.prototype_pollution", "PrototypePollutionModule"),
    "xxe_probe": ("modules.xxe_probe", "XXEProbeModule"),
    "deserialization_probe": ("modules.deserialization_probe", "DeserializationProbeModule"),
    "graphql_audit": ("modules.graphql_audit", "GraphQLAuditModule"),
    "race_condition": ("modules.race_condition", "RaceConditionModule"),
    "open_redirect_probe": ("modules.open_redirect_probe", "OpenRedirectProbeModule"),
    "api_key_validator": ("modules.api_key_validator", "APIKeyValidatorModule"),
    "idor_probe": ("modules.idor_probe", "IDORProbeModule"),
    "jwt_audit": ("modules.jwt_audit", "JWTAuditModule"),
    "websocket_probe": ("modules.websocket_probe", "WebSocketProbeModule"),
    "api_schema_audit": ("modules.api_schema_audit", "APISchemaAuditModule"),
    "js_security_audit": ("modules.js_security_audit", "JSSecurityAuditModule"),
    "xss": ("modules.xss", "XSSModule"),
    "sql_injection": ("modules.sql_injection", "SQLInjectionModule"),
    "vulnscan":    ("modules.vulnscan",     "VulnScanModule"),
    "cve_check":   ("modules.cve_check",    "CVECheckModule"),
    "correlator":  ("modules.correlator",   "CorrelatorModule"),
    "ai_report":   ("modules.ai_report",    "AIReportModule"),
}

# Module display names for Telegram and console
MODULE_LABELS = {
    "recon":       "DNS & Subdomain Enumeration",
    "secret_scanner": "Git Secret Scanning",
    "portscan":    "Port Scanning",
    "webdetect":   "Web Application Detection",
    "techstack":   "Technology Fingerprinting",
    "fuzzer":      "Crawling & Fuzzing",
    "ssl_checker": "SSL/TLS & Headers Analysis",
    "cors_checker":"CORS Misconfiguration Scanner",
    "auth_probe":  "JWT & Cookie Security Checks",
    "cmscan":      "CMS Vulnerability Scanning",
    "sourcemap_analyzer": "JavaScript Source Map Analysis",
    "vhost_enum":  "Virtual Host Enumeration",
    "takeover_checker": "Subdomain Takeover Checks",
    "openapi_parser": "OpenAPI Discovery",
    "parameter_discovery": "Hidden Parameter Discovery",
    "injection_probe": "SSRF / SSTI / XXE Detection",
    "http_smuggling": "HTTP Request Smuggling",
    "oauth_probe": "OAuth / OIDC Audit",
    "cache_poison": "Web Cache Poisoning",
    "host_header_injection": "Host Header Injection",
    "prototype_pollution": "Server-Side Prototype Pollution",
    "xxe_probe": "OOB XXE Detection",
    "deserialization_probe": "Deserialization Indicators",
    "graphql_audit": "GraphQL Abuse Audit",
    "race_condition": "Race Condition Candidates",
    "open_redirect_probe": "Open Redirect Detection",
    "api_key_validator": "API Key Leak Validation",
    "idor_probe": "IDOR / BOLA Candidate Analysis",
    "jwt_audit": "Deep JWT Security Audit",
    "websocket_probe": "WebSocket Security Checks",
    "api_schema_audit": "OpenAPI Security Schema Audit",
    "js_security_audit": "Static JavaScript Security Audit",
    "xss": "Cross-Site Scripting Testing",
    "sql_injection": "SQL Injection Testing (sqlmap)",
    "vulnscan":    "Vulnerability Scanning (Nuclei)",
    "cve_check":   "CVE & ExploitDB Correlation",
    "correlator":  "Cross-Finding Correlation",
    "ai_report":   "AI Security Analysis",
}

ACTIVE_PROBE_MODULES = (
    "injection_probe", "http_smuggling", "oauth_probe", "cache_poison",
    "host_header_injection", "prototype_pollution", "xxe_probe",
    "deserialization_probe", "graphql_audit", "race_condition",
    "open_redirect_probe", "api_key_validator", "idor_probe",
    "jwt_audit", "websocket_probe", "api_schema_audit", "js_security_audit",
    "xss", "sql_injection",
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
        },
    },
    "deep": {
        "scan": {
            "allow_write": False,
            "rate_limit": 35,
            "global_rate_limit": 35,
            "idor_probe": {"compare_profiles": True, "check_anonymous": True, "max_candidates": 400},
            "jwt_audit": {"collect_from_responses": True, "max_tokens": 200, "max_response_urls": 100},
            "websocket_probe": {"active_handshake": True, "check_origin": True, "max_endpoints": 100},
            "api_schema_audit": {"max_endpoints": 1000},
            "js_security_audit": {"max_js": 300},
            "xss": {"max_targets": 250, "max_requests": 700, "max_payloads": 5, "use_dalfox": True},
            "race_condition": {"active_probe": False},
        },
    },
    "intrusive": {
        "scan": {
            "allow_write": True,
            "rate_limit": 20,
            "global_rate_limit": 20,
            "idor_probe": {"compare_profiles": True, "check_anonymous": True, "max_candidates": 500},
            "websocket_probe": {"active_handshake": True, "check_origin": True, "message_probe": True},
            "xss": {"max_targets": 300, "max_requests": 900, "max_payloads": 5, "use_dalfox": True},
            "race_condition": {"active_probe": True},
            "api_key_validator": {"live_validation": True},
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
    elif name in ("webdetect", "techstack", "fuzzer", "ssl_checker",
                  "cors_checker", "auth_probe", "openapi_parser",
                  "http_smuggling", "oauth_probe", "cache_poison"):
        kwargs["live_hosts"] = live
    elif name == "cmscan":
        kwargs["tech_results"] = all_results.get("techstack", {})
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
    elif name == "graphql_audit":
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
    elif name in ("correlator", "ai_report"):
        kwargs["all_results"] = all_results
    return kwargs


def _module_summary(name: str, result: dict) -> str:
    """Build a one-line summary for a completed module."""
    status = result.get("status", "?")
    if status != "completed":
        return status

    if name == "recon":
        return (f"{result.get('subdomains_total', 0)} subs, "
                f"{len(result.get('live_http', []))} live, "
                f"{len(result.get('resolved_ips', []))} IPs")
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
    elif name == "fuzzer":
        return (f"{result.get('total_endpoints', 0)} endpoints, "
                f"{result.get('js_secrets_count', 0)} JS secrets")
    elif name == "vulnscan":
        return f"{result.get('total', 0)} vulnerabilities"
    elif name == "cve_check":
        summary = result.get("summary", {})
        return (f"{summary.get('total_cves', 0)} CVEs, "
                f"{summary.get('with_exploitdb', 0)} ExploitDB match(es)")
    elif name == "correlator":
        return f"{result.get('total', 0)} correlated priority item(s)"
    elif name == "cmscan":
        return f"{result.get('total_findings', 0)} findings"
    elif name in (
        "cors_checker", "auth_probe", "sourcemap_analyzer", "takeover_checker",
        "http_smuggling", "oauth_probe", "cache_poison", "host_header_injection",
        "prototype_pollution", "xxe_probe", "deserialization_probe", "graphql_audit",
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
    pdf_path = ""
    md_path = ""
    json_path = ""
    if "json" in formats:
        try:
            from reporting.json_report import generate_json_report
            json_path = generate_json_report(session_dir, target, all_results, elapsed)
            console.print(f"  [green]✓[/green]  JSON → {json_path}")
        except Exception as e:
            console.print(f"  [red]✗[/red]  JSON report: {e}")

    if "html" in formats:
        try:
            from reporting.html_report import HTMLReportGenerator
            gen = HTMLReportGenerator(str(session_dir), target, elapsed)
            report_path = gen.generate(all_results, ai_text)
            console.print(f"  [green]✓[/green]  HTML → {report_path}")
        except Exception as e:
            console.print(f"  [red]✗[/red]  HTML report: {e}")

        # PDF (WeasyPrint)
        if report_path:
            try:
                from reporting.pdf_report import generate_pdf
                pdf_path = generate_pdf(report_path)
                if pdf_path:
                    console.print(f"  [green]✓[/green]  PDF  → {pdf_path}")
            except Exception as e:
                console.print(f"  [yellow]![/yellow]  PDF skipped: {e}")

    if "md" in formats:
        md_path = _md_report(session_dir, target, all_results, ai_text, elapsed)
        console.print(f"  [green]✓[/green]  MD   → {md_path}")

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
            "elapsed":         elapsed,
        }

        report_files = [p for p in (json_path, md_path, report_path, pdf_path) if p]
        tg.notify_complete(target, tg_summary, report_files)

    return all_results


# ─── Markdown report ──────────────────────────────────────────────────────────

def _md_report(
    session_dir: Path, target: str, results: dict, ai: str, elapsed: str
) -> str:
    recon = results.get("recon", {})
    web = results.get("webdetect", {})
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
    openapi = results.get("openapi_parser", {})
    params = results.get("parameter_discovery", {})
    corr = results.get("correlator", {})

    lines = [
        f"# 🔬 ReconX: `{target}`",
        f"\n> **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  **Duration:** {elapsed}\n",
        "---\n## 📊 Summary\n",
        "| Metric | Value |", "|--------|-------|",
        f"| Subdomains | {recon.get('subdomains_total', 0)} |",
        f"| Live HTTP hosts | {len(web.get('live_urls') or recon.get('live_http', []))} |",
        f"| Unique IPs | {len(recon.get('resolved_ips', []))} |",
        f"| Open ports | {ports.get('total_open_ports', 0)} |",
        f"| Technologies | {len(tech.get('technologies_summary', {}))} |",
        f"| Endpoints | {fuzz.get('total_endpoints', 0)} |",
        f"| Vulnerabilities | {vuln.get('total', 0)} |",
        f"| CVEs | {cve.get('summary', {}).get('total_cves', 0)} |",
        f"| ExploitDB matches | {cve.get('summary', {}).get('with_exploitdb', 0)} |",
        f"| JS Secrets | {fuzz.get('js_secrets_count', 0)} |",
        f"| Git secret findings | {secret.get('total', len(secret.get('findings', [])))} |",
        f"| CORS findings | {cors.get('total', len(cors.get('findings', [])))} |",
        f"| Auth findings | {auth.get('total', len(auth.get('findings', [])))} |",
        f"| Active probe findings | {active_probe_findings} |",
        f"| Takeover candidates | {takeover.get('total', len(takeover.get('findings', [])))} |",
        f"| OpenAPI endpoints | {openapi.get('total_endpoints', 0)} |",
        f"| Parameters | {params.get('total', 0)} |",
        f"| Correlated priorities | {corr.get('total', 0)} |",
        "",
    ]
    if ai:
        lines += ["---\n## 🤖 AI Analysis\n", ai, ""]

    for f in vuln.get("findings", [])[:50]:
        sev = f.get("severity", "").upper()
        lines.append(f"| {sev} | {f.get('name','')} | {f.get('matched_url','')} |")

    cves = cve.get("cves", [])
    if cves:
        lines += ["", "---\n## CVE / ExploitDB Correlation\n",
                  "| CVE | Severity | Target | ExploitDB | Mode |",
                  "|-----|----------|--------|-----------|------|"]
        for item in cves[:50]:
            edb = "yes" if item.get("exploit_available") else "no"
            sim = item.get("attack_simulation", {}).get("mode", "dry_run")
            target_ref = item.get("matched_url") or item.get("component", "")
            lines.append(
                f"| {item.get('cve', '')} | {item.get('severity', '')} | "
                f"{target_ref} | {edb} | {sim} |"
            )

    for module_name, title in (
        ("secret_scanner", "Git Secret Findings"),
        ("fuzzer", "Fuzzer Findings"),
        ("cors_checker", "CORS Findings"),
        ("auth_probe", "Auth Findings"),
        ("injection_probe", "Injection Probe Findings"),
        ("xss", "XSS Findings"),
        ("sql_injection", "SQL Injection Findings"),
        ("http_smuggling", "HTTP Smuggling Findings"),
        ("oauth_probe", "OAuth / OIDC Findings"),
        ("cache_poison", "Cache Poisoning Findings"),
        ("host_header_injection", "Host Header Findings"),
        ("prototype_pollution", "Prototype Pollution Findings"),
        ("xxe_probe", "XXE Findings"),
        ("deserialization_probe", "Deserialization Findings"),
        ("graphql_audit", "GraphQL Audit Findings"),
        ("race_condition", "Race Condition Findings"),
        ("open_redirect_probe", "Open Redirect Findings"),
        ("api_key_validator", "API Key Validation Findings"),
        ("idor_probe", "IDOR / BOLA Findings"),
        ("jwt_audit", "JWT Audit Findings"),
        ("websocket_probe", "WebSocket Findings"),
        ("api_schema_audit", "OpenAPI Schema Audit Findings"),
        ("js_security_audit", "JavaScript Security Findings"),
        ("sourcemap_analyzer", "Source Map Findings"),
        ("takeover_checker", "Subdomain Takeover Candidates"),
        ("correlator", "Cross-Finding Correlation"),
    ):
        findings = results.get(module_name, {}).get("findings", [])
        if findings:
            lines += ["", f"---\n## {title}\n",
                      "| Severity | Type | URL |",
                      "|----------|------|-----|"]
            for item in findings[:50]:
                lines.append(
                    f"| {item.get('severity', 'INFO')} | {item.get('type', '')} | "
                    f"{item.get('url') or item.get('matched_url', '')} |"
                )

    path = session_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


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
    "CENSYS_API_ID": ("api_keys", "censys_api_id"),
    "CENSYS_API_SECRET": ("api_keys", "censys_api_secret"),
    "CENSYS_PAT": ("api_keys", "censys_api_secret"),
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
  python3 main.py -t example.com --resume
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
    legal_cfg = cfg.get("legal", {})
    if legal_cfg.get("require_acknowledgment", False) and not args.legal_acknowledgment:
        console.print("[red]Error: pass --legal-acknowledgment to confirm authorization[/red]")
        sys.exit(2)

    console.print(f"[bold]Target:[/bold]  [cyan]{args.target}[/cyan]")
    console.print(f"[bold]Modules:[/bold] {', '.join(active)}")
    if cfg.get("active_preset"):
        console.print(f"[bold]Preset:[/bold]  {cfg['active_preset']}")
    console.print(f"[bold]Resume:[/bold]  {'yes' if args.resume else 'no'}")
    if args.legal_acknowledgment:
        console.print("[green]Legal acknowledgment:[/green] authorization confirmed\n")
    else:
        console.print("[yellow]Legal notice:[/yellow] run only with written authorization and defined scope\n")

    session_dir = create_session_dir(args.target, args.output)
    console.print(f"[bold]Output:[/bold]  {session_dir}\n")

    try:
        install_ctrl_c_skip_handler()
        run_pipeline(args.target, cfg, session_dir, active, args.resume, previous_results)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — partial results saved.[/yellow]")
        sys.exit(1)


def create_session_dir(target: str, base: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_").replace(".", "_")
    d = Path(base) / "output" / f"reconx_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
        }
    return data if isinstance(data, dict) else {}


if __name__ == "__main__":
    main()
