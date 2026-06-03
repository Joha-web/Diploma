"""
ReconX — Module: server-side error surface.

Surfaces three classes of server-side error evidence for the report:

  1. **Error disclosure** — SQL errors (MySQL/Postgres/MSSQL/Oracle/SQLite…) and
     language/framework stack traces leaked in responses. Detected by scanning
     baseline responses plus a small error-provoking probe (a lone quote etc.)
     on parameterised endpoints.
  2. **5xx hotspots** — hosts returning many server-error responses, aggregated
     from the session audit log (audit.jsonl).
  3. **401 hotspots** — hosts returning many auth-required responses, same source.

The 5xx/401 aggregation is passive (reads the audit log every other module
already wrote). Only the error-disclosure probe sends requests, and it is
bounded and scope-checked.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase

# ── DBMS error signatures (error-based SQLi disclosure) ───────────────────────
SQL_ERROR_SIGNATURES = [
    (re.compile(r"SQL syntax.*?MySQL", re.I), "MySQL"),
    (re.compile(r"check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB) server version", re.I), "MySQL/MariaDB"),
    (re.compile(r"Warning.*?\bmysqli?_", re.I), "MySQL"),
    (re.compile(r"valid MySQL result|MySqlException|com\.mysql\.jdbc", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*?ERROR|pg_query\(\)|pg_exec\(\)|unterminated quoted string at or near", re.I), "PostgreSQL"),
    (re.compile(r"org\.postgresql\.util\.PSQLException", re.I), "PostgreSQL"),
    (re.compile(r"Microsoft OLE DB Provider for (?:ODBC Drivers|SQL Server)", re.I), "MSSQL"),
    (re.compile(r"Unclosed quotation mark after the character string|Incorrect syntax near", re.I), "MSSQL"),
    (re.compile(r"System\.Data\.SqlClient\.SqlException|microsoft sql (?:native|server)", re.I), "MSSQL"),
    (re.compile(r"\bORA-\d{5}\b|Oracle.*?Driver|quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"SQLite/JDBCDriver|SQLite3::|sqlite3\.OperationalError|\[SQLITE_ERROR\]|SQLite\.Exception", re.I), "SQLite"),
    (re.compile(r"DB2 SQL error|SQLCODE|com\.ibm\.db2\.jcc", re.I), "DB2"),
    (re.compile(r"Sybase message:|Warning.*?\bsybase_", re.I), "Sybase"),
]

# ── Stack-trace / verbose error signatures (info disclosure) ──────────────────
STACK_TRACE_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\):", re.I), "Python"),
    (re.compile(r"You're seeing this error because you have <code>DEBUG = True", re.I), "Django debug"),
    (re.compile(r"<b>Fatal error</b>:.*?on line\s*<b>\d+|<b>Warning</b>:.*?on line", re.I), "PHP"),
    (re.compile(r"Whoops, looks like something went wrong|Symfony\\Component", re.I), "Laravel/Symfony"),
    (re.compile(r"at [\w.$]+\([\w.]+\.java:\d+\)|java\.lang\.[A-Za-z.]+Exception", re.I), "Java"),
    (re.compile(r"System\.[A-Za-z.]+Exception:|\bat [\w.<>]+\(.*?\.cs:line \d+\)", re.I), ".NET"),
    (re.compile(r"\.rb:\d+:in [`']|ActionController::|Rails\.application", re.I), "Ruby/Rails"),
    (re.compile(r"\n\s+at .+? \(.*?:\d+:\d+\)", re.M), "Node.js"),
    (re.compile(r"Microsoft VBScript runtime error|ASP\.NET is configured to show verbose error", re.I), "ASP/.NET"),
]

# ── Framework DEBUG-mode signatures (high-precision, debug-only markers) ──────
# These prove debug mode is enabled (not just a one-off error): they leak
# settings/secrets and can enable RCE (Werkzeug console, Laravel Ignition).
FRAMEWORK_DEBUG_SIGNATURES = [
    (re.compile(r"You're seeing this error because you have\s*<code>\s*DEBUG\s*=\s*True", re.I), "Django (DEBUG=True)"),
    (re.compile(r"Using the URLconf defined in .{1,80}?Django tried these URL patterns", re.I | re.S), "Django (DEBUG=True)"),
    (re.compile(r"Request Method:.{0,200}?Django Version:", re.I | re.S), "Django (DEBUG=True)"),
    (re.compile(r"Werkzeug Debugger|The debugger caught an exception|werkzeug/debug/", re.I), "Flask/Werkzeug debugger"),
    (re.compile(r"id=\"console\".{0,200}?werkzeug|Console Locked", re.I | re.S), "Flask/Werkzeug console"),
    (re.compile(r"Whoops\\?,?\s*looks like something went wrong", re.I), "Laravel (APP_DEBUG=true)"),
    (re.compile(r"/_ignition/|Ignition\\\\|Illuminate\\\\Foundation\\\\Bootstrap", re.I), "Laravel Ignition (APP_DEBUG=true)"),
    (re.compile(r"/_profiler/|Symfony\\\\Component\\\\HttpKernel\\\\Exception|sf-toolbar", re.I), "Symfony (debug toolbar)"),
    (re.compile(r"Whitelabel Error Page|\"trace\"\s*:\s*\"[\w.]+Exception", re.I), "Spring Boot (trace enabled)"),
    (re.compile(r"Action Controller: Exception caught|<div id=\"traces\">|Rails\.root:", re.I), "Rails (development mode)"),
    (re.compile(r"Server Error in '/' Application.{0,400}?(Show Detailed|Stack Trace:)", re.I | re.S), ".NET (customErrors off)"),
]

ERROR_PAYLOADS = ["'", "\"\\'"]


class ErrorAnalyzerModule(ActiveProbeBase):
    name = "error_analyzer"
    description = "Server-Side Error Surface"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 parameter_results: dict | None = None,
                 fuzzer_results: dict | None = None,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []

    # ── Public API ─────────────────────────────────────────────────────────────
    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "total": 0, "status": "disabled"}
        cfg = self.module_config()

        # 1 + 2 + 3: aggregate observed status codes from the audit log (passive).
        status_5xx, status_401, status_summary = self._aggregate_audit_statuses(cfg)

        # Error disclosure (debug mode / SQL errors / stack traces) — baseline,
        # error-provoking probe, and a debug-mode trigger.
        sql_errors, server_errors, debug_modes = self._detect_error_disclosure(cfg)

        findings: list[dict] = []
        findings += [self._debug_finding(e) for e in debug_modes]
        findings += [self._disclosure_finding(e, "sql") for e in sql_errors]
        findings += [self._disclosure_finding(e, "server") for e in server_errors]
        findings += self._status_findings(status_5xx, "5xx", cfg)
        findings += self._status_findings(status_401, "401", cfg)
        findings = self.dedup_findings(findings)

        self.save_json({"debug_modes": debug_modes, "sql_errors": sql_errors,
                        "server_errors": server_errors, "status_5xx": status_5xx,
                        "status_401": status_401}, "error_analysis.json")
        return {
            "findings": findings,
            "total": len(findings),
            "debug_modes": debug_modes,
            "sql_errors": sql_errors,
            "server_errors": server_errors,
            "status_5xx": status_5xx,
            "status_401": status_401,
            "status_summary": status_summary,
        }

    def summary(self) -> str:
        r = self.results
        return (f"🧯 {len(r.get('debug_modes', []))} debug-mode, "
                f"{len(r.get('sql_errors', []))} SQL/error leak(s), "
                f"{r.get('status_5xx', {}).get('total', 0)} 5xx, "
                f"{r.get('status_401', {}).get('total', 0)} 401")

    # ── Audit-log status aggregation ────────────────────────────────────────────
    def _aggregate_audit_statuses(self, cfg: dict) -> tuple[dict, dict, dict]:
        audit_path = self.output_dir / "audit.jsonl"
        per_host_5xx: dict[str, dict] = defaultdict(lambda: {"count": 0, "statuses": defaultdict(int), "sample_urls": []})
        per_host_401: dict[str, dict] = defaultdict(lambda: {"count": 0, "sample_urls": []})
        overall: dict[str, int] = defaultdict(int)
        sample_cap = int(cfg.get("max_sample_urls", 15))

        for line in self._read_audit_lines(audit_path):
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                continue
            url = entry.get("url", "")
            status = entry.get("status")
            if not isinstance(status, int) or not url:
                continue
            # Re-check scope ourselves — logged `in_scope` is True even for the
            # third-party recon APIs (github/otx/…), which we must exclude.
            if not self.is_in_scope(url):
                continue
            host = urlparse(url).netloc
            overall[str(status)] += 1
            if 500 <= status <= 599:
                bucket = per_host_5xx[host]
                bucket["count"] += 1
                bucket["statuses"][str(status)] += 1
                if len(bucket["sample_urls"]) < sample_cap and url not in bucket["sample_urls"]:
                    bucket["sample_urls"].append(url)
            elif status == 401:
                bucket = per_host_401[host]
                bucket["count"] += 1
                if len(bucket["sample_urls"]) < sample_cap and url not in bucket["sample_urls"]:
                    bucket["sample_urls"].append(url)

        def shape(per_host: dict) -> dict:
            hosts = []
            for host, data in per_host.items():
                row = {"host": host, "count": data["count"], "sample_urls": data["sample_urls"]}
                if "statuses" in data:
                    row["statuses"] = dict(data["statuses"])
                hosts.append(row)
            hosts.sort(key=lambda h: h["count"], reverse=True)
            return {"total": sum(h["count"] for h in hosts), "hosts": hosts}

        return shape(per_host_5xx), shape(per_host_401), dict(overall)

    def _read_audit_lines(self, path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (FileNotFoundError, OSError):
            return []

    def _status_findings(self, agg: dict, kind: str, cfg: dict) -> list[dict]:
        threshold = int(cfg.get("min_5xx" if kind == "5xx" else "min_401", 3 if kind == "5xx" else 5))
        findings: list[dict] = []
        for host in agg.get("hosts", []):
            if host["count"] < threshold:
                continue
            if kind == "5xx":
                findings.append(self.make_finding(
                    "server_5xx_hotspot",
                    f"https://{host['host']}",
                    title=f"Frequent 5xx server errors on {host['host']} ({host['count']})",
                    description=("The host returned many 5xx responses during the scan, indicating "
                                 "server-side faults (unhandled exceptions, overload, or broken routes)."),
                    severity="MEDIUM",
                    confidence=0.7,
                    finding_type="server_5xx_hotspot",
                    exploitability="passive",
                    evidence={"host": host["host"], "count": host["count"],
                              "statuses": host.get("statuses", {}), "sample_urls": host["sample_urls"]},
                ))
            else:
                findings.append(self.make_finding(
                    "server_401_hotspot",
                    f"https://{host['host']}",
                    title=f"Many 401 responses on {host['host']} ({host['count']})",
                    description=("The host returned many 401 Unauthorized responses, marking a large "
                                 "authentication-protected surface worth reviewing for auth weaknesses."),
                    severity="INFO",
                    confidence=0.7,
                    finding_type="server_401_hotspot",
                    exploitability="passive",
                    evidence={"host": host["host"], "count": host["count"],
                              "sample_urls": host["sample_urls"]},
                ))
        return findings

    # ── Error-disclosure detection ──────────────────────────────────────────────
    def _detect_error_disclosure(self, cfg: dict) -> tuple[list[dict], list[dict], list[dict]]:
        import requests
        session = requests.Session()
        session.verify = False
        timeout = self.request_timeout()
        max_requests = int(cfg.get("max_requests", 150))
        sent = 0
        sql_errors: list[dict] = []
        server_errors: list[dict] = []
        debug_modes: list[dict] = []
        seen: set[tuple] = set()

        def scan(url: str, body: str, param: str = "", payload: str = ""):
            host_path = urlparse(url).netloc + urlparse(url).path
            debug_hit = False
            # Framework DEBUG mode (most severe) — check first.
            for rx, framework in FRAMEWORK_DEBUG_SIGNATURES:
                m = rx.search(body)
                if m:
                    debug_hit = True
                    key = ("debug", urlparse(url).netloc, framework)
                    if key not in seen:
                        seen.add(key)
                        debug_modes.append({"url": url, "framework": framework,
                                            "param": param, "payload": payload,
                                            "snippet": self._snippet(body, m)})
                    break
            # SQL errors (independent of debug).
            for rx, dbms in SQL_ERROR_SIGNATURES:
                m = rx.search(body)
                if m:
                    key = ("sql", host_path, dbms)
                    if key not in seen:
                        seen.add(key)
                        sql_errors.append({"url": url, "param": param, "payload": payload,
                                           "dbms": dbms, "snippet": self._snippet(body, m)})
                    break
            # Generic stack traces only when it isn't already a debug page.
            if not debug_hit:
                for rx, stack in STACK_TRACE_SIGNATURES:
                    m = rx.search(body)
                    if m:
                        key = ("srv", host_path, stack)
                        if key not in seen:
                            seen.add(key)
                            server_errors.append({"url": url, "param": param, "payload": payload,
                                                  "stack": stack, "snippet": self._snippet(body, m)})
                        break

        # Baseline fetches — catch errors that leak without any payload.
        if cfg.get("scan_baseline", True):
            for url in self.limit(self._baseline_urls(), "max_baseline", 40):
                if sent >= max_requests:
                    break
                resp = self.http_get(url, session=session, timeout=timeout, verify=False)
                sent += 1
                if resp is not None:
                    scan(url, resp.text or "")

        # Debug-mode trigger: request a random nonexistent path per host. In debug
        # mode Django lists its URLconf, Flask shows the Werkzeug debugger, etc.
        if cfg.get("probe_debug", True):
            import uuid
            hosts = {f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in self._baseline_urls()}
            for root in list(hosts)[: int(cfg.get("max_debug_hosts", 20))]:
                if sent >= max_requests:
                    break
                trigger = f"{root}/reconx-debug-{uuid.uuid4().hex[:10]}/'"
                resp = self.http_get(trigger, session=session, timeout=timeout, verify=False)
                sent += 1
                if resp is not None:
                    scan(trigger, resp.text or "")

        # Active error-provoking probe on parameterised endpoints.
        if cfg.get("probe_errors", True):
            max_params = int(cfg.get("max_params_per_target", 3))
            for target in self.limit(self._param_targets(), "max_targets", 40):
                for param in target["params"][:max_params]:
                    for payload in ERROR_PAYLOADS:
                        if sent >= max_requests:
                            break
                        probe_url = self._inject(target["url"], param, payload)
                        resp = self.http_get(probe_url, session=session, timeout=timeout, verify=False)
                        sent += 1
                        if resp is not None:
                            scan(probe_url, resp.text or "", param=param, payload=payload)

        return sql_errors, server_errors, debug_modes

    def _debug_finding(self, item: dict) -> dict:
        return self.make_finding(
            "framework_debug_enabled",
            item["url"],
            title=f"Framework debug mode enabled: {item['framework']}",
            description=("The application is running with debug mode on. Debug pages expose "
                         "settings, secrets, source and stack traces, and several frameworks "
                         "(Werkzeug console, Laravel Ignition) allow code execution from them. "
                         "Disable debug in production."),
            severity="HIGH",
            confidence=0.85,
            finding_type="framework_debug_enabled",
            exploitability="candidate",
            evidence={"framework": item["framework"], "param": item.get("param", ""),
                      "payload": item.get("payload", ""), "snippet": item["snippet"]},
        )

    def _disclosure_finding(self, item: dict, kind: str) -> dict:
        if kind == "sql":
            return self.make_finding(
                "sql_error_disclosure",
                item["url"],
                title=f"SQL error disclosed ({item['dbms']})",
                description=("The server returned a database error message, revealing the DBMS and "
                             "indicating error-based SQL injection may be possible. Validate with sqlmap."),
                severity="HIGH",
                confidence=0.8,
                finding_type="sql_injection",
                exploitability="candidate",
                evidence={"dbms": item["dbms"], "param": item.get("param", ""),
                          "payload": item.get("payload", ""), "snippet": item["snippet"]},
            )
        return self.make_finding(
            "server_error_disclosure",
            item["url"],
            title=f"Verbose server error / stack trace disclosed ({item['stack']})",
            description=("The server returned a stack trace or verbose error, leaking framework, "
                         "file paths and internal details useful to an attacker."),
            severity="MEDIUM",
            confidence=0.75,
            finding_type="server_error_disclosure",
            exploitability="passive",
            evidence={"stack": item["stack"], "param": item.get("param", ""),
                      "payload": item.get("payload", ""), "snippet": item["snippet"]},
        )

    # ── Target collection helpers ───────────────────────────────────────────────
    def _baseline_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        classified = self.fuzzer_results.get("classified", {}) or {}
        for bucket in ("api", "auth", "with_params"):
            urls.update(str(u) for u in classified.get(bucket, []) or [])
        return self.filter_in_scope_urls(urls)

    def _param_targets(self) -> list[dict]:
        targets: dict[str, set] = defaultdict(set)
        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict) and item.get("url") and item.get("param"):
                targets[str(item["url"])].add(str(item["param"]))
        urls = set(self.parameter_results.get("parameterized_targets", []) or [])
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls.update(classified.get("with_params", []) or [])
        urls.update(u for u in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(u))
        for url in urls:
            for param, _ in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
                if param:
                    targets[str(url)].add(param)
        return [{"url": url, "params": sorted(params)}
                for url, params in targets.items()
                if url.startswith(("http://", "https://")) and self.is_in_scope(url)]

    @staticmethod
    def _inject(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        names = {k for k, _ in pairs}
        updated = [(k, (v + payload) if k == param else v) for k, v in pairs]
        if param not in names:
            updated.append((param, payload))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    @staticmethod
    def _snippet(body: str, match: re.Match, radius: int = 120) -> str:
        start = max(0, match.start() - radius)
        end = min(len(body), match.end() + radius)
        return re.sub(r"\s+", " ", body[start:end]).strip()[:280]
