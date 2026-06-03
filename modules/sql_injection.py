"""
ReconX - Module: SQL injection testing with sqlmap.
"""

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.base import BaseModule
from modules.finding_registry import build_finding

# ── SQLi-likelihood signals ───────────────────────────────────────────────────
SQLI_HIGH_PARAMS = frozenset({
    "id", "uid", "pid", "cid", "oid", "gid", "cat", "category", "cate",
    "product", "prod", "item", "order", "ord", "post", "article", "art",
    "news", "page", "user", "username", "account", "acct", "member", "search",
    "q", "query", "s", "keyword", "kw", "filter", "sort", "orderby", "group",
    "groupby", "col", "column", "field", "table", "ref", "code", "num", "no",
    "year", "status", "state", "type", "kind",
})
SQLI_MEDIUM_PARAMS = frozenset({
    "name", "title", "email", "login", "value", "val", "view", "mode",
    "action", "tab", "key", "price", "amount", "qty", "quantity", "date",
    "from", "to", "start", "end", "min", "max", "limit", "offset", "lang",
})
SQLI_SORT_PARAMS = frozenset({
    "sort", "order", "orderby", "order_by", "sortby", "sort_by", "dir",
    "direction", "column", "col", "field", "orderdir",
})
SQLI_PATH_HINTS = re.compile(
    r"(search|product|item|categor|article|news|post|list|user|profile|"
    r"account|order|invoice|report|query|filter|detail|catalog|blog|comment|"
    r"review|forum|board|shop|store|gallery|event|booking)", re.I,
)
NUMERIC_VALUE_RE = re.compile(r"^-?\d{1,12}$")
NUMERICISH_VALUE_RE = re.compile(r"^\d[\d.,:\-/ ]{1,}$")


class SQLInjectionModule(BaseModule):
    name = "sql_injection"
    description = "SQL Injection Testing (sqlmap)"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        parameter_results: dict | None = None,
        fuzzer_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("sql_injection", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "targets": [], "total": 0, "status": "disabled"}

        possible = float(cfg.get("possible_threshold", 0.3))
        strong = float(cfg.get("strong_threshold", 0.5))

        # Score every (url, param) for SQLi likelihood, optionally confirming with
        # a lone-quote error pre-screen, then rank.
        candidates = self._collect_candidates()
        if cfg.get("error_prescreen", True):
            self._error_prescreen(candidates, cfg)
        scored = sorted((c for c in candidates if c["score"] >= possible),
                        key=lambda c: c["score"], reverse=True)
        self.save_json(scored, "sqli_candidates.json")

        have_sqlmap = self.has_tool("sqlmap")
        if not have_sqlmap:
            self.warn("sqlmap not available in PATH — reporting scored candidates only")

        sqlmap_findings: list[dict] = []
        runs: list[dict] = []
        confirmed: set[tuple] = set()
        if have_sqlmap:
            targets = self._build_targets(scored, strong, cfg)
            if targets:
                sqlmap_dir = self.module_dir / "sqlmap_output"
                sqlmap_dir.mkdir(exist_ok=True)
                self.save_json(targets, "sqlmap_targets.json")
                timeout = int(cfg.get("timeout", 900))
                for index, target in enumerate(targets, start=1):
                    cmd = self._sqlmap_command(target, cfg, sqlmap_dir)
                    result = self.exec(cmd, timeout=timeout, label=f"sqlmap {target['url']}")
                    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
                    stdout_file = f"sqlmap_run_{index:03d}.txt"
                    self.save_text(output, stdout_file)
                    target_findings = self._parse_sqlmap_findings(output, target, stdout_file, index)
                    sqlmap_findings.extend(target_findings)
                    for f in target_findings:
                        confirmed.add((self._base(target["url"]), str(f.get("evidence", {}).get("param", "")).lower()))
                    runs.append({"url": target["url"], "params": target.get("params", []),
                                 "returncode": result.returncode, "stdout_file": stdout_file,
                                 "findings": len(target_findings)})
                self.save_json(runs, "sqlmap_runs.json")

        # Candidate findings — the "where SQLi might exist" list — skipping any
        # parameter sqlmap already confirmed (those get the HIGH finding instead).
        candidate_findings = [
            self._candidate_finding(c, strong) for c in scored
            if (self._base(c["url"]), c["param"].lower()) not in confirmed
        ]
        findings = candidate_findings + sqlmap_findings
        self.save_json(findings, "sqlmap_findings.json")

        result = {
            "findings": findings,
            "candidates": scored,
            "candidate_count": len(scored),
            "runs": runs,
            "total": len(findings),
            "tested": len(runs),
            "sqlmap_used": have_sqlmap,
        }
        if not have_sqlmap:
            result["missing_tools"] = ["sqlmap"]
            if not findings:
                result["status"] = "skipped"
        return result

    # ── Candidate collection & scoring ──────────────────────────────────────────
    def _collect_candidates(self) -> list[dict]:
        cands: dict[tuple, dict] = {}

        def add(url: str, param: str, value: str, source: str):
            url, param = str(url or "").strip(), str(param or "").strip()
            if not url.startswith(("http://", "https://")) or not param:
                return
            if param not in self._query_params(url):
                url = self._with_param(url, param)
            if not self.is_in_scope(url):
                return
            parsed = urlparse(url)
            key = (self._base(url), param.lower())
            score, reasons = self._score(param, value, parsed.path)
            existing = cands.get(key)
            if existing is None or score > existing["score"]:
                cands[key] = {"url": url, "param": param, "value": value, "path": parsed.path,
                              "score": round(score, 2), "reasons": reasons, "sources": [source]}
            elif source not in cands[key]["sources"]:
                cands[key]["sources"].append(source)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                url = item.get("url", "")
                param = item.get("param") or item.get("name", "")
                value = dict(parse_qsl(urlparse(url).query)).get(param, "")
                add(url, param, value, item.get("source", "parameter_discovery"))

        urls = set(self.parameter_results.get("parameterized_targets", []) or [])
        classified = self.fuzzer_results.get("classified", {}) or {}
        urls.update(classified.get("with_params", []) or [])
        urls.update(u for u in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(u))
        for url in urls:
            for param, value in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
                add(str(url), param, value, "fuzzer")

        return list(cands.values())

    @staticmethod
    def _score(param: str, value: str, path: str) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        pname = (param or "").strip().lower()
        val = str(value or "").strip()

        if NUMERIC_VALUE_RE.match(val):
            score += 0.4
            reasons.append(f"numeric value ({val}) — WHERE id=N style")
        elif val and NUMERICISH_VALUE_RE.match(val):
            score += 0.2
            reasons.append("numeric-ish value (date/range/list)")

        if pname in SQLI_HIGH_PARAMS or pname.endswith("_id") or pname == "id":
            score += 0.35
            reasons.append(f"param name '{param}' is commonly query-bound")
        elif pname in SQLI_MEDIUM_PARAMS:
            score += 0.2
            reasons.append(f"param name '{param}' is sometimes query-bound")

        if pname in SQLI_SORT_PARAMS:
            score += 0.2
            reasons.append(f"'{param}' is an ORDER BY-style parameter")

        hit = SQLI_PATH_HINTS.search(path or "")
        if hit:
            score += 0.2
            reasons.append(f"DB-backed endpoint ('{hit.group(0)}')")

        return min(score, 1.0), reasons

    def _error_prescreen(self, candidates: list[dict], cfg: dict) -> None:
        """Send a lone quote to high-ish candidates; a SQL error force-promotes them."""
        from modules.error_analyzer import SQL_ERROR_SIGNATURES
        import requests
        session = requests.Session()
        session.verify = False
        timeout = float(cfg.get("request_timeout", 10))
        max_requests = int(cfg.get("prescreen_max_requests", 60))
        min_score = float(cfg.get("prescreen_min_score", 0.2))
        sent = 0
        for cand in sorted(candidates, key=lambda c: c["score"], reverse=True):
            if sent >= max_requests:
                break
            if cand["score"] < min_score:
                continue
            probe = self._set_param_value(cand["url"], cand["param"], (cand["value"] or "1") + "'")
            resp = self.http_get(probe, session=session, timeout=timeout, verify=False)
            sent += 1
            if resp is None:
                continue
            body = resp.text or ""
            for rx, dbms in SQL_ERROR_SIGNATURES:
                if rx.search(body):
                    cand["score"] = max(cand["score"], 0.95)
                    cand["reasons"] = cand["reasons"] + [f"lone-quote triggered {dbms} SQL error"]
                    cand["error_dbms"] = dbms
                    break

    def _build_targets(self, scored: list[dict], strong: float, cfg: dict) -> list[dict]:
        by_url: dict[str, dict] = {}
        for cand in scored:
            if cand["score"] < strong:
                continue
            entry = by_url.setdefault(cand["url"], {"url": cand["url"], "params": [],
                                                    "score": 0.0, "sources": set()})
            if cand["param"] not in entry["params"]:
                entry["params"].append(cand["param"])
            entry["score"] = max(entry["score"], cand["score"])
            entry["sources"].update(cand["sources"])
        targets = sorted(by_url.values(), key=lambda t: t["score"], reverse=True)
        for t in targets:
            t["sources"] = sorted(t["sources"])
        return targets[: int(cfg.get("max_targets", 10))]

    def _candidate_finding(self, cand: dict, strong: float) -> dict:
        tier = "likely" if cand["score"] >= strong else "possible"
        return build_finding(
            self.name, "sqli_candidate_parameter",
            url=cand["url"],
            title=f"{tier.capitalize()} SQL injection parameter: {cand['param']}",
            description=("Parameter scored as a probable SQL injection point. "
                         + "; ".join(cand["reasons"]) + ". "
                         + ("Confirmed error-based." if cand.get("error_dbms")
                            else "Unconfirmed — validated with sqlmap when likely.")),
            severity="MEDIUM" if cand["score"] >= strong else "LOW",
            confidence=min(0.85, 0.4 + cand["score"] * 0.4),
            finding_type="sql_injection",
            exploitability="candidate",
            evidence={"param": cand["param"], "value": str(cand["value"])[:80],
                      "path": cand["path"], "score": cand["score"],
                      "reasons": cand["reasons"], "sources": cand["sources"],
                      "tier": tier, "error_dbms": cand.get("error_dbms", "")},
        )

    @staticmethod
    def _base(url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query="", fragment=""))

    @staticmethod
    def _set_param_value(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        names = {k for k, _ in pairs}
        updated = [(k, value if k == param else v) for k, v in pairs]
        if param not in names:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    def _sqlmap_command(self, target: dict, cfg: dict, output_dir: Path) -> list[str]:
        cmd = [
            "sqlmap",
            "-u", target["url"],
            "--batch",
            "--disable-coloring",
            "--output-dir", str(output_dir),
            "--level", str(self._bounded_int(cfg.get("level", 1), 1, 5)),
            "--risk", str(self._bounded_int(cfg.get("risk", 1), 1, 3)),
            "--threads", str(self._bounded_int(cfg.get("threads", 1), 1, 10)),
            "--timeout", str(self._bounded_int(cfg.get("request_timeout", 10), 1, 120)),
            "--retries", str(self._bounded_int(cfg.get("retries", 1), 0, 10)),
            "--technique", str(cfg.get("technique", "BEUST")),
            "--no-cast",
            "--no-escape",
        ]
        params = [param for param in target.get("params", []) if param]
        if params:
            cmd.extend(["-p", ",".join(params)])
        if cfg.get("smart", True):
            cmd.append("--smart")
        if cfg.get("random_agent", True):
            cmd.append("--random-agent")
        if cfg.get("forms", False):
            cmd.append("--forms")
        crawl = self._bounded_int(cfg.get("crawl", 0), 0, 10)
        if crawl:
            cmd.extend(["--crawl", str(crawl)])
        tamper = str(cfg.get("tamper", "")).strip()
        if tamper:
            cmd.extend(["--tamper", tamper])
        for arg in cfg.get("extra_args", []) or []:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())
        return cmd

    def _parse_sqlmap_findings(self, output: str, target: dict, stdout_file: str, index: int) -> list[dict]:
        text = output or ""
        markers = (
            "sqlmap identified the following injection point",
            "is vulnerable. do you want to keep testing",
        )
        if not any(marker in text.lower() for marker in markers):
            return []

        params: set[tuple[str, str]] = set()
        for param, method in re.findall(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", text, re.I):
            params.add((param.strip(), method.strip().upper()))
        for method, param in re.findall(r"\b(GET|POST|URI|Cookie|User-Agent|Referer)\s+parameter\s+'([^']+)'", text, re.I):
            params.add((param.strip(), method.strip().upper()))
        if not params:
            params = {(param, "GET") for param in target.get("params", [])}

        dbms_match = re.search(r"back-end DBMS:\s*([^\n\r]+)", text, re.I)
        dbms = dbms_match.group(1).strip() if dbms_match else ""
        findings = []
        for offset, (param, method) in enumerate(sorted(params), start=1):
            findings.append({
                "source": self.name,
                "id": f"sql_injection_sqlmap_{index}_{offset}",
                "type": "sql_injection",
                "name": "SQL injection detected by sqlmap",
                "title": "SQL injection detected by sqlmap",
                "severity": "HIGH",
                "url": target["url"],
                "description": (
                    "sqlmap reported an injectable parameter. Validate exploitability and "
                    "scope before attempting data extraction."
                ),
                "evidence": {
                    "param": param,
                    "method": method,
                    "dbms": dbms,
                    "stdout_file": stdout_file,
                    "sources": target.get("sources", []),
                },
                "confidence": 0.9,
            })
        return findings

    @staticmethod
    def _query_params(url: str) -> set[str]:
        return {name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name}

    @staticmethod
    def _with_param(url: str, param: str) -> str:
        parsed = urlparse(url)
        query = urlencode({param: "reconx"})
        if parsed.query:
            query = f"{parsed.query}&{query}"
        return urlunparse(parsed._replace(query=query))

    @staticmethod
    def _bounded_int(value, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = minimum
        return min(max(parsed, minimum), maximum)
