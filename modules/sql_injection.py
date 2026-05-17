"""
ReconX - Module: SQL injection testing with sqlmap.
"""

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.base import BaseModule


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

        if not self.has_tool("sqlmap"):
            self.warn("sqlmap not available in PATH")
            return {"findings": [], "targets": [], "total": 0, "status": "skipped", "missing_tools": ["sqlmap"]}

        targets = self._collect_targets()[: int(cfg.get("max_targets", 10))]
        if not targets:
            self.warn("No parameterized URLs for sqlmap")
            return {"findings": [], "targets": [], "total": 0}

        sqlmap_dir = self.module_dir / "sqlmap_output"
        sqlmap_dir.mkdir(exist_ok=True)
        self.save_json(targets, "sqlmap_targets.json")

        findings: list[dict] = []
        runs: list[dict] = []
        timeout = int(cfg.get("timeout", 900))
        for index, target in enumerate(targets, start=1):
            cmd = self._sqlmap_command(target, cfg, sqlmap_dir)
            result = self.exec(cmd, timeout=timeout, label=f"sqlmap {target['url']}")
            output = "\n".join(part for part in (result.stdout, result.stderr) if part)
            stdout_file = f"sqlmap_run_{index:03d}.txt"
            self.save_text(output, stdout_file)

            target_findings = self._parse_sqlmap_findings(output, target, stdout_file, index)
            findings.extend(target_findings)
            runs.append({
                "url": target["url"],
                "params": target.get("params", []),
                "returncode": result.returncode,
                "stdout_file": stdout_file,
                "findings": len(target_findings),
            })

        self.save_json(runs, "sqlmap_runs.json")
        self.save_json(findings, "sqlmap_findings.json")
        return {
            "findings": findings,
            "targets": targets,
            "runs": runs,
            "total": len(findings),
            "tested": len(runs),
        }

    def _collect_targets(self) -> list[dict]:
        targets: dict[str, dict] = {}

        def add(url: str, params: list[str] | set[str], source: str) -> None:
            url = str(url or "").strip()
            clean_params = {str(param).strip() for param in params if str(param).strip()}
            if not url.startswith(("http://", "https://")) or not clean_params:
                return
            if "?" not in url:
                first_param = sorted(clean_params)[0]
                url = self._with_param(url, first_param)
            else:
                existing_params = self._query_params(url)
                for missing_param in sorted(clean_params - existing_params):
                    url = self._with_param(url, missing_param)
            if not self.is_in_scope(url):
                return
            entry = targets.setdefault(url, {"url": url, "params": set(), "sources": set()})
            entry["params"].update(clean_params)
            entry["sources"].add(source)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                add(item.get("url", ""), {item.get("param") or item.get("name", "")}, item.get("source", "parameter_discovery"))

        for url in self.parameter_results.get("parameterized_targets", []) or []:
            add(str(url), self._query_params(str(url)), "parameter_discovery")

        classified = self.fuzzer_results.get("classified", {}) or {}
        for url in classified.get("with_params", []) or []:
            add(str(url), self._query_params(str(url)), "fuzzer")
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            if "?" in str(url):
                add(str(url), self._query_params(str(url)), "fuzzer")

        return [
            {
                "url": item["url"],
                "params": sorted(item["params"]),
                "sources": sorted(item["sources"]),
            }
            for item in sorted(targets.values(), key=lambda entry: entry["url"])
        ]

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
