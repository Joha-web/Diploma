"""
ReconX — Module: Vulnerability Scanning (Nuclei)
Runs nuclei against all live web hosts using configurable
severity levels and template categories.
"""

import re
import json
import os
import select
import signal
import subprocess
import time
from pathlib import Path
from modules.base import BaseModule


class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "Vulnerability Scanning (Nuclei)"
    required_tools = ["nuclei"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 parameter_results: dict | None = None,
                 openapi_results: dict | None = None,
                 tech_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.parameter_results = parameter_results or {}
        self.openapi_results = openapi_results or {}
        self.tech_results = tech_results or {}
        self.nuclei_runtime: dict = {}
        self._oob_process: subprocess.Popen | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self.config.get("scan", {}).get("nuclei", {}).get("enabled", True):
            self.info("Nuclei disabled in config")
            return {"findings": [], "by_severity": {}, "total": 0, "status": "disabled"}

        urls = self._extract_urls()
        if not urls:
            self.warn("No URLs for vulnerability scanning")
            return {"findings": [], "by_severity": {}, "total": 0}

        url_file = self.module_dir / "target_urls.txt"
        self.save_text(urls, "target_urls.txt")

        # Update nuclei templates before scanning (best practice)
        self._update_templates()

        out_file = self.module_dir / "nuclei_results.jsonl"
        self._run_nuclei(url_file, out_file)

        findings = self._parse_results(out_file)
        by_sev   = self._group_by_severity(findings)
        target_count = self._line_count(url_file)
        if len(findings) == 0 and target_count > 0:
            warning = (
                "Nuclei returned 0 findings on live targets. Possible WAF blocking, "
                "template issue, restricted network, or aggressive rate limit. "
                "Try: nuclei -u <target> -t cves -debug"
            )
            self.warn(warning)
            self.nuclei_runtime["warning"] = warning
            self.nuclei_runtime["target_count"] = target_count

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = len(by_sev.get(sev, []))
            if count:
                icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
                self.warn(f"{icon} {sev}: {count} finding(s)")

        self.save_json(findings, "nuclei_findings.json")

        return {
            "findings":    findings,
            "by_severity": {k: len(v) for k, v in by_sev.items()},
            "total":       len(findings),
            "runtime":     self.nuclei_runtime,
        }

    def summary(self) -> str:
        total = self.results.get("total", 0)
        by_sev = self.results.get("by_severity", {})
        parts = [f"{k}: {v}" for k, v in by_sev.items() if v > 0]
        return f"🚨 {total} findings ({', '.join(parts) or 'none'})"

    # ── Nuclei runner ─────────────────────────────────────────────────────────

    def _update_templates(self):
        """Update nuclei templates. Uses BaseModule.exec() for safety."""
        self.info("Updating Nuclei templates...")
        r = self.exec(["nuclei", "-update-templates", "-silent"], timeout=120)
        if r.returncode == 0:
            self.success("Templates up to date")
        else:
            self.warn("Template update failed — continuing with existing templates")

    def _run_nuclei(self, url_file: Path, out_file: Path):
        ncfg = self.config.get("scan", {}).get("nuclei", {})
        severity  = ",".join(ncfg.get("severity", ["critical", "high", "medium"]))
        waf_names = self._detected_wafs()
        waf_detected = bool(waf_names)
        rate_value = ncfg.get("waf_rate_limit", 30) if waf_detected else ncfg.get("rate_limit", 150)
        rate      = str(rate_value)
        templates = ncfg.get("templates", ["cves", "exposures", "misconfiguration",
                                           "takeovers"])
        enable_risky = ncfg.get("enable_risky", False)
        if not enable_risky:
            risky_templates = {"default-logins", "fuzzing", "workflows"}
            templates = [t for t in templates if t not in risky_templates]
        exclude_tags = ncfg.get("exclude_tags", ["dos", "intrusive", "bruteforce", "destructive"])
        if waf_detected:
            exclude_tags = sorted(set(exclude_tags + ncfg.get(
                "waf_exclude_tags", ["fuzz", "fuzzing", "bruteforce", "headless"]
            )))

        cmd = [
            "nuclei",
            "-l",        str(url_file),
            "-severity", severity,
            "-rl",       rate,
            "-jsonl",
            "-o",        str(out_file),
            "-silent",
            "-no-color",
            "-timeout",  "10",
            "-retries",  "1",
        ]
        for t in templates:
            cmd.extend(["-t", t])
        if exclude_tags and not enable_risky:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        if waf_detected:
            cmd.extend(["-ss", str(ncfg.get("waf_scan_strategy", "host-spray"))])

        oob_runtime = self._apply_oob_flags(cmd, ncfg)
        if ncfg.get("dashboard_upload") and self.config.get("api_keys", {}).get("pdcp"):
            cmd.append("-dashboard")

        timeout = ncfg.get("nuclei_timeout", 3600)
        self.nuclei_runtime = {
            "rate_limit": int(rate_value),
            "waf_detected": waf_detected,
            "waf": waf_names,
            "templates": templates,
            "exclude_tags": exclude_tags if not enable_risky else [],
            "oob": oob_runtime,
        }
        waf_note = f" | WAF-aware rate: {rate}" if waf_detected else ""
        oob_note = " | OOB enabled" if oob_runtime.get("enabled") else " | OOB disabled"
        self.info(f"nuclei → {self._line_count(url_file)} URLs | severity: {severity}{waf_note}{oob_note}")
        try:
            self.exec(cmd, timeout=timeout)
        finally:
            self._stop_oob_client(oob_runtime)
        self.success(f"nuclei finished → {self._line_count(out_file)} raw findings")

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_results(self, out_file: Path) -> list[dict]:
        findings: list[dict] = []
        if not out_file.exists():
            return findings

        for line in out_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                matched_url = obj.get("matched-at", "")
                if matched_url and not self.is_in_scope(matched_url):
                    continue
                cves = sorted({
                    cve.upper()
                    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", json.dumps(obj, default=str), re.I)
                })
                findings.append({
                    "template_id":   obj.get("template-id", ""),
                    "name":          info.get("name", ""),
                    "severity":      info.get("severity", "info").upper(),
                    "description":   info.get("description", "")[:400],
                    "matched_url":   matched_url,
                    "type":          obj.get("type", ""),
                    "tags":          info.get("tags", []),
                    "cves":          cves,
                    "reference":     info.get("reference", [])[:3],
                    "curl_command":  obj.get("curl-command", "")[:500],
                    "extracted":     obj.get("extracted-results", [])[:5],
                    "confidence":    0.95 if obj.get("matcher-status") else 0.85,
                })
            except json.JSONDecodeError:
                continue

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: order.get(x["severity"], 5))
        return findings

    @staticmethod
    def _group_by_severity(findings: list[dict]) -> dict[str, list]:
        groups: dict[str, list] = {}
        for f in findings:
            groups.setdefault(f["severity"], []).append(f)
        return groups

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        for item in self.parameter_results.get("parameterized_targets", []) or []:
            if isinstance(item, str):
                urls.add(item)
        for item in self.openapi_results.get("endpoints", []) or []:
            if isinstance(item, dict) and item.get("url"):
                urls.add(item["url"])
        return self.filter_in_scope_urls(urls)

    def _apply_oob_flags(self, cmd: list[str], ncfg: dict) -> dict:
        oob_cfg = ncfg.get("oob", {})
        enabled = bool(oob_cfg.get("enabled", True))
        runtime = {
            "enabled": enabled,
            "client_available": self.has_tool("interactsh-client"),
            "server": oob_cfg.get("interactsh_server", ""),
            "callback_url": "",
            "interactions_log": "",
            "cooldown_period": int(oob_cfg.get("cooldown_period", 5)),
        }
        if not enabled:
            cmd.append("-ni")
            return runtime

        if runtime["client_available"] and oob_cfg.get("auto_client", True):
            client_runtime = self._start_interactsh_client(oob_cfg)
            runtime.update(client_runtime)

        server = str(oob_cfg.get("interactsh_server") or "").strip()
        if not server and runtime.get("callback_url"):
            server = self._server_from_callback(str(runtime["callback_url"]))
        if server:
            runtime["server"] = server
            cmd.extend(["-iserver", server])
        if oob_cfg.get("interactsh_token"):
            cmd.extend(["-itoken", str(oob_cfg["interactsh_token"])])
        cmd.extend(["-interactions-cooldown-period", str(runtime["cooldown_period"])])
        return runtime

    def _start_interactsh_client(self, oob_cfg: dict) -> dict:
        log_file = self.module_dir / "interactsh_interactions.jsonl"
        cmd = ["interactsh-client", "-json", "-o", str(log_file), "-silent"]
        if oob_cfg.get("interactsh_server"):
            cmd.extend(["-server", str(oob_cfg["interactsh_server"])])
        if oob_cfg.get("interactsh_token"):
            cmd.extend(["-token", str(oob_cfg["interactsh_token"])])

        runtime = {
            "client_started": False,
            "callback_url": "",
            "interactions_log": str(log_file.relative_to(self.output_dir)),
        }
        try:
            popen_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "text": True,
                "env": self._subprocess_env(),
            }
            if os.name != "nt":
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(cmd, **popen_kwargs)
            self._oob_process = proc
            runtime["client_started"] = True
            runtime["client_pid"] = proc.pid
        except Exception as exc:
            runtime["client_error"] = str(exc)
            return runtime

        callback = self._read_interactsh_callback(
            proc,
            timeout=float(oob_cfg.get("registration_timeout", 10)),
        )
        if callback:
            runtime["callback_url"] = callback
            self.success(f"Interactsh callback: {callback}")
        else:
            self.warn("Interactsh client started but no callback URL was observed")
        return runtime

    def _read_interactsh_callback(self, proc: subprocess.Popen, timeout: float = 10) -> str:
        deadline = time.monotonic() + timeout
        while proc.poll() is None and time.monotonic() < deadline:
            stream = proc.stdout
            if stream is None:
                break
            readable, _, _ = select.select([stream], [], [], 0.25)
            if not readable:
                continue
            line = stream.readline()
            if not line:
                continue
            callback = self._extract_interactsh_callback(line)
            if callback:
                return callback
        return ""

    @staticmethod
    def _extract_interactsh_callback(text: str) -> str:
        match = re.search(
            r"\b([a-z0-9][a-z0-9-]{4,}\.(?:oast\.(?:pro|live|site|online)|interact\.sh))\b",
            text,
            re.I,
        )
        return match.group(1).lower() if match else ""

    @staticmethod
    def _server_from_callback(callback: str) -> str:
        host = callback.split("/", 1)[0].strip().strip(".")
        labels = host.split(".")
        if len(labels) < 2:
            return ""
        return "https://" + ".".join(labels[-2:])

    def _stop_oob_client(self, runtime: dict) -> None:
        proc = self._oob_process
        self._oob_process = None
        if not proc or proc.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _detected_wafs(self) -> list[str]:
        names: set[str] = set()
        for host in self.tech_results.get("hosts", []) or []:
            for waf in host.get("waf", []) or []:
                if waf:
                    names.add(str(waf))
            for tech in host.get("technologies", []) or []:
                name = str(tech.get("name", ""))
                category = str(tech.get("category", ""))
                if "waf" in category.lower() or name.lower() in {
                    "cloudflare", "akamai", "imperva", "sucuri", "fastly",
                }:
                    names.add(name)
        return sorted(names)

    def _line_count(self, path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for _ in path.read_text(errors="replace").splitlines() if _.strip())
