"""
ReconX - Module: SSRF / SSTI / XXE detection probes.
"""

import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.base import BaseModule
from modules.vulnscan import VulnScanModule


class InjectionProbeModule(BaseModule):
    name = "injection_probe"
    description = "SSRF / SSTI / XXE Detection"
    required_tools: list[str] = []

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("*{7*7}", "49"),
    ]

    SSRF_PATHS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/metadata/v1/",
        "http://localhost:22",
        "http://127.0.0.1:6379",
    ]

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
        self._oob_process = None

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("injection_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._collect_parameter_targets()
        max_targets = int(cfg.get("max_targets", 50))
        targets = targets[:max_targets]
        if not targets:
            self.warn("No parameterized URLs for injection probes")
            return {"findings": [], "targets": [], "total": 0}

        ssti_findings: list[dict] = []
        ssrf_findings: list[dict] = []
        if cfg.get("ssti", True):
            ssti_findings = self._probe_ssti(targets, cfg)
        if cfg.get("ssrf", True):
            ssrf_findings = self._probe_ssrf(targets, cfg)
        if cfg.get("inband_ssrf", False):
            ssrf_findings.extend(self._probe_ssrf_inband(targets, cfg))

        findings = ssti_findings + ssrf_findings
        self.save_json(targets, "injection_targets.json")
        self.save_json(ssti_findings, "ssti_findings.json")
        self.save_json(ssrf_findings, "ssrf_findings.json")
        self.save_json(findings, "injection_findings.json")
        return {
            "findings": findings,
            "total": len(findings),
            "targets": targets,
            "ssti_findings": len(ssti_findings),
            "ssrf_findings": len(ssrf_findings),
        }

    def _collect_parameter_targets(self) -> list[dict]:
        targets: dict[str, dict] = {}

        def add(url: str, param: str, source: str) -> None:
            url = str(url or "").strip()
            param = str(param or "").strip()
            if not url.startswith(("http://", "https://")) or not param:
                return
            if not self.is_in_scope(url):
                return
            entry = targets.setdefault(url, {"url": url, "params": set(), "sources": set()})
            entry["params"].add(param)
            entry["sources"].add(source)

        for item in self.parameter_results.get("parameters", []) or []:
            if isinstance(item, dict):
                add(item.get("url", ""), item.get("param") or item.get("name", ""), item.get("source", "parameter_discovery"))

        for url in self.parameter_results.get("parameterized_targets", []) or []:
            for param in self._query_params(url):
                add(str(url), param, "parameterized_target")

        classified = self.fuzzer_results.get("classified", {}) or {}
        for url in classified.get("with_params", []) or []:
            for param in self._query_params(url):
                add(str(url), param, "fuzzer")
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            if "?" not in str(url):
                continue
            for param in self._query_params(url):
                add(str(url), param, "fuzzer")

        result = []
        for item in targets.values():
            result.append({
                "url": item["url"],
                "params": sorted(item["params"]),
                "sources": sorted(item["sources"]),
            })
        return sorted(result, key=lambda item: item["url"])

    def _probe_ssti(self, targets: list[dict], cfg: dict) -> list[dict]:
        findings: list[dict] = []
        timeout = float(cfg.get("timeout", self.config.get("scan", {}).get("timeout", 15)))
        max_requests = int(cfg.get("max_ssti_requests", 250))
        requests_sent = 0

        for target in targets:
            baseline = self.http_get(target["url"], timeout=timeout, verify=False)
            baseline_body = baseline.text or "" if baseline else ""
            for param in target.get("params", []):
                for payload, expected in self.SSTI_PAYLOADS:
                    if requests_sent >= max_requests:
                        return findings
                    probe_url = self._replace_param(target["url"], param, payload)
                    requests_sent += 1
                    resp = self.http_get(probe_url, timeout=timeout, verify=False)
                    if resp is None:
                        continue
                    body = resp.text or ""
                    if expected not in body or expected in baseline_body:
                        continue
                    findings.append(self._finding(
                        finding_id="ssti_expression_evaluated",
                        finding_type="ssti",
                        severity="HIGH",
                        title="Possible SSTI expression evaluation",
                        url=probe_url,
                        description=(
                            "A template expression payload was reflected as its evaluated result. "
                            "Manually validate the template engine and exploitability."
                        ),
                        evidence={
                            "param": param,
                            "payload": payload,
                            "expected": expected,
                            "status": resp.status_code,
                            "body_excerpt": self._excerpt(body, expected),
                        },
                        confidence=0.85,
                    ))
                    break
        return findings

    def _probe_ssrf(self, targets: list[dict], cfg: dict) -> list[dict]:
        helper, runtime = self._start_oob_runtime(cfg)
        callback = str(runtime.get("callback_url", "")).strip()
        if not callback:
            if runtime.get("client_available") is False:
                self.warn("Interactsh client not available - SSRF OOB probes skipped")
            else:
                self.warn("No Interactsh callback URL - SSRF OOB probes skipped")
            helper._stop_oob_client(runtime)
            return []

        timeout = float(cfg.get("timeout", self.config.get("scan", {}).get("timeout", 15)))
        max_requests = int(cfg.get("max_ssrf_requests", 150))
        sent: list[dict] = []
        requests_sent = 0
        try:
            for target in targets:
                for param in target.get("params", []):
                    if requests_sent >= max_requests:
                        break
                    token = f"rx{requests_sent:04d}"
                    payload = self._oob_payload(callback, token)
                    probe_url = self._replace_param(target["url"], param, payload)
                    requests_sent += 1
                    sent.append({
                        "token": token,
                        "url": probe_url,
                        "param": param,
                        "payload": payload,
                    })
                    self.http_get(probe_url, timeout=timeout, verify=False)

            wait = float(cfg.get("ssrf_wait", runtime.get("cooldown_period", 5)))
            if wait > 0:
                time.sleep(wait)

            interactions = self._read_oob_interactions(runtime)
            findings = []
            for item in sent:
                matches = self._matching_interactions(interactions, item["token"], callback)
                if not matches:
                    continue
                findings.append(self._finding(
                    finding_id="ssrf_oob_callback",
                    finding_type="ssrf",
                    severity="HIGH",
                    title="SSRF confirmed by OOB callback",
                    url=item["url"],
                    description=(
                        "A parameter value triggered an Interactsh callback, confirming "
                        "server-side retrieval of attacker-controlled URLs."
                    ),
                    evidence={
                        "param": item["param"],
                        "payload": item["payload"],
                        "callback_url": callback,
                        "interactions": matches[:5],
                    },
                    confidence=0.95,
                ))
            return findings
        finally:
            helper._stop_oob_client(runtime)

    def _probe_ssrf_inband(self, targets: list[dict], cfg: dict) -> list[dict]:
        findings: list[dict] = []
        timeout = float(cfg.get("timeout", self.config.get("scan", {}).get("timeout", 15)))
        markers = ("ami-id", "instance-id", "metadata", "redis_version", "ssh-")
        for target in targets[: int(cfg.get("max_inband_targets", 10))]:
            for param in target.get("params", []):
                for payload in self.SSRF_PATHS:
                    probe_url = self._replace_param(target["url"], param, payload)
                    resp = self.http_get(probe_url, timeout=timeout, verify=False)
                    if resp is None:
                        continue
                    body = (resp.text or "").lower()
                    matched = [marker for marker in markers if marker in body]
                    if not matched:
                        continue
                    findings.append(self._finding(
                        finding_id="ssrf_inband_indicator",
                        finding_type="ssrf",
                        severity="MEDIUM",
                        title="Potential in-band SSRF indicator",
                        url=probe_url,
                        description="A metadata or internal-service URL produced a recognizable response marker.",
                        evidence={"param": param, "payload": payload, "markers": matched[:5]},
                        confidence=0.75,
                    ))
                    break
        return findings

    def _start_oob_runtime(self, cfg: dict) -> tuple[object, dict]:
        oob_cfg = dict(self.config.get("scan", {}).get("nuclei", {}).get("oob", {}) or {})
        oob_cfg.update(cfg.get("oob", {}) or {})
        runtime = VulnScanModule._apply_oob_flags(self, [], {"oob": oob_cfg})
        return self, runtime

    def _start_interactsh_client(self, oob_cfg: dict) -> dict:
        return VulnScanModule._start_interactsh_client(self, oob_cfg)

    def _read_interactsh_callback(self, proc, timeout: float = 10) -> str:
        return VulnScanModule._read_interactsh_callback(self, proc, timeout)

    def _stop_oob_client(self, runtime: dict) -> None:
        VulnScanModule._stop_oob_client(self, runtime)

    _extract_interactsh_callback = staticmethod(VulnScanModule._extract_interactsh_callback)
    _server_from_callback = staticmethod(VulnScanModule._server_from_callback)

    def _read_oob_interactions(self, runtime: dict) -> list[dict]:
        rel_path = runtime.get("interactions_log", "")
        if rel_path:
            path = self.output_dir / rel_path
        else:
            path = self.module_dir / "interactsh_interactions.jsonl"
        path = Path(path)
        if not path.exists():
            return []

        interactions: list[dict] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                interactions.append(json.loads(line))
            except json.JSONDecodeError:
                interactions.append({"raw": line})
        return interactions

    @staticmethod
    def _matching_interactions(interactions: list[dict], token: str, callback: str) -> list[dict]:
        matched = []
        callback_host = InjectionProbeModule._callback_host(callback)
        for item in interactions:
            text = json.dumps(item, default=str).lower()
            if token and token.lower() in text:
                matched.append(item)
            elif not token and callback_host and callback_host in text:
                matched.append(item)
        return matched

    @staticmethod
    def _oob_payload(callback: str, token: str) -> str:
        host = InjectionProbeModule._callback_host(callback)
        return f"http://{token}.{host}" if host else callback

    @staticmethod
    def _callback_host(callback: str) -> str:
        value = str(callback or "").strip()
        if "://" in value:
            parsed = urlparse(value)
            return (parsed.hostname or "").strip(".").lower()
        return value.split("/", 1)[0].strip(".").lower()

    @staticmethod
    def _query_params(url: str) -> list[str]:
        parsed = urlparse(str(url or ""))
        return sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key})

    @staticmethod
    def _replace_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        new_pairs = []
        for key, existing in pairs:
            if key == param:
                new_pairs.append((key, value))
                replaced = True
            else:
                new_pairs.append((key, existing))
        if not replaced:
            new_pairs.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(new_pairs, doseq=True)))

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 120) -> str:
        match = re.search(re.escape(marker), body or "", re.I)
        if not match:
            return (body or "")[: radius * 2]
        start = max(match.start() - radius, 0)
        end = min(match.end() + radius, len(body))
        return body[start:end]

    def _finding(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        title: str,
        url: str,
        description: str,
        evidence: dict,
        confidence: float,
    ) -> dict:
        return {
            "source": self.name,
            "id": finding_id,
            "type": finding_type,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
        }
