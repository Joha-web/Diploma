"""
ReconX - Module: unsafe deserialization indicators.
"""

import base64
import re
from urllib.parse import parse_qsl, urlparse

import requests

from modules.base import BaseModule


JAVA_MAGIC = "rO0AB"
DOTNET_VIEWSTATE_RE = re.compile(r'name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']+)', re.I)
ERROR_SIGNATURES = (
    "java.io.ObjectInputStream",
    "StreamCorruptedException",
    "InvalidClassException",
    "ViewStateException",
    "Validation of viewstate MAC failed",
    "LosFormatter",
    "ObjectStateFormatter",
    "pickle.UnpicklingError",
    "yaml.constructor",
)


class DeserializationProbeModule(BaseModule):
    name = "deserialization_probe"
    description = "Unsafe Deserialization Indicators"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        fuzzer_results: dict | None = None,
        live_hosts: list | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("deserialization_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        urls = self._urls()[: int(cfg.get("max_urls", 100))]
        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for url in urls:
            findings.extend(self._inspect_url(url, session, cfg))
        findings = self._dedup(findings)
        self.save_json(findings, "deserialization_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _inspect_url(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        findings: list[dict] = []
        parsed = urlparse(url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            marker = self._serialized_marker(value)
            if marker:
                findings.append(self._finding("serialized_object_in_parameter", "HIGH", url, "Serialized object marker in URL parameter", {
                    "param": key,
                    "marker": marker,
                    "value_prefix": value[:24],
                }))

        resp = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        if resp is None:
            return findings
        body = resp.text or ""
        viewstate = DOTNET_VIEWSTATE_RE.search(body)
        if viewstate:
            value = viewstate.group(1)
            evidence = {"field": "__VIEWSTATE", "value_length": len(value), "value_prefix": value[:32]}
            if value.startswith("/w"):
                evidence["format"] = "ASP.NET LosFormatter"
            findings.append(self._finding("aspnet_viewstate_detected", "INFO", url, "ASP.NET ViewState detected", evidence))
        for signature in ERROR_SIGNATURES:
            if signature.lower() in body.lower():
                findings.append(self._finding("deserialization_error_signature", "MEDIUM", url, "Deserialization error signature exposed", {
                    "signature": signature,
                    "excerpt": self._excerpt(body, signature),
                }))
                break
        return findings

    @staticmethod
    def _serialized_marker(value: str) -> str:
        value = str(value or "")
        if value.startswith(JAVA_MAGIC):
            return "java_serialized_base64"
        try:
            decoded = base64.b64decode(value[:128] + "==", validate=False)
            if decoded.startswith(b"\xac\xed\x00\x05"):
                return "java_serialized_binary"
        except Exception:
            pass
        if value.startswith(("gAS", "gAJ", "cos\n", "c__builtin__")):
            return "python_pickle"
        if value.startswith("/w"):
            return "aspnet_viewstate_like"
        return ""

    def _urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("with_params", "api", "auth"):
            urls.update(str(url) for url in classified.get(key, []) or [])
        urls.update(str(url) for url in self.fuzzer_results.get("all_endpoints", []) or [] if "?" in str(url))
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 100) -> str:
        idx = body.lower().find(marker.lower())
        if idx < 0:
            return body[:200]
        return body[max(0, idx - radius): idx + len(marker) + radius]

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            key = (
                finding.get("id", ""),
                finding.get("url", ""),
                finding.get("evidence", {}).get("param", finding.get("evidence", {}).get("signature", "")),
            )
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result

    def _finding(self, finding_id: str, severity: str, url: str, title: str, evidence: dict) -> dict:
        return {
            "source": self.name,
            "id": finding_id,
            "type": finding_id,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": "Serialized object markers or deserialization errors were observed.",
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/deserialization"],
            "confidence": 0.75,
        }
