"""
ReconX - Module: unsafe deserialization indicators.
"""

import re
from urllib.parse import parse_qsl, unquote, urlparse

import requests

from modules.base import BaseModule


JAVA_MAGIC = "rO0AB"
DOTNET_VIEWSTATE_RE = re.compile(r'name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']+)', re.I)
# Generic hidden-input scanning: grab each <input> tag, then its attributes in
# any order (serialized blobs are quoted because they contain reserved chars).
_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_RE = re.compile(r'([\w:-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\')')
# ASP.NET state fields handled by the dedicated ViewState check below — don't
# also report them via the generic hidden-field scan.
ASP_NET_STATE_FIELDS = {
    "__viewstate", "__viewstategenerator", "__eventvalidation", "__viewstateencrypted",
}
# PHP serialize signatures: object O:N:"ClassName":..., array a:N:{}, string s:N:"..."
PHP_SERIALIZE_RE = re.compile(r'^(?:O:\d+:"|a:\d+:\{|s:\d+:")')
# Ruby Marshal binary header: \x04\x08 followed by Marshal type byte.
# Ruby Marshal hex-base64 starts with "BAg" (base64 of \x04\x08).
RUBY_MARSHAL_PREFIXES = ("BAg",)
# Node.js node-serialize signature — starts with _$$ND_FUNC$$_ for function payloads.
NODE_SERIALIZE_MARK = "_$$ND_FUNC$$_"
ERROR_SIGNATURES = (
    # Java
    "java.io.ObjectInputStream", "StreamCorruptedException", "InvalidClassException",
    "ClassNotFoundException", "OptionalDataException", "NotSerializableException",
    # ASP.NET ViewState / LosFormatter / BinaryFormatter
    "ViewStateException", "Validation of viewstate MAC failed",
    "LosFormatter", "ObjectStateFormatter", "BinaryFormatter",
    # Python
    "pickle.UnpicklingError", "_pickle.UnpicklingError",
    "yaml.constructor", "yaml.YAMLError",
    "ModuleNotFoundError: No module named",
    "jsonpickle.unpickler",
    # PHP
    "PHP Notice:  unserialize()", "PHP Warning:  unserialize()",
    "unserialize(): Error at offset",
    # Ruby
    "Marshal.load", "Psych::SyntaxError",
    # Node.js
    "node-serialize", "SyntaxError: Unexpected token in JSON",
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

        # Cookies are the most common carrier of serialized objects (Java/PHP
        # session state, Rails Marshal, .NET auth tickets) — scan them.
        self._scan_cookies(resp, url, findings)

        body = resp.text or ""
        viewstate = DOTNET_VIEWSTATE_RE.search(body)
        if viewstate:
            value = viewstate.group(1)
            evidence = {"field": "__VIEWSTATE", "value_length": len(value), "value_prefix": value[:32]}
            if value.startswith("/wE"):
                evidence["format"] = "ASP.NET LosFormatter"
            findings.append(self._finding("aspnet_viewstate_detected", "INFO", url, "ASP.NET ViewState detected", evidence))

        # Hidden form fields can carry serialized blobs the app deserializes on
        # POST (beyond the ASP.NET __VIEWSTATE handled above).
        self._scan_hidden_fields(body, url, findings)

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
        # Java — base64-encoded ObjectOutputStream. Java serialized data always
        # begins with the magic AC ED 00 05, which base64-encodes to "rO0AB", so
        # this prefix covers every base64 Java blob (URL-safe or standard).
        if value.startswith(JAVA_MAGIC):
            return "java_serialized_base64"
        # Python pickle — common base64-encoded markers + bare cos\n header
        if value.startswith(("gAS", "gAJ", "gAR", "cos\n", "c__builtin__", "ccopy_reg")):
            return "python_pickle"
        # ASP.NET ViewState — LosFormatter/ObjectStateFormatter output begins with
        # the bytes \xff\x01 (version marker), which base64-encode to "/wE". The
        # looser "/w" prefix only pins the first byte (0xFF) and matches arbitrary
        # base64, so it is too noisy for a HIGH finding.
        if value.startswith("/wE"):
            return "aspnet_viewstate_like"
        # PHP serialize() — O:N:"X":, a:N:{, s:N:"
        if PHP_SERIALIZE_RE.match(value):
            return "php_serialized"
        # Ruby Marshal — \x04\x08 header (base64 "BAg")
        if any(value.startswith(prefix) for prefix in RUBY_MARSHAL_PREFIXES):
            return "ruby_marshal"
        # Node.js node-serialize package
        if NODE_SERIALIZE_MARK in value:
            return "node_serialize_function"
        return ""

    def _scan_cookies(self, resp, url: str, findings: list) -> None:
        try:
            cookies = list(resp.cookies)
        except Exception:
            return
        for cookie in cookies:
            raw = getattr(cookie, "value", "") or ""
            # Try the raw value and its URL-decoded form (serialized cookies are
            # frequently percent-encoded).
            for candidate in (raw, unquote(raw)):
                marker = self._serialized_marker(candidate)
                if marker:
                    findings.append(self._finding(
                        "serialized_object_in_cookie", "HIGH", url,
                        "Serialized object marker in cookie",
                        {"cookie": getattr(cookie, "name", ""), "marker": marker,
                         "value_prefix": candidate[:24]},
                    ))
                    break

    def _scan_hidden_fields(self, body: str, url: str, findings: list) -> None:
        for tag in _INPUT_TAG_RE.findall(body):
            attrs: dict[str, str] = {}
            for m in _ATTR_RE.finditer(tag):
                attrs[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
            if attrs.get("type", "").lower() != "hidden":
                continue
            name = attrs.get("name", "")
            if name.lower() in ASP_NET_STATE_FIELDS:
                continue
            value = attrs.get("value", "")
            marker = self._serialized_marker(value)
            if marker:
                findings.append(self._finding(
                    "serialized_object_in_hidden_field", "HIGH", url,
                    "Serialized object marker in hidden form field",
                    {"field": name, "marker": marker, "value_prefix": value[:24]},
                ))

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
            ev = finding.get("evidence", {}) or {}
            location = (ev.get("param") or ev.get("cookie") or ev.get("field")
                        or ev.get("signature") or "")
            key = (finding.get("id", ""), finding.get("url", ""), location)
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
