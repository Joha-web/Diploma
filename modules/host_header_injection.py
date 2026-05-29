"""
ReconX - Module: Host header injection and reset poisoning indicators.
"""

import uuid
from urllib.parse import urlparse

import requests

from modules.base import BaseModule


RESET_KEYWORDS = ("reset", "forgot", "password", "recover", "account")

# Contexts where reflected Host shows up via routine framework URL generation rather than
# user-visible actionable links. These do not constitute an exploitable host header injection
# on their own and should be reported at LOW severity.
LOW_RISK_REFLECTION_CONTEXTS = (
    "rel=\"manifest\"",
    "rel='manifest'",
    "rel=manifest",
    "rel=\"canonical\"",
    "rel='canonical'",
    "rel=canonical",
    "rel=\"alternate\"",
    "rel='alternate'",
    "property=\"og:url\"",
    "property='og:url'",
    "name=\"twitter:url\"",
    "name='twitter:url'",
    "apple-mobile-web-app",
    "rel=\"apple-touch-icon\"",
    "rel='apple-touch-icon'",
    "rel=\"icon\"",
    "rel='icon'",
    "rel=\"shortcut icon\"",
    "rel='shortcut icon'",
    "rel=\"stylesheet\"",
    "rel='stylesheet'",
    "<base href=",
)


class HostHeaderInjectionModule(BaseModule):
    name = "host_header_injection"
    description = "Host Header Injection / Password Reset Poisoning"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None,
                 fuzzer_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.fuzzer_results = fuzzer_results or {}
        self.marker = f"reconx-host-{uuid.uuid4().hex[:8]}.invalid"

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("host_header_injection", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        targets = self._targets()[: int(cfg.get("max_urls", 80))]
        if not targets:
            self.warn("No URLs for Host header injection checks")
            return {"findings": [], "total": 0}

        session = requests.Session()
        session.verify = False
        findings: list[dict] = []
        for url in targets:
            findings.extend(self._probe(url, session, cfg))

        findings = self._dedup(findings)
        self.save_json(findings, "host_header_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _probe(self, url: str, session: requests.Session, cfg: dict) -> list[dict]:
        findings: list[dict] = []
        parsed = urlparse(url)
        if not parsed.hostname:
            return findings
        legitimate_host = parsed.hostname
        # Header sets sourced from PayloadsAllTheThings/Host Header Injection. Each
        # set tries a different way servers/proxies might be tricked into using the
        # attacker-supplied host (marker) instead of the legitimate one. Only sets
        # that carry the marker can produce a confirmed reflection finding.
        header_sets = [
            # Single-header override variants
            {"Host": self.marker},
            {"X-Forwarded-Host": self.marker},
            {"X-Host": self.marker},
            {"X-Original-Host": self.marker},
            {"X-Forwarded-Server": self.marker},
            {"X-HTTP-Host-Override": self.marker},
            {"Forwarded": f"host={self.marker}"},      # RFC 7239
            {"X-Forwarded-For": self.marker},
            {"X-Real-IP": self.marker},
            # Combined override — proxies that take the first explicit override header.
            {"Host": legitimate_host, "X-Forwarded-Host": self.marker},
            {"Host": legitimate_host, "X-Forwarded-Host": f"{self.marker}, {legitimate_host}"},
            # Host-with-port variant — some routers parse only the hostname part.
            {"Host": f"{self.marker}:80"},
            # Two Host headers (HTTP/1.1 multi-header confusion). requests will join
            # with comma; many gateways accept and split on the first.
            {"Host": f"{legitimate_host}, {self.marker}"},
            # NOTE: X-Forwarded-Proto: http is intentionally excluded — it does
            # not carry the random marker so it can never trigger a confirmed finding.
        ]
        baseline = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        baseline_text = (baseline.text or "") if baseline else ""
        for headers in header_sets:
            resp = self.http_get(
                url, session=session, headers=headers, allow_redirects=False,
                timeout=float(cfg.get("timeout", 10)), verify=False,
            )
            if resp is None:
                continue
            body = resp.text or ""
            location = resp.headers.get("Location", "")
            evidence = {
                "headers": headers,
                "status_code": resp.status_code,
                "location": location[:300],
                "marker": self.marker,
            }
            if self.marker in location:
                findings.append(self._finding("host_header_redirect", "HIGH", url, "Host header reflected in redirect Location", evidence))
            elif self.marker in body and self.marker not in baseline_text:
                excerpt = self._excerpt(body, self.marker)
                evidence["excerpt"] = excerpt
                is_reset = self._looks_like_reset(url)
                low_risk = self._reflection_is_low_risk(body, self.marker)
                evidence["low_risk_context"] = low_risk
                if is_reset:
                    severity = "HIGH"
                    finding_id = "password_reset_poisoning_indicator"
                    title = "Password reset poisoning indicator"
                elif low_risk:
                    # Reflection only in benign URL-generation contexts (PWA manifest,
                    # canonical, og:url, favicon, etc.). Not exploitable on its own.
                    severity = "LOW"
                    finding_id = "host_header_reflection_low"
                    title = "Host header reflected in non-actionable URL context"
                else:
                    severity = "MEDIUM"
                    finding_id = "host_header_reflection"
                    title = "Host header reflected in response body"
                findings.append(self._finding(finding_id, severity, url, title, evidence))
        return findings

    def _targets(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("auth", "with_params"):
            urls.update(str(url) for url in classified.get(key, []) or [])
        urls.update(self.load_lines(self.session_path("webdetect", "live_urls.txt")))
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def _looks_like_reset(url: str) -> bool:
        lowered = url.lower()
        return any(keyword in lowered for keyword in RESET_KEYWORDS)

    @staticmethod
    def _reflection_is_low_risk(body: str, marker: str) -> bool:
        """Return True if EVERY occurrence of the marker is inside a benign URL context.

        We scan a small window (~200 chars before each match) for known low-risk tags such
        as PWA manifest, canonical URLs, favicons, og:url, base href. If at least one match
        is in a non-trivial context (form action, fetch URL, plain body text, etc.) we keep
        the higher MEDIUM severity.
        """
        body_l = body.lower()
        m = marker.lower()
        idx = 0
        any_match = False
        while True:
            pos = body_l.find(m, idx)
            if pos < 0:
                break
            any_match = True
            window = body_l[max(0, pos - 250): pos]
            if not any(token in window for token in LOW_RISK_REFLECTION_CONTEXTS):
                return False
            idx = pos + len(m)
        return any_match

    @staticmethod
    def _excerpt(body: str, marker: str, radius: int = 100) -> str:
        idx = body.find(marker)
        if idx < 0:
            return body[:200]
        return body[max(0, idx - radius): idx + len(marker) + radius]

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            key = (finding.get("id", ""), finding.get("url", ""), str(finding.get("evidence", {}).get("headers", {})))
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
            "description": (
                "The application appears to trust attacker-controlled host override headers. "
                "On account recovery flows this can enable password reset poisoning."
            ),
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/host-header"],
            "confidence": 0.8,
        }
