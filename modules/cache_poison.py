"""
ReconX - Module: web cache poisoning indicators.
"""

import time
import uuid

import requests

from modules.base import BaseModule


CACHE_HEADERS = [
    "Age", "X-Cache", "CF-Cache-Status", "X-Varnish", "X-Cache-Hits",
    "X-Served-By", "Via", "X-Cache-Status", "Surrogate-Key", "X-Proxy-Cache",
]


class CachePoisonModule(BaseModule):
    name = "cache_poison"
    description = "Web Cache Poisoning Detection"
    required_tools: list[str] = []

    HEADER_PROBES = [
        ("X-Forwarded-Host", "host override"),
        ("X-Host", "host override"),
        ("X-Forwarded-Server", "server override"),
        ("X-Original-Host", "original host override"),
        ("X-HTTP-Host-Override", "host override"),
        ("Forwarded", "forwarded host override"),
        ("X-Forwarded-Prefix", "prefix injection"),
        ("X-Original-URL", "original URL injection"),
        ("X-Rewrite-URL", "rewrite URL injection"),
    ]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.marker = f"reconx-cp-{uuid.uuid4().hex[:8]}.invalid"

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("cache_poison", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        urls = self._extract_urls()[: int(cfg.get("max_urls", 60))]
        if not urls:
            self.warn("No URLs for cache poisoning checks")
            return {"findings": [], "total": 0}

        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"

        findings: list[dict] = []
        for url in urls:
            cache_info = self._cache_info(url, session, cfg)
            for header, desc in self.HEADER_PROBES[: int(cfg.get("max_headers", len(self.HEADER_PROBES)))]:
                finding = self._probe_header(url, session, cfg, cache_info, header, desc)
                if finding:
                    findings.append(finding)
            for finding in self._probe_fat_get(url, session, cfg, cache_info):
                findings.append(finding)
            for finding in self._probe_cookie(url, session, cfg, cache_info):
                findings.append(finding)

        findings = self._dedup(findings)
        self.save_json(findings, "cache_poison_findings.json")
        return {"findings": findings, "total": len(findings)}

    def _probe_header(self, url: str, session: requests.Session, cfg: dict, cache_info: dict,
                      header: str, desc: str) -> dict | None:
        baseline = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
        baseline_body = baseline.text or "" if baseline else ""
        value = f"{header.lower().replace('_', '-')}.{self.marker}" if header != "Forwarded" else f"host={self.marker}"
        probe = self.http_get(
            url,
            session=session,
            headers={header: value, "Cache-Control": "no-cache"},
            timeout=float(cfg.get("timeout", 10)),
            verify=False,
        )
        if probe is None:
            return None
        location = probe.headers.get("Location", "")
        body = probe.text or ""
        reflected = (self.marker in body and self.marker not in baseline_body) or self.marker in location
        if not reflected:
            return None

        cache_confirmed = False
        if cache_info.get("cache_detected") and cfg.get("confirm_cache", False):
            time.sleep(float(cfg.get("cache_wait", 1)))
            clean = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
            clean_text = (clean.text or "") if clean else ""
            cache_confirmed = self.marker in clean_text

        return self._finding(
            "cache_poisoning_unkeyed_header",
            "CRITICAL" if cache_confirmed else "HIGH",
            url,
            f"Unkeyed header reflected in response: {header}",
            {
                "header": header,
                "value": value,
                "description": desc,
                "reflected": True,
                "cache_confirmed": cache_confirmed,
                "cache_info": cache_info,
                "location": location[:300],
                "excerpt": self._excerpt(body, self.marker),
            },
        )

    def _probe_fat_get(self, url: str, session: requests.Session, cfg: dict, cache_info: dict) -> list[dict]:
        findings: list[dict] = []
        for name in ("reconx_fat", "utm_content", "_"):
            probe_url = url + ("&" if "?" in url else "?") + f"{name}={self.marker}"
            if not self.is_in_scope(probe_url):
                continue
            resp = self.http_get(probe_url, session=session, timeout=float(cfg.get("timeout", 10)), verify=False)
            if resp and self.marker in (resp.text or ""):
                findings.append(self._finding("cache_poisoning_fat_get", "HIGH", url, "Unkeyed query parameter reflected", {
                    "probe_url": probe_url,
                    "param": name,
                    "cache_info": cache_info,
                    "excerpt": self._excerpt(resp.text or "", self.marker),
                }))
                break
        return findings

    def _probe_cookie(self, url: str, session: requests.Session, cfg: dict, cache_info: dict) -> list[dict]:
        cookie = f"reconx_probe={self.marker}"
        resp = self.http_get(url, session=session, headers={"Cookie": cookie}, timeout=float(cfg.get("timeout", 10)), verify=False)
        if resp and self.marker in (resp.text or ""):
            return [self._finding("cache_poisoning_unkeyed_cookie", "HIGH", url, "Cookie value reflected in cacheable response", {
                "cookie": cookie,
                "cache_info": cache_info,
                "excerpt": self._excerpt(resp.text or "", self.marker),
            })]
        return []

    def _cache_info(self, url: str, session: requests.Session, cfg: dict) -> dict:
        resp = self.http_get(url, session=session, timeout=float(cfg.get("timeout", 8)), verify=False)
        if resp is None:
            return {"cache_detected": False, "headers": {}}
        headers = {name: resp.headers.get(name, "") for name in CACHE_HEADERS if resp.headers.get(name)}
        cc = resp.headers.get("Cache-Control", "")
        if cc:
            headers["Cache-Control"] = cc
        return {
            "cache_detected": bool(headers) or any(token in cc.lower() for token in ("public", "max-age", "s-maxage")),
            "headers": headers,
        }

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        urls.update(self.load_lines(self.session_path("webdetect", "live_urls.txt")))
        return self.filter_in_scope_urls(urls)

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
            key = (
                finding.get("id", ""),
                finding.get("url", ""),
                finding.get("evidence", {}).get("header", finding.get("evidence", {}).get("param", "")),
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
            "description": (
                "An attacker-controlled unkeyed input is reflected in a response that may be cached. "
                "If the response is cacheable, this can lead to web cache poisoning."
            ),
            "evidence": evidence,
            "references": ["https://portswigger.net/research/practical-web-cache-poisoning"],
            "confidence": 0.9 if evidence.get("cache_confirmed") else 0.7,
        }
