"""
Shared base class for low-impact active probes.
"""

from __future__ import annotations

import random
import time
from urllib.parse import parse_qsl, urlparse

from modules.base import BaseModule
from modules.finding_registry import build_finding


class ActiveProbeBase(BaseModule):
    """Base class for probes that need consistent safety and evidence output."""

    default_timeout = 10.0

    def module_config(self) -> dict:
        scan_cfg = self.config.get("scan", {})
        cfg = scan_cfg.get(self.name, {}) if isinstance(scan_cfg, dict) else {}
        return cfg if isinstance(cfg, dict) else {}

    def active_enabled(self) -> bool:
        return self.module_config().get("enabled", True) is not False

    def request_timeout(self) -> float:
        cfg = self.module_config()
        scan_cfg = self.config.get("scan", {})
        return float(cfg.get("timeout", scan_cfg.get("timeout", self.default_timeout)))

    def limit(self, items, key: str, default: int):
        value = int(self.module_config().get(key, default))
        return list(items)[: max(0, value)]

    def jitter_sleep(self) -> None:
        cfg = self.module_config()
        jitter = float(cfg.get("jitter", 0))
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))

    def auth_profiles(self) -> dict:
        profiles = self.config.get("auth_profiles")
        if profiles is None:
            profiles = self.config.get("scan", {}).get("auth_profiles", {})
        return profiles if isinstance(profiles, dict) else {}

    def profile(self, name: str) -> dict:
        if name == "anonymous":
            return {}
        value = self.auth_profiles().get(name, {})
        return value if isinstance(value, dict) else {}

    def profile_headers(self, name: str) -> dict:
        profile = self.profile(name)
        headers = dict(profile.get("headers", {}) or {})
        token = str(profile.get("token", "") or "").strip()
        if token and "Authorization" not in headers:
            token_type = str(profile.get("token_type", "Bearer") or "").strip()
            if token.lower().startswith(("bearer ", "basic ", "token ")):
                headers["Authorization"] = token
            elif token_type:
                headers["Authorization"] = f"{token_type} {token}"
            else:
                headers["Authorization"] = token

        cookies = profile.get("cookies", {}) or {}
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return headers

    def configured_profile_names(self) -> list[str]:
        names = ["anonymous"]
        names.extend(sorted(name for name in self.auth_profiles() if name != "anonymous"))
        return names

    def profile_names_with_auth(self) -> list[str]:
        names = []
        for name in self.configured_profile_names():
            if name == "anonymous":
                continue
            if self.profile_headers(name):
                names.append(name)
        return names

    def get_with_profile(self, url: str, profile_name: str, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self.profile_headers(profile_name))
        return self.http_get(url, headers=headers, **kwargs)

    def post_with_profile(self, url: str, profile_name: str, safe_readonly: bool = True, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self.profile_headers(profile_name))
        return self.http_post(url, headers=headers, safe_readonly=safe_readonly, **kwargs)

    def make_finding(
        self,
        finding_id: str,
        url: str = "",
        evidence: dict | None = None,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        confidence: float | None = None,
        references: list[str] | None = None,
        finding_type: str | None = None,
        tags: list[str] | None = None,
        exploitability: str | float | None = None,
        asset_criticality: float | None = None,
    ) -> dict:
        return build_finding(
            source=self.name,
            finding_id=finding_id,
            url=url,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            confidence=confidence,
            references=references,
            finding_type=finding_type,
            tags=tags,
            exploitability=exploitability,
            asset_criticality=asset_criticality,
        )

    @staticmethod
    def dedup_findings(findings: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for finding in findings:
            evidence = finding.get("evidence", {}) or {}
            key = (
                str(finding.get("id", "")),
                str(finding.get("url", "") or finding.get("matched_url", "")),
                str(evidence.get("param") or evidence.get("path") or evidence.get("sink") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return result

    def collect_live_urls(self, live_hosts: list | None = None) -> list[str]:
        urls: set[str] = set()
        for item in live_hosts or []:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        urls.update(self.load_lines(self.session_path("webdetect", "live_urls.txt")))
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def query_pairs(url: str) -> list[tuple[str, str]]:
        parsed = urlparse(str(url or ""))
        return parse_qsl(parsed.query, keep_blank_values=True)

    @staticmethod
    def base_url(url: str) -> str:
        parsed = urlparse(str(url or ""))
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"
