"""
ReconX - Module: race-condition candidate detection and optional duplicate probes.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from modules.base import BaseModule


RACE_KEYWORDS = (
    "checkout", "payment", "pay", "purchase", "order", "redeem", "coupon",
    "promo", "discount", "wallet", "transfer", "withdraw", "balance", "invite",
)


class RaceConditionModule(BaseModule):
    name = "race_condition"
    description = "Race Condition Candidate Detection"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        fuzzer_results: dict | None = None,
        openapi_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("race_condition", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        candidates = self._candidates()[: int(cfg.get("max_targets", 80))]
        findings = [
            self._finding("race_condition_candidate", "INFO", item["url"], "Race-sensitive endpoint candidate", item)
            for item in candidates
        ]

        active_findings: list[dict] = []
        if cfg.get("active_probe", False) and self.config.get("scan", {}).get("allow_write", False):
            active_findings = self._active_probe(candidates[: int(cfg.get("max_active_targets", 5))], cfg)
            findings.extend(active_findings)

        self.save_json(candidates, "race_candidates.json")
        self.save_json(findings, "race_findings.json")
        return {
            "findings": findings,
            "total": len(findings),
            "candidates": len(candidates),
            "active_findings": len(active_findings),
        }

    def _candidates(self) -> list[dict]:
        urls: set[str] = set()
        classified = self.fuzzer_results.get("classified", {}) or {}
        for key in ("api", "auth", "with_params"):
            urls.update(str(url) for url in classified.get(key, []) or [])
        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if isinstance(endpoint, dict) and endpoint.get("url"):
                urls.add(endpoint["url"])
        result = []
        for url in self.filter_in_scope_urls(urls):
            lowered = (urlparse(url).path + "?" + urlparse(url).query).lower()
            matched = [keyword for keyword in RACE_KEYWORDS if keyword in lowered]
            if matched:
                result.append({"url": url, "matched_keywords": matched[:8]})
        return result

    def _active_probe(self, candidates: list[dict], cfg: dict) -> list[dict]:
        findings: list[dict] = []
        workers = int(cfg.get("parallel_requests", 2))
        for item in candidates:
            url = item["url"]
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(self.http_get, url, timeout=float(cfg.get("timeout", 8)), verify=False)
                    for _ in range(workers)
                ]
                responses = [future.result() for future in as_completed(futures)]
            statuses = [resp.status_code for resp in responses if resp is not None]
            if len(statuses) >= 2 and len(set(statuses)) == 1 and statuses[0] in (200, 201, 202):
                findings.append(self._finding("race_condition_duplicate_success", "MEDIUM", url, "Duplicate parallel requests returned success", {
                    **item,
                    "parallel_requests": workers,
                    "statuses": statuses,
                }))
        return findings

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
                "Endpoint path suggests race-sensitive business logic such as payment, "
                "coupon redemption, wallet transfer, or account state changes."
            ),
            "evidence": evidence,
            "references": ["https://portswigger.net/web-security/race-conditions"],
            "confidence": 0.6 if finding_id.endswith("candidate") else 0.75,
        }
