"""
ReconX - Module: per-asset risk scoring and attack-surface ranking.

Aggregates signals from prior modules (recon, portscan, fuzzer, cve_check,
takeover_checker, active probes) into a single per-host risk score so triage
can start with the assets that matter most.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule


# Weights are tuned so that a single confirmed vuln on a live host already
# clears the HIGH tier; a clean live host stays in LOW.
WEIGHTS = {
    "confirmed_finding": 25,
    "candidate_finding": 6,
    "critical_severity": 10,
    "high_severity": 6,
    "medium_severity": 2,
    "exposed_admin": 12,
    "sensitive_file": 8,
    "open_port": 1,
    "high_risk_port": 8,
    "cve_hit": 7,
    "exploitdb_hit": 12,
    "takeover_signal": 30,
    "live_http": 2,
}

# Score → tier mapping. Tiers are deliberately wide; downstream UI just needs
# enough granularity to colour-code the table.
TIER_THRESHOLDS = [
    (80, "critical"),
    (50, "high"),
    (25, "medium"),
    (0,  "low"),
]


class AssetRiskModule(BaseModule):
    name = "asset_risk"
    description = "Per-Asset Risk Ranking"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 all_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.all_results = all_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("asset_risk", {})
        if not cfg.get("enabled", True):
            return {"ranked_assets": [], "total_assets": 0, "status": "disabled"}

        assets = self._enumerate_assets()
        if not assets:
            self.warn("No assets available for risk scoring")
            return {"ranked_assets": [], "total_assets": 0}

        ranked: list[dict] = []
        for host, ips in sorted(assets.items()):
            signals = self._collect_signals(host, ips)
            score = self._score(signals)
            ranked.append({
                "asset": host,
                "ips": sorted(ips),
                "score": score,
                "tier": self._tier(score),
                "signals": signals,
            })

        ranked.sort(key=lambda a: (-a["score"], a["asset"]))
        max_rows = int(cfg.get("max_rows", 200))
        ranked = ranked[:max_rows]

        self.save_json(ranked, "assets_ranked.json")
        crit = sum(1 for a in ranked if a["tier"] == "critical")
        high = sum(1 for a in ranked if a["tier"] == "high")
        if crit or high:
            self.warn(f"Asset risk: {crit} critical, {high} high")
        else:
            self.success(f"Asset risk: ranked {len(ranked)} assets")
        return {
            "ranked_assets": ranked,
            "total_assets": len(ranked),
            "tier_summary": {
                "critical": crit,
                "high": high,
                "medium": sum(1 for a in ranked if a["tier"] == "medium"),
                "low": sum(1 for a in ranked if a["tier"] == "low"),
            },
        }

    # ── Asset enumeration ─────────────────────────────────────────────────────

    def _enumerate_assets(self) -> dict[str, set[str]]:
        """Build {hostname: {ips}} from every recon signal we have."""
        hosts: dict[str, set[str]] = {}

        recon = self.all_results.get("recon", {}) or {}
        for entry in recon.get("live_subdomains", []) or []:
            host = (entry.get("subdomain") or "").lower()
            if not host:
                continue
            hosts.setdefault(host, set()).update(entry.get("ips") or [])

        # Fall back to resolved_hosts when live_subdomains is empty
        for line in recon.get("resolved_hosts", []) or []:
            parts = str(line).split()
            if not parts:
                continue
            host = parts[0].lower()
            for chunk in parts[1:]:
                ip = chunk.strip("[]")
                if self._looks_like_ip(ip):
                    hosts.setdefault(host, set()).add(ip)

        # Pull anything httpx confirmed live but recon missed
        for url in recon.get("live_http", []) or []:
            host = (urlparse(url).hostname or "").lower()
            if host:
                hosts.setdefault(host, set())

        for item in (self.all_results.get("webdetect", {}) or {}).get("live_hosts", []) or []:
            url = item.get("url") if isinstance(item, dict) else str(item)
            host = (urlparse(url or "").hostname or "").lower()
            if host:
                hosts.setdefault(host, set())
                ip = item.get("ip") if isinstance(item, dict) else ""
                if ip:
                    hosts[host].add(ip)

        return hosts

    # ── Per-asset signal extraction ───────────────────────────────────────────

    def _collect_signals(self, host: str, ips: set[str]) -> dict:
        ports = self._ports_for(ips)
        cve_hits, exploit_hits = self._cve_for(host)
        findings, confirmed, candidates, sev_counts = self._findings_for(host)
        return {
            "live": self._is_live(host),
            "open_ports": len(ports),
            "high_risk_ports": sorted({p["port"] for p in ports if p.get("high_risk")}),
            "port_services": [p.get("service", "") for p in ports if p.get("service")][:20],
            "cve_hits": cve_hits,
            "exploitdb_hits": exploit_hits,
            "findings_total": findings,
            "findings_confirmed": confirmed,
            "findings_candidate": candidates,
            "severity_counts": sev_counts,
            "exposed_admin": self._has_admin_exposure(host),
            "sensitive_files": self._sensitive_files_for(host),
            "takeover_candidate": self._has_takeover(host),
        }

    def _is_live(self, host: str) -> bool:
        recon = self.all_results.get("recon", {}) or {}
        for entry in recon.get("live_subdomains", []) or []:
            if (entry.get("subdomain") or "").lower() == host:
                return bool(entry.get("live"))
        # Fallback: any URL in live_http with this hostname counts
        for url in recon.get("live_http", []) or []:
            if (urlparse(url).hostname or "").lower() == host:
                return True
        return False

    def _ports_for(self, ips: set[str]) -> list[dict]:
        from modules.portscan import HIGH_RISK_PORTS
        result: list[dict] = []
        for entry in (self.all_results.get("portscan", {}) or {}).get("hosts", []) or []:
            if str(entry.get("ip", "")) not in ips:
                continue
            for port in entry.get("open_ports", []) or []:
                try:
                    pnum = int(port.get("port", 0))
                except (TypeError, ValueError):
                    continue
                result.append({
                    "port": pnum,
                    "service": port.get("service", ""),
                    "product": port.get("product", ""),
                    "high_risk": pnum in HIGH_RISK_PORTS,
                })
        return result

    def _cve_for(self, host: str) -> tuple[int, int]:
        cves = (self.all_results.get("cve_check", {}) or {}).get("cves", []) or []
        cve_count = 0
        exploit_count = 0
        for item in cves:
            url = item.get("matched_url") or item.get("url") or ""
            if (urlparse(url).hostname or "").lower() == host:
                cve_count += 1
                if item.get("exploit_available"):
                    exploit_count += 1
        return cve_count, exploit_count

    def _findings_for(self, host: str) -> tuple[int, int, int, dict[str, int]]:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        confirmed = candidates = total = 0

        for module_name, data in self.all_results.items():
            if not isinstance(data, dict):
                continue
            for f in (data.get("findings", []) or []):
                if not isinstance(f, dict):
                    continue
                url = f.get("url") or f.get("matched_url") or ""
                if (urlparse(url).hostname or "").lower() != host:
                    continue
                total += 1
                sev = str(f.get("severity", "INFO") or "INFO").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                verdict = f.get("verdict") or ""
                if verdict == "confirmed":
                    confirmed += 1
                elif verdict == "candidate":
                    candidates += 1

        return total, confirmed, candidates, sev_counts

    def _has_admin_exposure(self, host: str) -> bool:
        classified = (self.all_results.get("fuzzer", {}) or {}).get("classified", {}) or {}
        for url in classified.get("admin_panels", []) or []:
            if (urlparse(str(url)).hostname or "").lower() == host:
                return True
        return False

    def _sensitive_files_for(self, host: str) -> int:
        classified = (self.all_results.get("fuzzer", {}) or {}).get("classified", {}) or {}
        return sum(
            1 for url in classified.get("sensitive_files", []) or []
            if (urlparse(str(url)).hostname or "").lower() == host
        )

    def _has_takeover(self, host: str) -> bool:
        for f in (self.all_results.get("takeover_checker", {}) or {}).get("findings", []) or []:
            url = f.get("url") or ""
            evidence_host = (f.get("evidence", {}) or {}).get("host", "")
            if (
                (urlparse(url).hostname or "").lower() == host
                or str(evidence_host).lower() == host
            ):
                return True
        return False

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, s: dict) -> int:
        score = 0
        if s["live"]:
            score += WEIGHTS["live_http"]
        score += s["open_ports"] * WEIGHTS["open_port"]
        score += len(s["high_risk_ports"]) * WEIGHTS["high_risk_port"]
        score += s["cve_hits"] * WEIGHTS["cve_hit"]
        score += s["exploitdb_hits"] * WEIGHTS["exploitdb_hit"]
        score += s["findings_confirmed"] * WEIGHTS["confirmed_finding"]
        score += s["findings_candidate"] * WEIGHTS["candidate_finding"]
        sev = s["severity_counts"]
        score += sev.get("CRITICAL", 0) * WEIGHTS["critical_severity"]
        score += sev.get("HIGH", 0) * WEIGHTS["high_severity"]
        score += sev.get("MEDIUM", 0) * WEIGHTS["medium_severity"]
        if s["exposed_admin"]:
            score += WEIGHTS["exposed_admin"]
        score += min(s["sensitive_files"], 3) * WEIGHTS["sensitive_file"]
        if s["takeover_candidate"]:
            score += WEIGHTS["takeover_signal"]
        return score

    @staticmethod
    def _tier(score: int) -> str:
        for threshold, tier in TIER_THRESHOLDS:
            if score >= threshold:
                return tier
        return "low"

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
