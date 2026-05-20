from modules.asset_risk import AssetRiskModule


def _all_results():
    return {
        "recon": {
            "live_subdomains": [
                {"subdomain": "api.example.com", "live": True, "reasons": ["dns", "http"], "ips": ["192.0.2.10"]},
                {"subdomain": "static.example.com", "live": True, "reasons": ["http"], "ips": []},
                {"subdomain": "dead.example.com", "live": False, "reasons": [], "ips": []},
            ],
            "resolved_hosts": ["legacy.example.com [A] [198.51.100.5]"],
            "live_http": ["https://api.example.com", "https://static.example.com"],
        },
        "portscan": {
            "hosts": [
                {"ip": "192.0.2.10", "open_ports": [
                    {"port": 22, "service": "ssh"},
                    {"port": 443, "service": "https"},
                    {"port": 3306, "service": "mysql"},  # high-risk
                ]},
            ],
        },
        "cve_check": {
            "cves": [
                {"cve": "CVE-2024-0001", "matched_url": "https://api.example.com/", "exploit_available": True},
                {"cve": "CVE-2024-0002", "matched_url": "https://api.example.com/v1", "exploit_available": False},
            ],
        },
        "xss": {
            "findings": [
                {
                    "url": "https://api.example.com/?q=x",
                    "severity": "HIGH",
                    "verdict": "confirmed",
                    "evidence": {"poc": "<script>"},
                },
            ],
        },
        "sql_injection": {
            "findings": [
                {
                    "url": "https://api.example.com/?id=1",
                    "severity": "HIGH",
                    "verdict": "candidate",
                    "evidence": {"param": "id"},
                },
            ],
        },
        "fuzzer": {
            "classified": {
                "admin_panels": ["https://api.example.com/admin"],
                "sensitive_files": [
                    "https://api.example.com/.env",
                    "https://api.example.com/backup.zip",
                ],
            },
        },
        "takeover_checker": {
            "findings": [
                {"url": "https://dead.example.com", "evidence": {"host": "dead.example.com"}, "severity": "HIGH"},
            ],
        },
    }


def test_asset_risk_ranks_api_above_static_and_dead(tmp_path):
    module = AssetRiskModule("example.com", str(tmp_path), {}, all_results=_all_results())

    result = module.run()

    ranked = result["ranked_assets"]
    assert result["total_assets"] >= 4
    # Highest-scoring asset is the one with cve + confirmed finding + admin + sensitive
    assert ranked[0]["asset"] == "api.example.com"
    assert ranked[0]["tier"] in ("critical", "high")
    # api signals must surface the joined data
    api = ranked[0]["signals"]
    assert api["open_ports"] == 3
    assert 3306 in api["high_risk_ports"]
    assert api["cve_hits"] == 2
    assert api["exploitdb_hits"] == 1
    assert api["findings_confirmed"] == 1
    assert api["findings_candidate"] == 1
    assert api["exposed_admin"] is True
    assert api["sensitive_files"] == 2
    # Takeover is on dead.example.com
    by_host = {a["asset"]: a for a in ranked}
    assert by_host["dead.example.com"]["signals"]["takeover_candidate"] is True
    # Static host with no findings stays in lower tiers
    assert by_host["static.example.com"]["tier"] in ("low", "medium")


def test_asset_risk_returns_empty_when_no_assets(tmp_path):
    module = AssetRiskModule("example.com", str(tmp_path), {}, all_results={})
    result = module.run()
    assert result["ranked_assets"] == []
    assert result["total_assets"] == 0


def test_asset_risk_disabled_via_config(tmp_path):
    module = AssetRiskModule(
        "example.com",
        str(tmp_path),
        {"scan": {"asset_risk": {"enabled": False}}},
        all_results=_all_results(),
    )
    result = module.run()
    assert result["status"] == "disabled"
    assert result["ranked_assets"] == []


def test_asset_risk_persists_json(tmp_path):
    module = AssetRiskModule("example.com", str(tmp_path), {}, all_results=_all_results())
    module.run()
    assert (tmp_path / "asset_risk" / "assets_ranked.json").exists()
