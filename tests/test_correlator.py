from modules.correlator import CorrelatorModule


def test_correlator_flags_admin_port_no_waf_cve_chain(tmp_path):
    module = CorrelatorModule(
        "example.com",
        str(tmp_path),
        {},
        all_results={
            "fuzzer": {"classified": {"admin_panels": ["/admin"]}},
            "portscan": {
                "hosts": [{
                    "ip": "192.0.2.10",
                    "open_ports": [{"port": 8080, "service": "http-proxy"}],
                }]
            },
            "techstack": {"hosts": [{"url": "https://example.com", "waf": [], "technologies": []}]},
            "cve_check": {
                "cves": [{
                    "cve": "CVE-2024-0001",
                    "severity": "HIGH",
                    "matched_url": "https://example.com",
                    "exploit_available": True,
                }]
            },
        },
    )

    result = module.run()

    assert result["total"] == 1
    assert result["findings"][0]["rule_id"] == "admin_panel_exposed_port_no_waf_cve"
    assert result["findings"][0]["severity"] == "HIGH"


def test_correlator_skips_admin_chain_when_waf_exists(tmp_path):
    module = CorrelatorModule(
        "example.com",
        str(tmp_path),
        {},
        all_results={
            "fuzzer": {"classified": {"admin_panels": ["/admin"]}},
            "portscan": {"hosts": [{"ip": "192.0.2.10", "open_ports": [{"port": 8080}]}]},
            "techstack": {"hosts": [{"waf": ["Cloudflare"], "technologies": []}]},
            "cve_check": {"cves": [{"cve": "CVE-2024-0001"}]},
        },
    )

    assert module._rule_admin_port_no_waf_cve() is None
