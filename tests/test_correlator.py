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


def test_correlator_flags_exposed_datastore_with_no_auth_evidence(tmp_path):
    module = CorrelatorModule(
        "example.com",
        str(tmp_path),
        {},
        all_results={
            "portscan": {
                "hosts": [{
                    "ip": "192.0.2.10",
                    "open_ports": [{
                        "port": 6379,
                        "service": "redis",
                        "extrainfo": "no authentication required",
                    }],
                }]
            }
        },
    )

    finding = module._rule_exposed_datastore()

    assert finding["rule_id"] == "exposed_datastore_no_auth_indicators"
    assert finding["severity"] == "HIGH"


def test_correlator_flags_exposed_docker_api_fingerprint(tmp_path):
    module = CorrelatorModule(
        "example.com",
        str(tmp_path),
        {},
        all_results={
            "portscan": {
                "hosts": [{
                    "ip": "192.0.2.10",
                    "open_ports": [{"port": 2375, "service": "docker"}],
                }]
            },
            "fuzzer": {
                "findings": [{
                    "url": "http://192.0.2.10:2375/version",
                    "evidence": {"body": '{"message":"page not found"}'},
                }]
            },
        },
    )

    finding = module._rule_docker_api_exposed()

    assert finding["rule_id"] == "docker_api_exposed"
    assert finding["severity"] == "CRITICAL"


def test_correlator_flags_high_confidence_takeover(tmp_path):
    module = CorrelatorModule(
        "example.com",
        str(tmp_path),
        {},
        all_results={
            "takeover_checker": {
                "findings": [{
                    "url": "https://docs.example.com",
                    "severity": "HIGH",
                    "provider": "github_pages",
                    "confidence": 0.85,
                    "evidence": {
                        "host": "docs.example.com",
                        "cnames": ["docs.github.io"],
                        "body_fingerprint": "There isn't a GitHub Pages site here",
                    },
                }]
            }
        },
    )

    finding = module._rule_high_confidence_takeover()

    assert finding["rule_id"] == "high_confidence_subdomain_takeover"
    assert finding["severity"] == "CRITICAL"
