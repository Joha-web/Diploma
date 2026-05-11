from modules.cve_check import CVECheckModule


def test_collect_cves_from_vulnscan_and_cms(tmp_path):
    module = CVECheckModule(
        "example.com",
        str(tmp_path),
        {},
        vuln_results={"findings": [{
            "name": "Test CVE-2024-12345",
            "severity": "HIGH",
            "matched_url": "https://example.com",
            "template_id": "cves/test",
        }]},
        all_results={"cmscan": {"scans": [{
            "url": "https://example.com",
            "findings": [{"title": "Plugin CVE-2023-9999", "severity": "MEDIUM"}],
        }]}},
    )

    cves = module._collect_cves_from_findings()

    assert "CVE-2024-12345" in cves
    assert "CVE-2023-9999" in cves


def test_dry_run_simulation_never_attempts_attack():
    sim = CVECheckModule._dry_run_simulation("CVE-2024-12345", True, {"matched_url": "https://example.com"})

    assert sim["mode"] == "dry_run"
    assert sim["attempted"] is False
    assert sim["auto_exploit"] is False
