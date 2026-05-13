import json

from reporting.json_report import build_results_diff, generate_json_report


def test_build_results_diff_reports_new_assets_and_findings():
    previous = {
        "recon": {"subdomains": ["old.example.com"]},
        "webdetect": {"live_urls": ["https://old.example.com"]},
        "portscan": {"hosts": [{"ip": "192.0.2.1", "open_ports": [{"port": 80}]}]},
        "vulnscan": {"findings": [{"template_id": "old", "matched_url": "https://old.example.com"}]},
    }
    current = {
        "recon": {
            "subdomains": ["new.example.com"],
            "email_security": {"findings": [{"id": "missing_spf"}]},
        },
        "webdetect": {"live_urls": ["https://new.example.com"]},
        "portscan": {"hosts": [{"ip": "192.0.2.1", "open_ports": [{"port": 443}]}]},
        "vulnscan": {"findings": [{"template_id": "new", "matched_url": "https://new.example.com"}]},
    }

    diff = build_results_diff(previous, current)

    assert diff["new_subdomains"] == ["new.example.com"]
    assert diff["new_open_ports"] == ["192.0.2.1:443"]
    assert "vulnscan:new:https://new.example.com" in diff["new_findings"]
    assert "recon:missing_spf:" in diff["new_findings"]


def test_json_report_exports_new_finding_sources_and_assets(tmp_path):
    report_path = generate_json_report(
        tmp_path,
        "example.com",
        {
            "recon": {
                "subdomains_total": 1,
                "resolved_ips": ["192.0.2.10"],
                "scan_ips": ["198.51.100.20"],
                "email_security": {
                    "findings": [{
                        "id": "missing_spf",
                        "title": "Email spoofing possible",
                        "severity": "MEDIUM",
                    }]
                },
            },
            "webdetect": {
                "live_urls": ["https://example.com"],
                "screenshots": [{"relative_path": "webdetect/screenshots/example.png"}],
            },
            "fuzzer": {
                "total_endpoints": 1,
                "cloud_assets": [{"provider": "aws_s3", "bucket": "assets-example"}],
                "graphql_details": [{"endpoint": "https://example.com/graphql"}],
                "findings": [{
                    "id": "public_cloud_storage_listing",
                    "title": "Public cloud storage listing exposed",
                    "severity": "CRITICAL",
                    "url": "https://assets-example.s3.amazonaws.com/",
                }],
            },
            "correlator": {
                "total": 1,
                "findings": [{
                    "id": "admin_panel_exposed_port_no_waf_cve",
                    "title": "Admin surface exposed",
                    "severity": "HIGH",
                }],
            },
        },
        "0m 1s",
    )

    report = json.loads(open(report_path, encoding="utf-8").read())
    ids = {finding["id"] for finding in report["findings"]}

    assert "missing_spf" in ids
    assert "public_cloud_storage_listing" in ids
    assert "admin_panel_exposed_port_no_waf_cve" in ids
    assert report["summary"]["live_hosts"] == 1
    assert report["summary"]["correlated_findings"] == 1
    assert report["assets"]["scan_ips"] == ["198.51.100.20"]
    assert report["assets"]["screenshots"]
    assert report["assets"]["cloud_assets"]
    assert report["assets"]["graphql"]
