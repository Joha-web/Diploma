from reporting.json_report import build_results_diff


def test_build_results_diff_reports_new_assets_and_findings():
    previous = {
        "recon": {"subdomains": ["old.example.com"]},
        "webdetect": {"live_urls": ["https://old.example.com"]},
        "portscan": {"hosts": [{"ip": "192.0.2.1", "open_ports": [{"port": 80}]}]},
        "vulnscan": {"findings": [{"template_id": "old", "matched_url": "https://old.example.com"}]},
    }
    current = {
        "recon": {"subdomains": ["new.example.com"]},
        "webdetect": {"live_urls": ["https://new.example.com"]},
        "portscan": {"hosts": [{"ip": "192.0.2.1", "open_ports": [{"port": 443}]}]},
        "vulnscan": {"findings": [{"template_id": "new", "matched_url": "https://new.example.com"}]},
    }

    diff = build_results_diff(previous, current)

    assert diff["new_subdomains"] == ["new.example.com"]
    assert diff["new_open_ports"] == ["192.0.2.1:443"]
    assert diff["new_findings"] == ["vulnscan:new:https://new.example.com"]
