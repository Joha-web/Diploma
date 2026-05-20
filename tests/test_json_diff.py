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


def test_build_results_diff_computes_asset_score_deltas_and_summary():
    previous = {
        "recon": {"subdomains": []},
        "webdetect": {"live_urls": []},
        "asset_risk": {"ranked_assets": [
            {"asset": "api.example.com", "score": 60},
            {"asset": "static.example.com", "score": 10},
            {"asset": "gone.example.com", "score": 25},
        ]},
    }
    current = {
        "recon": {"subdomains": []},
        "webdetect": {"live_urls": []},
        "asset_risk": {"ranked_assets": [
            {"asset": "api.example.com", "score": 90},        # ↑30
            {"asset": "static.example.com", "score": 10},     # unchanged
            {"asset": "new.example.com", "score": 45},        # new
        ]},
    }

    diff = build_results_diff(previous, current)

    by_asset = {d["asset"]: d for d in diff["asset_score_deltas"]}
    assert by_asset["api.example.com"]["delta"] == 30
    assert by_asset["new.example.com"]["delta"] == 45
    assert by_asset["gone.example.com"]["delta"] == -25
    assert "static.example.com" not in by_asset  # unchanged entries are omitted

    assert diff["summary"]["assets_score_up"] == 2
    assert diff["summary"]["assets_score_down"] == 1


def test_persist_and_resolve_snapshot_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONX_SNAPSHOT_DIR", str(tmp_path))
    from main import _persist_snapshot, _resolve_previous_snapshot, _load_previous_results

    all_results = {
        "recon": {"subdomains": ["a.example.com", "b.example.com"]},
        "webdetect": {"live_urls": ["https://a.example.com"]},
        "portscan": {"hosts": []},
        "vulnscan": {"findings": [{"template_id": "x", "matched_url": "https://a.example.com"}]},
        "asset_risk": {"ranked_assets": [{"asset": "a.example.com", "score": 42}]},
    }
    snap = _persist_snapshot("example.com", all_results)
    assert snap is not None and snap.exists()

    found = _resolve_previous_snapshot("example.com")
    assert found is not None
    loaded = _load_previous_results(str(found))
    assert "a.example.com" in loaded["recon"]["subdomains"]
    assert loaded["asset_risk"]["ranked_assets"][0]["score"] == 42
