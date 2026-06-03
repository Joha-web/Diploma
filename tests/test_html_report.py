from reporting.html_report import HTMLReportGenerator


def test_html_report_renders_email_security_findings(tmp_path):
    generator = HTMLReportGenerator(str(tmp_path), "example.com", "0m 1s")

    path = generator.generate({
        "recon": {
            "email_security": {
                "findings": [{
                    "severity": "MEDIUM",
                    "type": "missing_spf",
                    "title": "Email spoofing possible",
                    "url": "",
                    "evidence": {"record": "TXT"},
                }]
            }
        }
    })

    html = tmp_path.joinpath("report.html").read_text(encoding="utf-8")
    assert path.endswith("report.html")
    assert "Email DNS Security" in html
    assert "Email spoofing possible" in html


def test_html_report_risk_badge_uses_non_nuclei_findings(tmp_path):
    generator = HTMLReportGenerator(str(tmp_path), "example.com", "0m 1s")

    generator.generate({
        "vulnscan": {"findings": [], "by_severity": {}, "total": 0},
        "cors_checker": {
            "findings": [{
                "severity": "CRITICAL",
                "type": "cors_wildcard_credentials",
                "title": "Wildcard CORS with credentials",
                "url": "https://coll.example.com",
                "evidence": {},
                "confidence": 0.9,
            }],
            "total": 1,
        },
    })

    html = tmp_path.joinpath("report.html").read_text(encoding="utf-8")
    assert "CRITICAL RISK" in html
    assert 'id="finding-confidence-filter"' in html
    assert 'value="0.95"' not in html


def test_html_report_renders_ai_unavailable_placeholder(tmp_path):
    generator = HTMLReportGenerator(str(tmp_path), "example.com", "0m 1s")

    generator.generate({})

    html = tmp_path.joinpath("report.html").read_text(encoding="utf-8")
    # When AI is unavailable, static analysis fallback is shown
    assert "Executive Summary" in html or "Security Analysis" in html
    assert "Auto-generated" in html or "Recommended Actions" in html


def test_evidence_summary_surfaces_secret_location():
    ev = HTMLReportGenerator._evidence_summary({
        "source_path": "src/config/keys.js",
        "match": "API_KEY = '***'",
        "validation": {"status": "not_validated", "valid": False},
    })
    labels = {item["label"]: item["value"] for item in ev}
    assert labels["File"] == "src/config/keys.js"
    assert labels["Match"] == "API_KEY = '***'"


def test_evidence_summary_ignores_empty_and_nondict():
    assert HTMLReportGenerator._evidence_summary({}) == []
    assert HTMLReportGenerator._evidence_summary("nope") == []
    assert HTMLReportGenerator._evidence_summary({"location": ""}) == []


def test_report_shows_sourcemap_and_apikey_evidence(tmp_path):
    generator = HTMLReportGenerator(str(tmp_path), "example.com", "0m 1s")
    generator.generate({
        "sourcemap_analyzer": {"findings": [{
            "severity": "HIGH", "id": "sourcemap_secret", "type": "sourcemap_secret",
            "title": "Potential secret found in source map content",
            "url": "https://example.com/app.js.map",
            "evidence": {"source_path": "src/secrets.js", "match": "API_KEY = '***'"},
        }]},
        "api_key_validator": {"findings": [{
            "severity": "HIGH", "id": "api_key_leak", "type": "api_key",
            "title": "Potential live API key leak: api_key",
            "url": "https://my.example.com/Scripts/bootstrap.js",
            "evidence": {"redacted": "API_KEY = '***'", "key_type": "api_key",
                         "location": "https://my.example.com/Scripts/bootstrap.js", "source": "fuzzer",
                         "validation": {"status": "not_validated"}},
        }]},
    })
    html = tmp_path.joinpath("report.html").read_text(encoding="utf-8")
    # #2 source map secret location is shown
    assert "src/secrets.js" in html
    # #5 API key details are shown
    assert "API_KEY = &#39;***&#39;" in html or "API_KEY = '***'" in html
    # #1 attack-simulation policy text is gone, #4 cache poisoning section is gone
    assert "Attack simulation policy" not in html
    assert "Cache Poisoning Findings" not in html
