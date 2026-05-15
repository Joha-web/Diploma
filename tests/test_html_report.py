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
    assert "AI Analysis — not available" in html
    assert "ollama serve" in html
