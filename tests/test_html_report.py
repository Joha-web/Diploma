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
