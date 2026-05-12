from modules.ai_report import AIReportModule


def test_ai_prompt_defaults_to_english(tmp_path):
    module = AIReportModule("example.com", str(tmp_path), {}, {})

    prompt = module._build_prompt()

    assert "Write the entire report in clear professional English only" in prompt
    assert "Напиши отчёт" not in prompt


def test_ai_prompt_rejects_mixed_language_output():
    bad_report = """
## Executive Summary
The target has several findings.

## 🔴 Kritische Risikogebiete der Angriffsmöglichkeiten
- Entdeckung: Self-signed certificate
- Warum危险: Unzuverlässiger Zertifikat
- Empfehlung: Überprüfen Sie den Zertifikat.
"""

    assert not AIReportModule._is_acceptable_english_report(bad_report)


def test_ai_prompt_rejects_unsupported_claims():
    bad_report = """
## Executive Summary
The target has several findings based on automated scan evidence.

## Critical and High Risk Findings
- Evidence: Missing CSRF protection was detected.
- Risk: Account compromise.
- Recommendation: Implement CSRF protection.
"""

    assert not AIReportModule._is_acceptable_english_report(bad_report)


def test_ai_prompt_accepts_supported_english_output():
    good_report = """
## Executive Summary
The automated scan identified a limited attack surface with several issues that require manual validation.
The overall grade is C because exposed FTP and SMTP services increase operational risk.

## Critical and High Risk Findings
- Evidence: 185.98.5.117:21 (ftp) and 185.98.5.117:25 (smtp).
- Risk: Exposed administrative or mail services can increase brute-force and misconfiguration risk.
- Recommendation: Restrict access and verify whether these services are required.
"""

    assert AIReportModule._is_acceptable_english_report(good_report)
