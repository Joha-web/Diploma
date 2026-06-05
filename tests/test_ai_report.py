import json

import requests

from modules.ai_report import AIReportModule


class _FakeStreamResp:
    """Minimal stand-in for a streaming requests.Response."""

    def __init__(self, lines, status_code=200, raise_after=None, exc=None):
        self._lines = lines
        self.status_code = status_code
        self.text = ""
        self._raise_after = raise_after
        self._exc = exc

    def iter_lines(self, decode_unicode=False):
        for i, line in enumerate(self._lines):
            if self._raise_after is not None and i == self._raise_after:
                raise self._exc
            yield line

    def close(self):
        pass


def _ollama_lines(*responses, done=True):
    lines = [json.dumps({"response": r, "done": False}) for r in responses]
    if done:
        lines.append(json.dumps({"response": "", "done": True}))
    return lines


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
- Evidence: The host is exposed to DRDoS amplification attacks.
- Risk: Service disruption.
- Recommendation: Filter UDP traffic.
"""

    assert not AIReportModule._is_acceptable_english_report(bad_report)


def test_ai_report_accepts_normal_security_english():
    # Regression: the word "protection" must NOT be rejected as German — that bug
    # silently discarded good AI reports and fell back to a thin static summary.
    good = """
## Executive Summary
The scan identified issues requiring manual validation; the overall grade is C.

## Critical and High Risk Findings
- Evidence: /search?q= reflected an unescaped marker.
- Risk: Cross-site scripting.
- Recommendation: Add Content-Security-Policy protection and output encoding.
"""

    assert AIReportModule._is_acceptable_english_report(good)


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


# ── streaming / reasoning-model handling ───────────────────────────────────

def test_is_reasoning_model():
    assert AIReportModule._is_reasoning_model("deepseek-r1:7b")
    assert AIReportModule._is_reasoning_model("qwq:32b")
    assert not AIReportModule._is_reasoning_model("qwen2.5:7b-instruct")
    assert not AIReportModule._is_reasoning_model("llama3:8b")


def test_clean_output_strips_complete_and_unterminated_think():
    # Complete reasoning block removed, report kept.
    assert AIReportModule._clean_model_output(
        "<think>weighing options</think>\n## Report\nbody") == "## Report\nbody"
    # Unterminated <think> (cut off mid-reasoning) -> nothing leaks through.
    assert AIReportModule._clean_model_output("## Intro\n<think>still reasoning...") == "## Intro"
    assert AIReportModule._clean_model_output("<think>only thinking, never finished") == ""


def test_ollama_generate_assembles_streamed_chunks(tmp_path, monkeypatch):
    module = AIReportModule("example.com", str(tmp_path), {}, {})
    lines = _ollama_lines("<think>plan</think>## Exec\n", "body text")
    monkeypatch.setattr("modules.ai_report.requests.post",
                        lambda *a, **k: _FakeStreamResp(lines))
    out = module._ollama_generate("http://x", "deepseek-r1:7b", "prompt", {})
    assert out == "## Exec\nbody text"


def test_ollama_generate_salvages_partial_output_on_timeout(tmp_path, monkeypatch):
    """A mid-stream timeout must keep what was already generated, not return ''."""
    module = AIReportModule("example.com", str(tmp_path), {}, {})
    # Two good chunks, then the stream raises Timeout (no done=True).
    lines = [json.dumps({"response": r, "done": False}) for r in ("## Exec\n", "partial body")]
    resp = _FakeStreamResp(lines, raise_after=2, exc=requests.exceptions.Timeout())
    monkeypatch.setattr("modules.ai_report.requests.post", lambda *a, **k: resp)
    out = module._ollama_generate("http://x", "deepseek-r1:7b", "p", {"timeout": 5})
    assert out == "## Exec\npartial body"  # salvaged despite the timeout


def test_ollama_generate_reasoning_only_returns_empty(tmp_path, monkeypatch):
    """Budget spent entirely on an unterminated <think> -> empty, with a hint."""
    module = AIReportModule("example.com", str(tmp_path), {}, {})
    lines = [json.dumps({"response": r, "done": False})
             for r in ("<think>reasoning ", "and more reasoning")]
    resp = _FakeStreamResp(lines, raise_after=2, exc=requests.exceptions.Timeout())
    monkeypatch.setattr("modules.ai_report.requests.post", lambda *a, **k: resp)
    out = module._ollama_generate("http://x", "deepseek-r1:7b", "p", {"timeout": 5})
    assert out == ""


def test_ollama_generate_surfaces_api_error(tmp_path, monkeypatch):
    module = AIReportModule("example.com", str(tmp_path), {}, {})
    resp = _FakeStreamResp([], status_code=500)
    resp.text = "boom"
    monkeypatch.setattr("modules.ai_report.requests.post", lambda *a, **k: resp)
    assert module._ollama_generate("http://x", "m", "p", {}) == ""
