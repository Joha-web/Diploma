from modules.fp_triage import FPTriageModule
from modules.finding_registry import VERDICT_REVIEW


def _module(tmp_path, all_results, config=None):
    return FPTriageModule(
        "example.com",
        str(tmp_path),
        config or {},
        all_results=all_results,
    )


def test_disabled_via_config(tmp_path):
    module = _module(
        tmp_path,
        {"xss": {"findings": [{"id": "xss", "evidence": {}}]}},
        {"scan": {"fp_triage": {"enabled": False}}},
    )
    result = module.run()
    assert result["status"] == "disabled"


def test_no_findings_is_completed(tmp_path):
    module = _module(tmp_path, {"recon": {"subdomains_total": 3}})
    result = module.run()
    assert result["status"] == "completed"
    assert result["assessed"] == 0


def test_heuristic_flags_evidenceless_low_confidence_finding(tmp_path):
    findings = [{
        "id": "open_redirect_candidate",
        "type": "open_redirect",
        "severity": "LOW",
        "confidence": 0.3,
        "exploitability": "candidate",
        "evidence": {},
        "verdict": "candidate",
    }]
    all_results = {"open_redirect_probe": {"findings": findings}}
    module = _module(tmp_path, all_results,
                     {"scan": {"fp_triage": {"use_ai": False}}})

    result = module.run()

    assert result["method"] == "heuristic"
    assert result["assessed"] == 1
    assert result["flagged"] == 1
    # The original finding dict is mutated in place.
    assert findings[0]["verdict"] == VERDICT_REVIEW
    assert findings[0]["fp_triage"]["is_false_positive"] is True
    assert findings[0]["fp_triage"]["original_verdict"] == "candidate"


def test_heuristic_keeps_confirmed_finding(tmp_path):
    findings = [{
        "id": "jwt_alg_none",
        "type": "jwt",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "exploitability": "confirmed",
        "evidence": {"header": "alg=none"},
        "verdict": "confirmed",
    }]
    all_results = {"jwt_audit": {"findings": findings}}
    module = _module(tmp_path, all_results,
                     {"scan": {"fp_triage": {"use_ai": False}}})

    result = module.run()

    assert result["flagged"] == 0
    assert findings[0]["verdict"] == "confirmed"
    assert findings[0]["fp_triage"]["is_false_positive"] is False


def test_correlator_and_report_findings_are_skipped(tmp_path):
    all_results = {
        "correlator": {"findings": [{"id": "chain", "evidence": {}}]},
        "ai_report": {"findings": [{"id": "x", "evidence": {}}]},
    }
    module = _module(tmp_path, all_results,
                     {"scan": {"fp_triage": {"use_ai": False}}})
    result = module.run()
    assert result["assessed"] == 0


def test_parse_ai_tolerates_fenced_json(tmp_path):
    findings = [{"idx": 0, "finding": {}}]
    raw = '```json\n[{"idx": 0, "is_false_positive": true, ' \
          '"confidence": 0.9, "reason": "encoded reflection"}]\n```'
    parsed = FPTriageModule._parse_ai(raw, {0})
    assert parsed[0]["is_fp"] is True
    assert parsed[0]["confidence"] == 0.9
    assert parsed[0]["reason"] == "encoded reflection"
