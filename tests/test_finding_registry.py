from modules.finding_registry import (
    VERDICT_CONFIRMED,
    VERDICT_CANDIDATE,
    VERDICT_REVIEW,
    attack_for,
    build_finding,
    cvss_for,
    cwe_for,
    normalize_finding,
    owasp_for,
    verdict_for,
)


def test_cwe_lookup_matches_exact_and_substring():
    assert cwe_for("xss") == "CWE-79"
    assert cwe_for("xss_reflected") == "CWE-79"
    assert cwe_for("", finding_id="xss_dalfox_confirmed") == "CWE-79"
    assert cwe_for("sql_injection") == "CWE-89"
    assert cwe_for("unknown_thing") is None


def test_cvss_lookup_falls_back_to_substring():
    assert cvss_for("sql_injection").startswith("CVSS:3.1/")
    assert cvss_for("idor_path_identifier_candidate").startswith("CVSS:3.1/")
    assert cvss_for("not-a-real-bug-class") is None


def test_verdict_for_classifies_evidence_strength():
    # Confirmed: probe-grade evidence + explicit confirmed label
    assert (
        verdict_for("confirmed", {"poc": "x"}, confidence=0.9) == VERDICT_CONFIRMED
    )
    # Active probe with strong confidence + evidence -> confirmed
    assert verdict_for("active", {"req": "x"}, confidence=0.9) == VERDICT_CONFIRMED
    # Heuristic candidate
    assert verdict_for("candidate", {"hint": "x"}, confidence=0.7) == VERDICT_CANDIDATE
    # No evidence at all -> needs review
    assert verdict_for("passive", {}, confidence=0.4) == VERDICT_REVIEW
    # Confirmed but no evidence falls back to review
    assert verdict_for("confirmed", {}, confidence=0.95) == VERDICT_REVIEW


def test_build_finding_attaches_cwe_cvss_and_verdict():
    finding = build_finding(
        source="xss",
        finding_id="xss_dalfox_confirmed",
        url="https://example.com/?q=x",
        evidence={"poc": "<script>"},
    )

    assert finding["cwe"] == "CWE-79"
    assert finding["cvss_vector"].startswith("CVSS:3.1/")
    assert finding["verdict"] == VERDICT_CONFIRMED
    assert finding["severity"] == "HIGH"
    assert finding["risk_score"] > 0
    assert finding["owasp"].startswith("A03:2021")
    assert finding["attack"]["id"].startswith("T")


def test_owasp_and_attack_lookups():
    assert owasp_for("sql_injection").startswith("A03:2021")
    assert owasp_for("idor").startswith("A01:2021")
    assert owasp_for("", "jwt_audit_weak_secret").startswith("A02:2021")
    assert owasp_for("unknown") is None

    attack = attack_for("ssrf")
    assert attack["id"] == "T1190"
    attack = attack_for("", "subdomain_takeover_provider")
    assert attack["id"].startswith("T1584")
    assert attack_for("unknown") is None


def test_normalize_finding_backfills_enrichment_fields():
    normalized = normalize_finding(
        "sql_injection",
        {
            "id": "sql_injection_sqlmap_1_1",
            "type": "sql_injection",
            "title": "SQLi found",
            "severity": "HIGH",
            "confidence": 0.9,
            "exploitability": "confirmed",
            "evidence": {"param": "id"},
            "url": "https://example.com/?id=1",
        },
    )

    assert normalized["cwe"] == "CWE-89"
    assert normalized["cvss_vector"].startswith("CVSS:3.1/")
    assert normalized["verdict"] == VERDICT_CONFIRMED


def test_normalize_finding_preserves_explicit_enrichment_overrides():
    normalized = normalize_finding(
        "custom_module",
        {
            "id": "weird",
            "type": "weird",
            "severity": "LOW",
            "confidence": 0.5,
            "evidence": {},
            "cwe": "CWE-9999",
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
            "verdict": VERDICT_CANDIDATE,
        },
    )

    assert normalized["cwe"] == "CWE-9999"
    assert normalized["cvss_vector"].startswith("CVSS:3.1/AV:L")
    assert normalized["verdict"] == VERDICT_CANDIDATE
