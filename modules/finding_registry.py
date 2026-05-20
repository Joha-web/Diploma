"""
ReconX finding registry and risk scoring helpers.

The registry keeps module output consistent without forcing every probe to
repeat severity, confidence, references, and risk scoring boilerplate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_WEIGHTS = {
    "INFO": 5,
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90,
}

EXPLOITABILITY_WEIGHTS = {
    "passive": 0.20,
    "candidate": 0.35,
    "requires_auth": 0.50,
    "active": 0.65,
    "confirmed": 0.90,
}

# Verdict triage. Drives a 'confirmed vs candidate' split in the report so
# manual review effort can be focused where evidence is strongest.
VERDICT_CONFIRMED = "confirmed"
VERDICT_CANDIDATE = "candidate"
VERDICT_REVIEW = "manual_review"

# CWE / CVSS mapping by finding_type. Vectors are deliberately coarse — they
# describe the worst-case shape of the bug class, not the per-instance impact.
# Lookups fall back to None when a category is unknown, so additions are safe.
CWE_BY_TYPE: dict[str, str] = {
    "xss": "CWE-79",
    "sql_injection": "CWE-89",
    "idor": "CWE-639",
    "jwt": "CWE-345",
    "ssrf": "CWE-918",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "open_redirect": "CWE-601",
    "host_header_injection": "CWE-444",
    "http_smuggling": "CWE-444",
    "cache_poison": "CWE-444",
    "cors_misconfiguration": "CWE-942",
    "cors_wildcard_origin": "CWE-942",
    "cors_reflected_origin": "CWE-942",
    "cors_null_origin": "CWE-942",
    "prototype_pollution": "CWE-1321",
    "deserialization": "CWE-502",
    "graphql_introspection": "CWE-200",
    "secrets_exposed": "CWE-798",
    "secret_scanner": "CWE-798",
    "subdomain_takeover": "CWE-1390",
    "takeover_checker": "CWE-1390",
    "auth": "CWE-287",
    "session_cookie_flags": "CWE-614",
    "session_management": "CWE-384",
    "race_condition": "CWE-362",
    "websocket": "CWE-346",
    "javascript": "CWE-79",
    "openapi": "CWE-200",
    "api_key_validator": "CWE-798",
    "injection_probe": "CWE-94",
}

CVSS_BY_TYPE: dict[str, str] = {
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "jwt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "host_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "http_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cache_poison": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N",
    "cors_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "cors_wildcard_origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "cors_reflected_origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "cors_null_origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "prototype_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "secrets_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "secret_scanner": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "takeover_checker": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "auth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "session_cookie_flags": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "race_condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "websocket": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "javascript": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "openapi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "injection_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}


@dataclass(frozen=True)
class FindingDefinition:
    finding_id: str
    title: str
    severity: str = "INFO"
    confidence: float = 0.70
    finding_type: str = ""
    description: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)
    exploitability: str | float = "candidate"
    tags: tuple[str, ...] = field(default_factory=tuple)


REFERENCE_SETS = {
    "idor": (
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "https://portswigger.net/web-security/access-control/idor",
    ),
    "jwt": (
        "https://portswigger.net/web-security/jwt",
        "https://datatracker.ietf.org/doc/html/rfc8725",
    ),
    "websocket": (
        "https://portswigger.net/web-security/websockets",
        "https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html",
    ),
    "openapi": (
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "https://spec.openapis.org/oas/latest.html",
    ),
    "javascript": (
        "https://portswigger.net/web-security/cross-site-scripting/dom-based",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
    ),
    "xss": (
        "https://portswigger.net/web-security/cross-site-scripting",
        "https://owasp.org/www-community/attacks/xss/",
    ),
}


FINDING_DEFINITIONS: dict[str, FindingDefinition] = {
    "idor_query_identifier_candidate": FindingDefinition(
        "idor_query_identifier_candidate",
        "IDOR/BOLA candidate in query parameter",
        "MEDIUM",
        0.70,
        "idor",
        "A query parameter appears to reference a user, account, organization, or object identifier.",
        REFERENCE_SETS["idor"],
        "candidate",
        ("idor", "bola", "access-control"),
    ),
    "idor_path_identifier_candidate": FindingDefinition(
        "idor_path_identifier_candidate",
        "IDOR/BOLA candidate in URL path",
        "MEDIUM",
        0.72,
        "idor",
        "A URL path contains an object identifier on a sensitive resource path.",
        REFERENCE_SETS["idor"],
        "candidate",
        ("idor", "bola", "access-control"),
    ),
    "idor_openapi_object_endpoint": FindingDefinition(
        "idor_openapi_object_endpoint",
        "OpenAPI object endpoint may require BOLA testing",
        "MEDIUM",
        0.68,
        "idor",
        "An OpenAPI route exposes object identifiers and should be verified for object-level authorization.",
        REFERENCE_SETS["idor"],
        "candidate",
        ("idor", "bola", "openapi"),
    ),
    "idor_anonymous_object_access": FindingDefinition(
        "idor_anonymous_object_access",
        "Object endpoint accessible anonymously",
        "HIGH",
        0.80,
        "idor",
        "A candidate object endpoint returned a successful response without an auth profile.",
        REFERENCE_SETS["idor"],
        "active",
        ("idor", "bola", "anonymous-access"),
    ),
    "idor_profile_response_overlap": FindingDefinition(
        "idor_profile_response_overlap",
        "Auth profiles received overlapping object response",
        "HIGH",
        0.72,
        "idor",
        "Two different auth profiles received highly similar successful responses from the same object endpoint.",
        REFERENCE_SETS["idor"],
        "requires_auth",
        ("idor", "bola", "access-control"),
    ),
    "jwt_alg_none": FindingDefinition(
        "jwt_alg_none",
        "JWT uses alg=none",
        "CRITICAL",
        0.95,
        "jwt",
        "The JWT header advertises the none algorithm.",
        REFERENCE_SETS["jwt"],
        "confirmed",
        ("jwt", "auth"),
    ),
    "jwt_weak_hmac_secret": FindingDefinition(
        "jwt_weak_hmac_secret",
        "JWT signed with weak HMAC secret",
        "CRITICAL",
        0.95,
        "jwt",
        "The JWT signature validated with a weak dictionary secret.",
        REFERENCE_SETS["jwt"],
        "confirmed",
        ("jwt", "auth", "weak-secret"),
    ),
    "jwt_kid_path_traversal": FindingDefinition(
        "jwt_kid_path_traversal",
        "JWT kid header contains path traversal indicator",
        "HIGH",
        0.82,
        "jwt",
        "The JWT key id header contains traversal, absolute path, or URL-like content.",
        REFERENCE_SETS["jwt"],
        "candidate",
        ("jwt", "auth", "kid"),
    ),
    "jwt_untrusted_jku_x5u": FindingDefinition(
        "jwt_untrusted_jku_x5u",
        "JWT references untrusted remote key URL",
        "HIGH",
        0.82,
        "jwt",
        "The JWT header points jku/x5u at an out-of-scope or insecure URL.",
        REFERENCE_SETS["jwt"],
        "candidate",
        ("jwt", "auth", "jku", "x5u"),
    ),
    "jwt_missing_claim": FindingDefinition(
        "jwt_missing_claim",
        "JWT missing recommended claim",
        "MEDIUM",
        0.70,
        "jwt",
        "The JWT omits a recommended issuer, audience, or expiration claim.",
        REFERENCE_SETS["jwt"],
        "passive",
        ("jwt", "auth", "claims"),
    ),
    "jwt_long_lived_token": FindingDefinition(
        "jwt_long_lived_token",
        "JWT appears long-lived",
        "MEDIUM",
        0.76,
        "jwt",
        "The token lifetime exceeds the configured maximum.",
        REFERENCE_SETS["jwt"],
        "passive",
        ("jwt", "auth", "claims"),
    ),
    "websocket_insecure_scheme": FindingDefinition(
        "websocket_insecure_scheme",
        "Insecure ws:// WebSocket endpoint",
        "MEDIUM",
        0.78,
        "websocket",
        "A WebSocket endpoint uses plaintext ws://.",
        REFERENCE_SETS["websocket"],
        "passive",
        ("websocket", "transport"),
    ),
    "websocket_unauthenticated_connect": FindingDefinition(
        "websocket_unauthenticated_connect",
        "WebSocket accepts unauthenticated connection",
        "MEDIUM",
        0.80,
        "websocket",
        "The endpoint completed a WebSocket upgrade without auth profile headers.",
        REFERENCE_SETS["websocket"],
        "active",
        ("websocket", "auth"),
    ),
    "websocket_origin_not_validated": FindingDefinition(
        "websocket_origin_not_validated",
        "WebSocket Origin validation may be missing",
        "HIGH",
        0.82,
        "websocket",
        "The endpoint completed a WebSocket upgrade with an untrusted Origin header.",
        REFERENCE_SETS["websocket"],
        "active",
        ("websocket", "origin"),
    ),
    "websocket_reflected_message": FindingDefinition(
        "websocket_reflected_message",
        "WebSocket reflected probe message",
        "LOW",
        0.70,
        "websocket",
        "A probe message was reflected by the WebSocket endpoint.",
        REFERENCE_SETS["websocket"],
        "active",
        ("websocket", "reflection"),
    ),
    "openapi_endpoint_without_security": FindingDefinition(
        "openapi_endpoint_without_security",
        "OpenAPI endpoint has no security requirement",
        "MEDIUM",
        0.72,
        "api_schema",
        "An OpenAPI operation appears to be callable without a security requirement.",
        REFERENCE_SETS["openapi"],
        "passive",
        ("openapi", "auth"),
    ),
    "openapi_sensitive_route_without_auth": FindingDefinition(
        "openapi_sensitive_route_without_auth",
        "Sensitive OpenAPI route lacks auth",
        "HIGH",
        0.78,
        "api_schema",
        "A sensitive route appears to have no effective security requirement.",
        REFERENCE_SETS["openapi"],
        "passive",
        ("openapi", "auth", "sensitive"),
    ),
    "openapi_dangerous_method_without_auth": FindingDefinition(
        "openapi_dangerous_method_without_auth",
        "Dangerous OpenAPI method lacks auth",
        "HIGH",
        0.78,
        "api_schema",
        "A state-changing OpenAPI method appears to have no effective security requirement.",
        REFERENCE_SETS["openapi"],
        "passive",
        ("openapi", "auth", "state-changing"),
    ),
    "openapi_overly_broad_schema": FindingDefinition(
        "openapi_overly_broad_schema",
        "OpenAPI schema is overly broad",
        "LOW",
        0.68,
        "api_schema",
        "A request schema accepts free-form object input or lacks explicit properties.",
        REFERENCE_SETS["openapi"],
        "passive",
        ("openapi", "schema"),
    ),
    "openapi_missing_rate_limit_hint": FindingDefinition(
        "openapi_missing_rate_limit_hint",
        "No rate-limit hint on sensitive API operation",
        "LOW",
        0.60,
        "api_schema",
        "A sensitive operation lacks 429 responses or rate-limit header documentation.",
        REFERENCE_SETS["openapi"],
        "passive",
        ("openapi", "rate-limit"),
    ),
    "js_dom_xss_sink": FindingDefinition(
        "js_dom_xss_sink",
        "Potential DOM XSS sink in JavaScript",
        "HIGH",
        0.74,
        "javascript",
        "JavaScript appears to pass attacker-controlled browser data into an HTML/code sink.",
        REFERENCE_SETS["javascript"],
        "passive",
        ("javascript", "dom-xss"),
    ),
    "js_postmessage_missing_origin_check": FindingDefinition(
        "js_postmessage_missing_origin_check",
        "postMessage handler lacks origin check",
        "MEDIUM",
        0.75,
        "javascript",
        "A message event handler does not appear to validate event.origin.",
        REFERENCE_SETS["javascript"],
        "passive",
        ("javascript", "postmessage"),
    ),
    "js_hardcoded_graphql_endpoint": FindingDefinition(
        "js_hardcoded_graphql_endpoint",
        "Hardcoded GraphQL endpoint in JavaScript",
        "INFO",
        0.70,
        "javascript",
        "A JavaScript bundle references a GraphQL endpoint.",
        REFERENCE_SETS["javascript"],
        "passive",
        ("javascript", "graphql"),
    ),
    "js_unsafe_redirect": FindingDefinition(
        "js_unsafe_redirect",
        "Potential unsafe client-side redirect",
        "MEDIUM",
        0.72,
        "javascript",
        "JavaScript appears to redirect using URL-controlled input.",
        REFERENCE_SETS["javascript"],
        "passive",
        ("javascript", "redirect"),
    ),
    "xss_html_injection_candidate": FindingDefinition(
        "xss_html_injection_candidate",
        "Reflected HTML injection indicates XSS risk",
        "HIGH",
        0.82,
        "xss",
        "A reflected payload was returned as raw HTML, indicating likely reflected XSS exposure.",
        REFERENCE_SETS["xss"],
        "active",
        ("xss", "reflected", "html-injection"),
    ),
    "xss_script_context_reflection": FindingDefinition(
        "xss_script_context_reflection",
        "Reflected input in script context",
        "HIGH",
        0.78,
        "xss",
        "A marker was reflected inside a script block, where escaping mistakes can become executable XSS.",
        REFERENCE_SETS["xss"],
        "active",
        ("xss", "reflected", "script-context"),
    ),
    "xss_attribute_context_reflection": FindingDefinition(
        "xss_attribute_context_reflection",
        "Reflected input in HTML attribute context",
        "MEDIUM",
        0.74,
        "xss",
        "A marker was reflected inside an HTML tag or attribute context.",
        REFERENCE_SETS["xss"],
        "active",
        ("xss", "reflected", "attribute-context"),
    ),
    "xss_reflected_input": FindingDefinition(
        "xss_reflected_input",
        "Reflected input observed",
        "LOW",
        0.62,
        "xss",
        "A marker was reflected by the application, but the observed context did not prove executable XSS.",
        REFERENCE_SETS["xss"],
        "candidate",
        ("xss", "reflected"),
    ),
    "xss_dalfox_confirmed": FindingDefinition(
        "xss_dalfox_confirmed",
        "Cross-Site Scripting confirmed by Dalfox",
        "HIGH",
        0.90,
        "xss",
        "Dalfox confirmed reflected XSS via proof-of-concept payload.",
        REFERENCE_SETS["xss"],
        "confirmed",
        ("xss", "reflected", "dalfox"),
    ),
}


def definition_for(finding_id: str) -> FindingDefinition:
    return FINDING_DEFINITIONS.get(
        finding_id,
        FindingDefinition(
            finding_id=finding_id,
            title=finding_id.replace("_", " ").title(),
            severity="INFO",
            confidence=0.70,
            finding_type=finding_id,
            exploitability="candidate",
        ),
    )


def build_finding(
    source: str,
    finding_id: str,
    url: str = "",
    title: str | None = None,
    description: str | None = None,
    severity: str | None = None,
    evidence: dict[str, Any] | None = None,
    confidence: float | None = None,
    references: list[str] | tuple[str, ...] | None = None,
    finding_type: str | None = None,
    tags: list[str] | tuple[str, ...] | None = None,
    exploitability: str | float | None = None,
    asset_criticality: float | None = None,
) -> dict[str, Any]:
    definition = definition_for(finding_id)
    sev = normalize_severity(severity or definition.severity)
    conf = clamp(confidence if confidence is not None else definition.confidence)
    refs = list(references if references is not None else definition.references)
    item_type = finding_type or definition.finding_type or finding_id
    exp = exploitability if exploitability is not None else definition.exploitability
    score = risk_score(sev, conf, exp, asset_criticality)
    item_tags = list(tags if tags is not None else definition.tags)
    return {
        "source": source,
        "id": finding_id,
        "type": item_type,
        "name": title or definition.title,
        "title": title or definition.title,
        "severity": sev,
        "url": url,
        "matched_url": url,
        "description": description or definition.description or (title or definition.title),
        "evidence": evidence or {},
        "references": refs,
        "confidence": conf,
        "risk_score": score,
        "exploitability": exp,
        "tags": item_tags,
        "cwe": cwe_for(item_type, finding_id),
        "cvss_vector": cvss_for(item_type, finding_id),
        "verdict": verdict_for(exp, evidence or {}, conf),
    }


def normalize_finding(module_name: str, finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = finding.get("id") or finding.get("type", "")
    finding_type = finding.get("type") or finding_id
    severity = normalize_severity(finding.get("severity", "INFO"))
    confidence = clamp(finding.get("confidence", 0.75))
    exploitability = finding.get("exploitability", "candidate")
    evidence = finding.get("evidence", {})
    return {
        "source": finding.get("source", module_name),
        "id": finding_id,
        "title": finding.get("title") or finding.get("name", ""),
        "severity": severity,
        "url": finding.get("url") or finding.get("matched_url", ""),
        "description": finding.get("description", ""),
        "evidence": evidence,
        "references": finding.get("references", []),
        "tags": finding.get("tags", [module_name, finding.get("type", "")]),
        "confidence": confidence,
        "risk_score": finding.get(
            "risk_score",
            risk_score(severity, confidence, exploitability, finding.get("asset_criticality")),
        ),
        "exploitability": exploitability,
        "cwe": finding.get("cwe") or cwe_for(finding_type, finding_id),
        "cvss_vector": finding.get("cvss_vector") or cvss_for(finding_type, finding_id),
        "verdict": finding.get("verdict") or verdict_for(exploitability, evidence, confidence),
    }


def risk_score(
    severity: str,
    confidence: float = 0.75,
    exploitability: str | float = "candidate",
    asset_criticality: float | None = None,
) -> int:
    sev = SEVERITY_WEIGHTS.get(normalize_severity(severity), 5)
    conf = clamp(confidence) * 100
    exp = _exploitability_weight(exploitability) * 100
    crit = clamp(0.50 if asset_criticality is None else asset_criticality) * 100
    return int(round((sev * 0.55) + (conf * 0.25) + (exp * 0.15) + (crit * 0.05)))


def normalize_severity(value: str) -> str:
    sev = str(value or "INFO").upper()
    return sev if sev in SEVERITY_WEIGHTS else "INFO"


def clamp(value: Any, default: float = 0.75) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return max(0.0, min(1.0, number))


def _exploitability_weight(value: str | float) -> float:
    if isinstance(value, (int, float)):
        return clamp(value)
    return EXPLOITABILITY_WEIGHTS.get(str(value or "").lower(), 0.35)


def cwe_for(finding_type: str, finding_id: str = "") -> str | None:
    """Best-effort CWE lookup. Returns None when no rule matches.

    Tries the exact finding_type first, then falls back to substring matching
    so e.g. `xss_dalfox_confirmed` resolves to CWE-79 via the `xss` prefix.
    """
    finding_type = (finding_type or "").lower()
    finding_id = (finding_id or "").lower()
    if finding_type in CWE_BY_TYPE:
        return CWE_BY_TYPE[finding_type]
    for key, cwe in CWE_BY_TYPE.items():
        if key and (key in finding_type or key in finding_id):
            return cwe
    return None


def cvss_for(finding_type: str, finding_id: str = "") -> str | None:
    """Best-effort CVSS:3.1 vector lookup. Returns None when unknown."""
    finding_type = (finding_type or "").lower()
    finding_id = (finding_id or "").lower()
    if finding_type in CVSS_BY_TYPE:
        return CVSS_BY_TYPE[finding_type]
    for key, vec in CVSS_BY_TYPE.items():
        if key and (key in finding_type or key in finding_id):
            return vec
    return None


def verdict_for(
    exploitability: str | float,
    evidence: dict[str, Any] | None = None,
    confidence: float = 0.75,
) -> str:
    """Triage a finding into confirmed / candidate / manual_review.

    A finding is `confirmed` when the probe captured concrete proof
    (exploitability=='confirmed' or active+strong confidence, with non-empty
    evidence). It is a `candidate` when heuristic evidence exists but
    exploitation wasn't demonstrated. It is `manual_review` when both signal
    and evidence are weak — the human should look before any action.
    """
    evidence = evidence or {}
    has_evidence = bool(evidence)
    conf = clamp(confidence)

    if isinstance(exploitability, (int, float)):
        weight = clamp(exploitability)
    else:
        weight = EXPLOITABILITY_WEIGHTS.get(str(exploitability or "").lower(), 0.35)

    label = str(exploitability or "").lower() if isinstance(exploitability, str) else ""
    if label == "confirmed" and has_evidence:
        return VERDICT_CONFIRMED
    if weight >= 0.65 and has_evidence and conf >= 0.80:
        return VERDICT_CONFIRMED
    if weight >= 0.35 and has_evidence:
        return VERDICT_CANDIDATE
    return VERDICT_REVIEW
