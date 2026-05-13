import base64
import json

from modules.auth_probe import AuthProbeModule


def _b64(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_auth_probe_detects_alg_none_jwt(tmp_path):
    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1'})}."
    module = AuthProbeModule("example.com", str(tmp_path), {}, live_hosts=[])

    findings = module._analyse_jwt(token, "https://example.com")

    assert any(f["type"] == "jwt_alg_none" for f in findings)


def test_auth_probe_cookie_flags(tmp_path):
    module = AuthProbeModule("example.com", str(tmp_path), {}, live_hosts=[])

    findings = module._audit_cookies("https://example.com", ["sid=abc; Path=/"])

    types = {f["type"] for f in findings}
    assert "cookie_missing_secure" in types
    assert "cookie_missing_httponly" in types
    assert "cookie_weak_samesite" in types
