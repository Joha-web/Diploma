from modules.cors_checker import CORSCheckerModule


class DummyResponse:
    def __init__(self, headers=None, status_code=200, text=""):
        self.headers = headers or {}
        self.status_code = status_code
        self.text = text
        self.content = text.encode()


def test_cors_checker_flags_reflected_credentialed_origin(tmp_path, monkeypatch):
    module = CORSCheckerModule("example.com", str(tmp_path), {}, live_hosts=[])

    def fake_get(url, **kwargs):
        return DummyResponse({
            "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
            "Access-Control-Allow-Credentials": "true",
        })

    monkeypatch.setattr(module, "http_get", fake_get)

    findings = module._check_url("https://example.com", object())

    assert findings
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["evidence"]["access_control_allow_credentials"] == "true"
    assert "headers: {Origin" not in findings[0]["poc"]
    assert "Host this page" in findings[0]["poc"]


def test_cors_checker_flags_wildcard_origin(tmp_path, monkeypatch):
    module = CORSCheckerModule("example.com", str(tmp_path), {}, live_hosts=[])
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: DummyResponse({
        "Access-Control-Allow-Origin": "*",
    }))

    findings = module._check_url("https://example.com", object())

    assert findings[0]["type"] == "cors_wildcard_origin"
    assert findings[0]["severity"] == "MEDIUM"
    assert len(findings) == 1


def test_cors_checker_deduplicates_wildcard_credentialed_origin(tmp_path, monkeypatch):
    module = CORSCheckerModule("example.com", str(tmp_path), {}, live_hosts=[])
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: DummyResponse({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }))

    findings = module._check_url("https://example.com", object())

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "Browsers reject" in findings[0]["evidence"]["browser_note"]


def test_cors_checker_uses_requested_bypass_origins():
    origins = [origin for _, origin, _ in CORSCheckerModule.ORIGIN_PROBES]

    assert "https://evil{domain}" in origins
    assert "https://notexample.com" in origins
    assert "https://not{domain}" not in origins


def test_cors_reflects_any_origin_yields_single_medium_finding(tmp_path, monkeypatch):
    """A server that reflects ANY origin with no credentials is one root cause →
    one MEDIUM finding, not five inflated HIGH ones."""
    module = CORSCheckerModule("example.com", str(tmp_path), {}, live_hosts=[])
    monkeypatch.setattr(module, "http_get", lambda url, **kw: DummyResponse({
        "Access-Control-Allow-Origin": kw["headers"]["Origin"],   # reflect anything, no creds
    }))
    findings = module._check_url("https://example.com", object())
    assert len(findings) == 1
    assert findings[0]["type"] == "cors_reflected_origin"
    assert findings[0]["severity"] == "MEDIUM"   # no credentials → not HIGH/CRITICAL


def test_cors_detects_prefix_bypass_only(tmp_path, monkeypatch):
    """Server doesn't reflect arbitrary origins but has a prefix-match bug → the
    targeted bypass probe still catches it."""
    module = CORSCheckerModule("example.com", str(tmp_path), {}, live_hosts=[])

    def fake_get(url, **kw):
        origin = kw["headers"]["Origin"]
        if origin == "https://example.com.attacker-reconx.com":
            return DummyResponse({"Access-Control-Allow-Origin": origin,
                                  "Access-Control-Allow-Credentials": "true"})
        return DummyResponse({})   # arbitrary origins not reflected

    monkeypatch.setattr(module, "http_get", fake_get)
    findings = module._check_url("https://example.com", object())
    assert len(findings) == 1
    assert findings[0]["type"] == "cors_prefix_bypass"
    assert findings[0]["severity"] == "CRITICAL"   # credentials allowed
