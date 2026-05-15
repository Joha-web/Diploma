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
