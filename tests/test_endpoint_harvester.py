import json
import subprocess

from modules.endpoint_harvester import EndpointHarvesterModule


def _module(tmp_path, **kwargs):
    config = {"scope": {"enforce": False}}
    return EndpointHarvesterModule("example.com", str(tmp_path), config, **kwargs)


def _proc(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout, "")


def test_classify_buckets_endpoint_types(tmp_path):
    module = _module(tmp_path)
    urls = [
        "https://example.com/api/v1/users",
        "https://example.com/login",
        "https://example.com/admin/dashboard",
        "https://example.com/swagger-ui/index.html",
        "https://example.com/.env",
        "https://example.com/static/app.min.js",
        "https://example.com/search?q=test",
    ]
    classified = module._classify(urls)

    assert "https://example.com/api/v1/users" in classified["api"]
    assert "https://example.com/login" in classified["auth"]
    assert "https://example.com/admin/dashboard" in classified["admin"]
    assert "https://example.com/swagger-ui/index.html" in classified["docs"]
    assert "https://example.com/.env" in classified["sensitive_files"]
    assert "https://example.com/static/app.min.js" in classified["static"]
    assert "https://example.com/search?q=test" in classified["with_params"]


def test_classify_excludes_static_js_from_api(tmp_path):
    """A bundle named api.js must not be classified as an API endpoint."""
    module = _module(tmp_path)
    classified = module._classify(["https://example.com/assets/api.js"])
    assert classified["api"] == []
    assert "https://example.com/assets/api.js" in classified["static"]


def test_parse_cariddi_extracts_endpoints_secrets_params(tmp_path):
    module = _module(tmp_path)
    lines = [
        json.dumps({
            "url": "https://example.com/app?token=abc",
            "matches": {
                "secrets": [{"name": "AWS Key", "match": "AKIAIOSFODNN7EXAMPLE"}],
                "parameters": [{"name": "token"}],
            },
        }),
        json.dumps({"url": "https://example.com/api/users"}),
        "not-json-just-noise https://example.com/from-plain",
    ]
    endpoints, secrets, params, juicy = module._parse_cariddi(lines)

    assert "https://example.com/app?token=abc" in endpoints
    assert "https://example.com/api/users" in endpoints
    assert "https://example.com/from-plain" in endpoints  # plain-URL fallback
    assert secrets[0]["name"] == "AWS Key"
    assert "AKIA" in secrets[0]["match"] and "EXAMPLE" not in secrets[0]["match"]  # redacted
    assert params[0]["param"] == "token"


def _exec_writing(content: str):
    """Fake exec for the streaming tools: write `content` to the shell-redirect
    target ('… > <path> 2>/dev/null') and return an empty (timeout-style) result."""
    import os

    def fake(cmd, timeout=300, shell=False, label=None, **k):
        path = cmd.split("> ", 1)[1].rsplit(" 2>/dev/null", 1)[0].strip().strip("'")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")
    return fake


def test_run_linkfinder_resolves_relative_endpoints(tmp_path, monkeypatch):
    module = _module(tmp_path, fuzzer_results={"js_urls": ["https://example.com/static/app.js"]})
    monkeypatch.setattr(module, "exec",
                        _exec_writing("/api/v2/orders\nhttps://example.com/api/v2/items\n#invalid line!"))
    found = module._run_linkfinder(["linkfinder"], module.module_config())

    assert "https://example.com/api/v2/orders" in found      # relative resolved
    assert "https://example.com/api/v2/items" in found        # absolute kept


def test_run_kiterunner_parses_route_urls(tmp_path, monkeypatch):
    module = _module(tmp_path, live_hosts=["https://example.com"])
    output = (
        "GET     200 [   1234,   56,    7] https://example.com/api/admin 0cf6\n"
        "POST    401 [     12,    3,    1] https://example.com/api/internal abcd\n"
        "garbage line with no url\n"
    )
    monkeypatch.setattr(module, "exec", _exec_writing(output))
    found = module._run_kiterunner("kr", module.module_config())

    assert "https://example.com/api/admin" in found
    assert "https://example.com/api/internal" in found


def test_build_findings_for_secrets_and_admin(tmp_path):
    module = _module(tmp_path)
    classified = {
        "admin": ["https://example.com/admin", "https://example.com/admin/users"],
        "sensitive_files": ["https://example.com/.git/config"],
        "api": ["https://example.com/api/v1"],
    }
    secrets = [{"url": "https://example.com/app", "name": "Slack token", "match": "xoxb-…"}]
    findings = module._build_findings(classified, secrets, parameters=[])

    ids = {f["id"] for f in findings}
    assert ids == {
        "endpoint_secret_exposed",
        "endpoint_admin_surface",
        "endpoint_sensitive_file_reference",
        "endpoint_api_surface",
    }
    secret_finding = next(f for f in findings if f["id"] == "endpoint_secret_exposed")
    assert secret_finding["severity"] == "HIGH"


def test_run_returns_empty_without_seeds(tmp_path):
    module = _module(tmp_path)
    result = module.run()
    assert result["total_endpoints"] == 0


def test_disabled_module_short_circuits(tmp_path):
    config = {"scope": {"enforce": False}, "scan": {"endpoint_harvester": {"enabled": False}}}
    module = EndpointHarvesterModule("example.com", str(tmp_path), config)
    result = module.run()
    assert result["status"] == "disabled"
