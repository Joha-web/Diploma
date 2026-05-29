from urllib.parse import parse_qs, urlparse

from modules.injection_probe import InjectionProbeModule


class Response:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


def test_injection_probe_collects_fuzzer_parameterized_urls(tmp_path):
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {},
        fuzzer_results={
            "classified": {"with_params": ["https://example.com/search?q=term"]},
            "all_endpoints": ["https://api.example.com/items?id=1"],
        },
    )

    targets = module._collect_parameter_targets()

    assert {"url": "https://example.com/search?q=term", "params": ["q"], "sources": ["fuzzer"]} in targets
    assert {"url": "https://api.example.com/items?id=1", "params": ["id"], "sources": ["fuzzer"]} in targets


def test_injection_probe_detects_ssti_response_marker(tmp_path, monkeypatch):
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssrf": False, "ssti": True}}},
        parameter_results={"parameters": [{"url": "https://example.com/search", "param": "q"}]},
    )

    def fake_http_get(url, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        return Response("calculated 49" if value == "{{7*7}}" else "no match")

    monkeypatch.setattr(module, "http_get", fake_http_get)

    result = module.run()

    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "ssti_expression_evaluated"
    assert finding["evidence"]["param"] == "q"
    assert finding["evidence"]["payload"] == "{{7*7}}"


def test_injection_probe_ignores_ssti_marker_already_in_baseline(tmp_path, monkeypatch):
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssrf": False, "ssti": True}}},
        parameter_results={"parameters": [{"url": "https://example.com/search", "param": "q"}]},
    )
    monkeypatch.setattr(module, "http_get", lambda url, **kwargs: Response("page already says 49"))

    result = module.run()

    assert result["findings"] == []


def test_injection_probe_ignores_ssti_marker_inside_express_stack_trace(tmp_path, monkeypatch):
    """Express stack traces contain "route.js:149:13" which embeds the substring "49"
    inside a larger line number. SSTI should not fire on substring matches.
    """
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssrf": False, "ssti": True}}},
        parameter_results={"parameters": [{"url": "https://example.com/redirect", "param": "to"}]},
    )

    def fake_http_get(url, **kwargs):
        value = parse_qs(urlparse(url).query).get("to", [""])[0]
        if not value:
            return Response("OK", status_code=200)
        body = (
            "<html><title>Error: Unrecognized target URL</title>"
            "<ul><li>at Layer.handle [as handle_request] "
            "(/app/node_modules/express/lib/router/layer.js:95:5)</li>"
            "<li> &nbsp; at next "
            "(/app/node_modules/express/lib/router/route.js:149:13)</li></ul></html>"
        )
        return Response(body, status_code=406)

    monkeypatch.setattr(module, "http_get", fake_http_get)

    result = module.run()
    assert result["findings"] == [], (
        f"SSTI must not fire when '49' appears only inside ':149:13' line numbers"
        f" within an Express stack trace; got: {result['findings']}"
    )


def test_injection_probe_ssti_still_fires_on_standalone_49(tmp_path, monkeypatch):
    """Sanity: a clean, evaluated 49 should still fire."""
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssrf": False, "ssti": True}}},
        parameter_results={"parameters": [{"url": "https://example.com/search", "param": "q"}]},
    )

    def fake_http_get(url, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        if value == "{{7*7}}":
            return Response("<h1>Result: 49</h1>", status_code=200)
        return Response("<h1>Result:</h1>", status_code=200)

    monkeypatch.setattr(module, "http_get", fake_http_get)

    findings = module.run()["findings"]
    assert findings and findings[0]["id"] == "ssti_expression_evaluated"


def test_injection_probe_detects_ssrf_oob_interaction(tmp_path, monkeypatch):
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssti": False, "ssrf": True, "ssrf_wait": 0}}},
        parameter_results={"parameters": [{"url": "https://example.com/fetch", "param": "url"}]},
    )
    stopped = {}
    requested = []

    class Helper:
        def _stop_oob_client(self, runtime):
            stopped["value"] = runtime

    monkeypatch.setattr(
        module,
        "_start_oob_runtime",
        lambda cfg: (Helper(), {"callback_url": "abc.oast.pro", "cooldown_period": 0}),
    )
    monkeypatch.setattr(module, "_read_oob_interactions", lambda runtime: [{"full-id": "rx0000.abc.oast.pro"}])
    monkeypatch.setattr(module, "http_get", lambda url, **kwargs: requested.append(url) or Response(""))

    result = module.run()

    assert stopped["value"]["callback_url"] == "abc.oast.pro"
    assert requested
    assert result["findings"][0]["id"] == "ssrf_oob_callback"
    assert result["findings"][0]["evidence"]["payload"] == "http://rx0000.abc.oast.pro"


def test_injection_probe_stops_oob_client_when_callback_missing(tmp_path, monkeypatch):
    module = InjectionProbeModule(
        "example.com",
        str(tmp_path),
        {"scan": {"injection_probe": {"ssti": False, "ssrf": True}}},
        parameter_results={"parameters": [{"url": "https://example.com/fetch", "param": "url"}]},
    )
    stopped = {}

    class Helper:
        def _stop_oob_client(self, runtime):
            stopped["value"] = runtime

    runtime = {"client_available": True, "client_started": True, "callback_url": ""}
    monkeypatch.setattr(module, "_start_oob_runtime", lambda cfg: (Helper(), runtime))

    assert module.run()["findings"] == []
    assert stopped["value"] is runtime
