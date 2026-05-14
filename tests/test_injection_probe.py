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
