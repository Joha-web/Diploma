from modules.parameter_discovery import ParameterDiscoveryModule


def test_parameter_discovery_merges_arjun_and_openapi_params(tmp_path):
    module = ParameterDiscoveryModule(
        "example.com",
        str(tmp_path),
        {},
        openapi_results={"parameters": [{"url": "https://example.com/api", "name": "id"}]},
    )
    parsed = module._parse_arjun({"https://example.com/login": ["next"]})
    openapi = module._openapi_parameters()

    params = module._dedupe_params(parsed + openapi)

    assert {"url": "https://example.com/login", "param": "next", "source": "arjun"} in params
    assert {"url": "https://example.com/api", "param": "id", "source": "openapi"} in params


def test_parameter_discovery_builds_parameterized_target(tmp_path):
    module = ParameterDiscoveryModule("example.com", str(tmp_path), {})

    assert module._with_param("https://example.com/api", "id") == "https://example.com/api?id=reconx"
