import pytest

from main import CLASS_MAP, MODULE_LABELS, PIPELINE, _build_kwargs, _module_summary, _select_active_modules


def test_new_modules_are_wired_into_pipeline():
    groups = {step["name"]: step["group"] for step in PIPELINE}
    active_modules = {
        "http_smuggling": ("modules.http_smuggling", "HTTPSmugglingModule"),
        "oauth_probe": ("modules.oauth_probe", "OAuthProbeModule"),
        "host_header_injection": ("modules.host_header_injection", "HostHeaderInjectionModule"),
        "prototype_pollution": ("modules.prototype_pollution", "PrototypePollutionModule"),
        "xxe_probe": ("modules.xxe_probe", "XXEProbeModule"),
        "deserialization_probe": ("modules.deserialization_probe", "DeserializationProbeModule"),
        "race_condition": ("modules.race_condition", "RaceConditionModule"),
        "open_redirect_probe": ("modules.open_redirect_probe", "OpenRedirectProbeModule"),
        "api_key_validator": ("modules.api_key_validator", "APIKeyValidatorModule"),
        "jwt_audit": ("modules.jwt_audit", "JWTAuditModule"),
        "websocket_probe": ("modules.websocket_probe", "WebSocketProbeModule"),
        "api_schema_audit": ("modules.api_schema_audit", "APISchemaAuditModule"),
        "js_security_audit": ("modules.js_security_audit", "JSSecurityAuditModule"),
        "endpoint_harvester": ("modules.endpoint_harvester", "EndpointHarvesterModule"),
        "ssrf_probe": ("modules.ssrf_probe", "SSRFProbeModule"),
    }
    post_parameter_modules = {
        "injection_probe": ("modules.injection_probe", "InjectionProbeModule"),
        "xss": ("modules.xss", "XSSModule"),
        "sql_injection": ("modules.sql_injection", "SQLInjectionModule"),
        "idor_probe": ("modules.idor_probe", "IDORProbeModule"),
    }

    assert groups["secret_scanner"] == 1
    assert CLASS_MAP["secret_scanner"] == ("modules.secret_scanner", "SecretScannerModule")
    assert CLASS_MAP["injection_probe"] == ("modules.injection_probe", "InjectionProbeModule")
    assert MODULE_LABELS["injection_probe"] == "SSRF / SSTI / XXE Detection"
    assert CLASS_MAP["xss"] == ("modules.xss", "XSSModule")
    assert MODULE_LABELS["xss"] == "Cross-Site Scripting Testing"
    assert CLASS_MAP["sql_injection"] == ("modules.sql_injection", "SQLInjectionModule")
    assert MODULE_LABELS["sql_injection"] == "SQL Injection Testing (sqlmap)"
    for module_name, class_ref in active_modules.items():
        assert CLASS_MAP[module_name] == class_ref
    for module_name, class_ref in post_parameter_modules.items():
        assert CLASS_MAP[module_name] == class_ref

    # Verify new group assignments
    assert groups["http_smuggling"] == 7
    assert groups["jwt_audit"] == 7
    assert groups["websocket_probe"] == 7
    assert groups["api_schema_audit"] == 7
    assert groups["js_security_audit"] == 7

    assert groups["oauth_probe"] == 8
    assert groups["host_header_injection"] == 8
    assert groups["open_redirect_probe"] == 8
    assert groups["prototype_pollution"] == 8
    assert groups["deserialization_probe"] == 8
    assert groups["race_condition"] == 8

    assert groups["endpoint_harvester"] == 5

    assert groups["api_key_validator"] == 9
    assert groups["xxe_probe"] == 9

    assert groups["injection_probe"] == 10
    assert groups["xss"] == 10
    assert groups["sql_injection"] == 10
    assert groups["idor_probe"] == 10


def test_injection_probe_kwargs_use_parameter_and_fuzzer_results():
    all_results = {
        "parameter_discovery": {"parameters": [{"url": "https://example.com", "param": "q"}]},
        "fuzzer": {"classified": {"with_params": ["https://example.com/?q=x"]}},
    }

    kwargs = _build_kwargs("injection_probe", all_results)

    assert kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_sql_injection_kwargs_use_parameter_and_fuzzer_results():
    all_results = {
        "parameter_discovery": {"parameters": [{"url": "https://example.com", "param": "id"}]},
        "fuzzer": {"classified": {"with_params": ["https://example.com/?id=1"]}},
    }

    kwargs = _build_kwargs("sql_injection", all_results)

    assert kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_xss_kwargs_use_parameter_and_fuzzer_results():
    all_results = {
        "parameter_discovery": {"parameters": [{"url": "https://example.com", "param": "q"}]},
        "fuzzer": {"classified": {"with_params": ["https://example.com/?q=x"]}},
    }

    kwargs = _build_kwargs("xss", all_results)

    assert kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_active_probe_kwargs_use_prior_results():
    all_results = {
        "fuzzer": {"classified": {}},
        "openapi_parser": {"endpoints": []},
        "secret_scanner": {"findings": []},
        "parameter_discovery": {"parameters": []},
        "webdetect": {"live_urls": ["https://example.com"]},
    }

    assert _build_kwargs("prototype_pollution", all_results)["openapi_results"] is all_results["openapi_parser"]
    assert _build_kwargs("xxe_probe", all_results)["fuzzer_results"] is all_results["fuzzer"]
    assert _build_kwargs("api_key_validator", all_results)["secret_results"] is all_results["secret_scanner"]
    assert _build_kwargs("oauth_probe", all_results)["live_hosts"] == ["https://example.com"]
    assert _build_kwargs("idor_probe", all_results)["openapi_results"] is all_results["openapi_parser"]
    assert _build_kwargs("api_schema_audit", all_results)["openapi_results"] is all_results["openapi_parser"]

    harvester_kwargs = _build_kwargs("endpoint_harvester", all_results)
    assert harvester_kwargs["live_hosts"] == ["https://example.com"]
    assert harvester_kwargs["fuzzer_results"] is all_results["fuzzer"]
    assert _build_kwargs("parameter_discovery", all_results)["endpoint_results"] == {}

    ssrf_kwargs = _build_kwargs("ssrf_probe", all_results)
    assert ssrf_kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert ssrf_kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_new_module_summaries():
    assert _module_summary("secret_scanner", {"status": "completed", "total": 2}) == "2 git secret finding(s)"
    assert _module_summary("injection_probe", {"status": "completed", "total": 3}) == "3 injection finding(s)"
    assert _module_summary("xss", {"status": "completed", "total": 2}) == "2 findings"
    assert _module_summary("sql_injection", {"status": "completed", "total": 1}) == "1 findings"
    assert _module_summary("http_smuggling", {"status": "completed", "total": 1}) == "1 findings"
    assert _module_summary("idor_probe", {"status": "completed", "total": 2}) == "2 findings"


def test_select_active_modules_rejects_unknown_module():
    with pytest.raises(ValueError, match="unknown_module"):
        _select_active_modules("recon,unknown_module", "")


def test_select_active_modules_rejects_empty_selection():
    with pytest.raises(ValueError, match="No modules selected"):
        _select_active_modules("recon", "recon")
