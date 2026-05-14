from main import CLASS_MAP, MODULE_LABELS, PIPELINE, _build_kwargs, _module_summary


def test_new_modules_are_wired_into_pipeline():
    groups = {step["name"]: step["group"] for step in PIPELINE}
    active_modules = {
        "http_smuggling": ("modules.http_smuggling", "HTTPSmugglingModule"),
        "oauth_probe": ("modules.oauth_probe", "OAuthProbeModule"),
        "cache_poison": ("modules.cache_poison", "CachePoisonModule"),
        "host_header_injection": ("modules.host_header_injection", "HostHeaderInjectionModule"),
        "prototype_pollution": ("modules.prototype_pollution", "PrototypePollutionModule"),
        "xxe_probe": ("modules.xxe_probe", "XXEProbeModule"),
        "deserialization_probe": ("modules.deserialization_probe", "DeserializationProbeModule"),
        "graphql_audit": ("modules.graphql_audit", "GraphQLAuditModule"),
        "race_condition": ("modules.race_condition", "RaceConditionModule"),
        "open_redirect_probe": ("modules.open_redirect_probe", "OpenRedirectProbeModule"),
        "api_key_validator": ("modules.api_key_validator", "APIKeyValidatorModule"),
        "jwt_audit": ("modules.jwt_audit", "JWTAuditModule"),
        "websocket_probe": ("modules.websocket_probe", "WebSocketProbeModule"),
        "api_schema_audit": ("modules.api_schema_audit", "APISchemaAuditModule"),
        "js_security_audit": ("modules.js_security_audit", "JSSecurityAuditModule"),
    }
    post_parameter_modules = {
        "injection_probe": ("modules.injection_probe", "InjectionProbeModule"),
        "idor_probe": ("modules.idor_probe", "IDORProbeModule"),
    }

    assert groups["secret_scanner"] == 1
    assert CLASS_MAP["secret_scanner"] == ("modules.secret_scanner", "SecretScannerModule")
    assert CLASS_MAP["injection_probe"] == ("modules.injection_probe", "InjectionProbeModule")
    assert MODULE_LABELS["injection_probe"] == "SSRF / SSTI / XXE Detection"
    for module_name, class_ref in active_modules.items():
        assert groups[module_name] == 6
        assert CLASS_MAP[module_name] == class_ref
    for module_name, class_ref in post_parameter_modules.items():
        assert groups[module_name] == 7
        assert CLASS_MAP[module_name] == class_ref


def test_injection_probe_kwargs_use_parameter_and_fuzzer_results():
    all_results = {
        "parameter_discovery": {"parameters": [{"url": "https://example.com", "param": "q"}]},
        "fuzzer": {"classified": {"with_params": ["https://example.com/?q=x"]}},
    }

    kwargs = _build_kwargs("injection_probe", all_results)

    assert kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_active_probe_kwargs_use_prior_results():
    all_results = {
        "fuzzer": {"classified": {}},
        "openapi_parser": {"endpoints": []},
        "secret_scanner": {"findings": []},
        "webdetect": {"live_urls": ["https://example.com"]},
    }

    assert _build_kwargs("prototype_pollution", all_results)["openapi_results"] is all_results["openapi_parser"]
    assert _build_kwargs("xxe_probe", all_results)["fuzzer_results"] is all_results["fuzzer"]
    assert _build_kwargs("api_key_validator", all_results)["secret_results"] is all_results["secret_scanner"]
    assert _build_kwargs("oauth_probe", all_results)["live_hosts"] == ["https://example.com"]
    assert _build_kwargs("idor_probe", all_results)["openapi_results"] is all_results["openapi_parser"]
    assert _build_kwargs("api_schema_audit", all_results)["openapi_results"] is all_results["openapi_parser"]


def test_new_module_summaries():
    assert _module_summary("secret_scanner", {"status": "completed", "total": 2}) == "2 git secret finding(s)"
    assert _module_summary("injection_probe", {"status": "completed", "total": 3}) == "3 injection finding(s)"
    assert _module_summary("http_smuggling", {"status": "completed", "total": 1}) == "1 findings"
    assert _module_summary("idor_probe", {"status": "completed", "total": 2}) == "2 findings"
