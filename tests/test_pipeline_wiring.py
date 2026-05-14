from main import CLASS_MAP, MODULE_LABELS, PIPELINE, _build_kwargs, _module_summary


def test_new_modules_are_wired_into_pipeline():
    groups = {step["name"]: step["group"] for step in PIPELINE}

    assert groups["secret_scanner"] == 1
    assert groups["injection_probe"] == 6
    assert CLASS_MAP["secret_scanner"] == ("modules.secret_scanner", "SecretScannerModule")
    assert CLASS_MAP["injection_probe"] == ("modules.injection_probe", "InjectionProbeModule")
    assert MODULE_LABELS["injection_probe"] == "SSRF / SSTI / XXE Detection"


def test_injection_probe_kwargs_use_parameter_and_fuzzer_results():
    all_results = {
        "parameter_discovery": {"parameters": [{"url": "https://example.com", "param": "q"}]},
        "fuzzer": {"classified": {"with_params": ["https://example.com/?q=x"]}},
    }

    kwargs = _build_kwargs("injection_probe", all_results)

    assert kwargs["parameter_results"] is all_results["parameter_discovery"]
    assert kwargs["fuzzer_results"] is all_results["fuzzer"]


def test_new_module_summaries():
    assert _module_summary("secret_scanner", {"status": "completed", "total": 2}) == "2 git secret finding(s)"
    assert _module_summary("injection_probe", {"status": "completed", "total": 3}) == "3 injection finding(s)"
