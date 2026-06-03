import subprocess

from modules.ssrf_probe import SSRFProbeModule


def _module(tmp_path, **kwargs):
    config = {"scope": {"enforce": False}, "scan": {"ssrf_probe": {"use_ssrfmap": False}}}
    return SSRFProbeModule("example.com", str(tmp_path), config, **kwargs)


def test_score_url_value_plus_name_plus_path_is_strong(tmp_path):
    module = _module(tmp_path)
    score, reasons = module._score("url", "https://x.com/a", "/api/preview")
    assert score >= 0.6
    assert any("value is a URL" in r for r in reasons)
    assert any("SSRF-prone" in r for r in reasons)
    assert any("URL fetch" in r for r in reasons)


def test_score_plain_text_param_is_skipped(tmp_path):
    module = _module(tmp_path)
    score, _ = module._score("q", "shoes", "/search")
    assert score < 0.35


def test_score_id_param_is_zero(tmp_path):
    module = _module(tmp_path)
    score, reasons = module._score("id", "42", "/list")
    assert score == 0.0
    assert reasons == []


def test_collect_candidates_ranks_and_dedupes(tmp_path):
    module = _module(
        tmp_path,
        parameter_results={"parameters": [
            {"url": "https://example.com/api/preview?url=https://intra.x", "param": "url"},
            {"url": "https://example.com/items?id=5", "param": "id"},
        ]},
        fuzzer_results={"classified": {"with_params": [
            "https://example.com/fetch?target=10.0.0.1",
        ]}},
    )
    cands = {(c["param"]) : c for c in module._collect_candidates()}
    assert cands["url"]["score"] >= 0.6           # url value + name + /preview path
    assert cands["target"]["score"] >= 0.35       # host value + name + /fetch path
    assert "id" not in cands or cands["id"]["score"] < 0.35


def test_injection_probe_findings_force_promoted(tmp_path):
    module = _module(
        tmp_path,
        injection_results={"findings": [{
            "id": "ssrf_oob_callback", "url": "https://example.com/x?weird=1",
            "evidence": {"param": "weird", "value": "1"},
        }]},
    )
    cands = module._collect_candidates()
    weird = next(c for c in cands if c["param"] == "weird")
    assert weird["score"] >= 0.95
    assert weird["forced"] is True


def test_run_scores_candidates_and_reports_when_ssrfmap_missing(tmp_path, monkeypatch):
    module = SSRFProbeModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False}, "scan": {"ssrf_probe": {}}},
        parameter_results={"parameters": [
            {"url": "https://example.com/proxy?url=https://intra", "param": "url"},
        ]},
    )
    # SSRFmap not installed → still scores + reports candidates.
    monkeypatch.setattr(module, "_ssrfmap_command", lambda cfg: None)
    result = module.run()
    assert result["candidate_count"] == 1
    assert result["ssrfmap_used"] is False
    assert result["findings"][0]["id"] == "ssrf_candidate_parameter"


def test_run_skips_ssrfmap_when_use_ssrfmap_false(tmp_path, monkeypatch):
    module = SSRFProbeModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False}, "scan": {"ssrf_probe": {"use_ssrfmap": False}}},
        parameter_results={"parameters": [
            {"url": "https://example.com/proxy?url=https://intra", "param": "url"},
        ]},
    )
    # Even if SSRFmap is installed, use_ssrfmap:false must not run it.
    monkeypatch.setattr(module, "_ssrfmap_command", lambda cfg: ["python3", "/opt/SSRFmap/ssrfmap.py"])
    called = {"exec": False}
    monkeypatch.setattr(module, "exec", lambda *a, **k: called.__setitem__("exec", True))
    result = module.run()
    assert called["exec"] is False
    assert result["ssrfmap_used"] is False


def test_raw_request_contains_param_and_host(tmp_path):
    module = _module(tmp_path)
    cand = {"url": "https://example.com/proxy?url=https://intra", "method": "GET", "param": "url"}
    raw = module._raw_request(cand)
    assert raw.startswith("GET /proxy?url=https://intra HTTP/1.1")
    assert "Host: example.com" in raw


def test_parse_ssrfmap_flags_internal_hit(tmp_path):
    module = _module(tmp_path)
    cand = {"url": "https://example.com/proxy?url=x", "param": "url", "path": "/proxy",
            "score": 0.9, "reasons": ["value is a URL"]}
    output = "[INFO] Testing...\n[OK] port 6379 is open\nami-id\n"
    findings = module._parse_ssrfmap(output, cand, "portscan,aws", "ssrfmap/run_001.txt", 1)
    assert len(findings) == 1
    assert findings[0]["id"] == "ssrfmap_confirmed"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["evidence"]["hits"]


def test_parse_ssrfmap_silent_without_hits(tmp_path):
    module = _module(tmp_path)
    cand = {"url": "https://example.com/proxy?url=x", "param": "url", "path": "/proxy",
            "score": 0.9, "reasons": []}
    assert module._parse_ssrfmap("[INFO] nothing interesting\n", cand, "m", "f", 1) == []


def test_run_ssrfmap_invokes_tool_and_parses(tmp_path, monkeypatch):
    module = SSRFProbeModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"allow_write": True, "ssrf_probe": {"max_targets": 5}}},
        parameter_results={"parameters": [
            {"url": "https://example.com/proxy?url=https://intra", "param": "url"},
        ]},
    )
    monkeypatch.setattr(module, "_ssrfmap_command", lambda cfg: ["python3", "/opt/SSRFmap/ssrfmap.py"])
    captured = {}

    def fake_exec(cmd, timeout=600, label=None, **kw):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "port 6379 is open\n", "")

    monkeypatch.setattr(module, "exec", fake_exec)
    result = module.run()

    assert "-p" in captured["cmd"] and captured["cmd"][captured["cmd"].index("-p") + 1] == "url"
    assert "-m" in captured["cmd"]
    assert any(f["id"] == "ssrfmap_confirmed" for f in result["findings"])
    assert result["ssrfmap_used"] is True
