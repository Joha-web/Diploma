import json
import subprocess

from modules.command_injection import CommandInjectionModule


def _module(tmp_path, cfg=None, **kwargs):
    config = {"scope": {"enforce": False},
              "scan": {"command_injection": cfg or {"exec_prescreen": False, "commix": False, "ffuf": False}}}
    return CommandInjectionModule("example.com", str(tmp_path), config, **kwargs)


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def test_score_command_params():
    s, reasons = CommandInjectionModule._score("host", "8.8.8.8", "/network/ping.php")
    assert s >= 0.9 and any("host/IP" in r for r in reasons)

    s, _ = CommandInjectionModule._score("cmd", "ls", "/exec")
    assert s >= 0.7

    s, _ = CommandInjectionModule._score("file", "report.pdf", "/download")
    assert 0.3 <= s < 0.5  # medium name + filename value → possible

    assert CommandInjectionModule._score("q", "shoes", "/search")[0] == 0.0


def test_collect_and_rank_candidates(tmp_path):
    module = _module(
        tmp_path,
        parameter_results={"parameters": [
            {"url": "https://example.com/ping?host=8.8.8.8", "param": "host"},
            {"url": "https://example.com/search?q=x", "param": "q"},
        ]},
    )
    cands = {c["param"]: c for c in module._collect_candidates()}
    assert cands["host"]["score"] >= 0.9
    assert "q" not in cands or cands["q"]["score"] == 0.0


def test_build_targets_limits_to_likely(tmp_path):
    module = _module(tmp_path)
    scored = [
        {"url": "u1", "param": "cmd", "score": 0.9},
        {"url": "u2", "param": "file", "score": 0.35},
    ]
    likely = module._build_targets(scored, strong=0.5, cfg={"max_targets": 5})
    assert [c["param"] for c in likely] == ["cmd"]


def test_exec_prescreen_force_promotes_on_execution(tmp_path):
    module = _module(tmp_path, cfg={"exec_prescreen": True, "commix": False, "ffuf": False},
                     parameter_results={"parameters": [{"url": "https://example.com/x?ref=abc", "param": "ref"}]})

    # Simulate the echo+arithmetic payload executing: marker followed by 38027.
    def fake_get(url, **kw):
        import re
        from urllib.parse import unquote
        m = re.search(r"CMDX[0-9A-F]{6}", unquote(url))
        return _Resp(text=(m.group(0) + "38027") if m else "no exec")

    import types
    module.http_get = types.MethodType(lambda self, url, **kw: fake_get(url), module)
    cands = module._collect_candidates()
    module._exec_prescreen(cands, {"prescreen_min_score": 0.0})
    ref = next(c for c in cands if c["param"] == "ref")
    assert ref["score"] >= 0.95 and ref.get("exec_confirmed")


def test_parse_commix_hit_builds_critical_finding(tmp_path):
    module = _module(tmp_path)
    cand = {"url": "https://example.com/ping?host=x", "param": "host", "path": "/ping",
            "score": 0.95, "reasons": ["name host"]}
    out = "[*] testing...\n(!) The (GET) 'host' parameter is vulnerable to (results-based) command injection.\n"
    # commix now streams to a file (shell redirect); emulate that, including a
    # timeout-kill (empty stdout) so the file-read path is what yields the finding.
    import subprocess as sp

    def fake_exec(cmd, timeout=300, label=None, **kw):
        (module.module_dir / "commix" / "run_001.txt").write_text(out, encoding="utf-8")
        return sp.CompletedProcess(cmd, 1, "", "timeout")

    module.exec = fake_exec
    findings = module._run_commix(cand, {}, 1)
    assert findings and findings[0]["id"] == "command_injection_detected"
    assert findings[0]["severity"] == "CRITICAL"


def test_run_ffuf_parses_executed_marker_pattern(tmp_path):
    module = _module(tmp_path)
    wl = tmp_path / "cmdi.txt"
    wl.write_text(";echo X\n", encoding="utf-8")
    cand = {"url": "https://example.com/ping?host=x", "param": "host", "path": "/ping",
            "score": 0.9, "reasons": []}

    def fake_exec(cmd, timeout=300, label=None, **kw):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            json.dump({"results": [{"input": {"FUZZ": ";echo ABCDEF$((1+1))$(echo ABCDEF)ABCDEF"},
                                    "status": 200, "url": "https://example.com/ping?host=..."}]}, fh)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    module.exec = fake_exec
    findings = module._run_ffuf(cand, str(wl), {}, 1)
    assert findings and findings[0]["id"] == "command_injection_detected"
    assert findings[0]["evidence"]["tool"] == "ffuf"


def test_run_reports_candidates_only_without_tools(tmp_path):
    module = _module(
        tmp_path,
        parameter_results={"parameters": [{"url": "https://example.com/exec?cmd=ls", "param": "cmd"}]},
    )
    result = module.run()
    assert result["candidate_count"] == 1
    assert any(f["id"] == "cmdi_candidate_parameter" for f in result["findings"])


def test_timing_prescreen_confirms_blind_cmdi(tmp_path, monkeypatch):
    """A sleep payload that delays the response ~N seconds (and ~2N on the
    confirm) flags blind command injection."""
    from urllib.parse import unquote_plus
    import re as _re
    module = _module(tmp_path)
    cand = {"url": "https://example.com/ping?host=8.8.8.8", "param": "host", "value": "8.8.8.8",
            "path": "/ping", "score": 0.9, "reasons": [], "sources": ["t"]}

    def fake_timed_get(url, session, timeout):
        dec = unquote_plus(url)  # a real server decodes '+' in the query to a space
        m = _re.search(r"(?:sleep|ping -[cn]) ?(\d+)", dec)
        return float(m.group(1)) + 0.1 if m else 0.2  # delay == requested sleep

    monkeypatch.setattr(module, "_timed_get", fake_timed_get)
    module._timing_prescreen([cand], {"time_delay": 6})

    assert cand.get("time_confirmed") is True
    assert cand["score"] >= 0.9
    assert any("time-based blind" in r for r in cand["reasons"])


def test_timing_prescreen_no_false_positive_when_no_delay(tmp_path, monkeypatch):
    module = _module(tmp_path)
    cand = {"url": "https://example.com/ping?host=8.8.8.8", "param": "host", "value": "8.8.8.8",
            "path": "/ping", "score": 0.9, "reasons": [], "sources": ["t"]}
    # Endpoint never delays → must not confirm.
    monkeypatch.setattr(module, "_timed_get", lambda url, session, timeout: 0.2)
    module._timing_prescreen([cand], {"time_delay": 6})
    assert not cand.get("time_confirmed")


def test_timing_prescreen_ignores_already_slow_baseline(tmp_path, monkeypatch):
    """If the baseline itself is slow (>= delay), timing is inconclusive — skip."""
    module = _module(tmp_path)
    cand = {"url": "https://example.com/ping?host=8.8.8.8", "param": "host", "value": "8.8.8.8",
            "path": "/ping", "score": 0.9, "reasons": [], "sources": ["t"]}
    monkeypatch.setattr(module, "_timed_get", lambda url, session, timeout: 9.0)  # always slow
    module._timing_prescreen([cand], {"time_delay": 6})
    assert not cand.get("time_confirmed")
