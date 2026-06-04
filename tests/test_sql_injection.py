import subprocess

from modules.sql_injection import SQLInjectionModule


def test_sql_injection_scores_candidates():
    score, reasons = SQLInjectionModule._score("id", "42", "/product.php")
    assert score >= 0.9  # numeric value + id name + product path
    assert any("numeric" in r for r in reasons)

    score, _ = SQLInjectionModule._score("sort", "name", "/list")
    assert 0.5 <= score < 0.9  # sort name + ORDER BY bonus + list path

    score, _ = SQLInjectionModule._score("utm_source", "google", "/track")
    assert score == 0.0  # no signals


def test_sql_injection_collects_and_ranks_candidates(tmp_path):
    module = SQLInjectionModule(
        "example.com", str(tmp_path), {"scope": {"enforce": False}},
        parameter_results={"parameters": [
            {"url": "https://example.com/product?id=5", "param": "id"},
            {"url": "https://example.com/track?utm_source=x", "param": "utm_source"},
        ]},
        fuzzer_results={"classified": {"with_params": ["https://example.com/list?sort=name"]}},
    )
    cands = {c["param"]: c for c in module._collect_candidates()}
    assert cands["id"]["score"] >= 0.9
    assert cands["sort"]["score"] >= 0.5
    assert cands["utm_source"]["score"] == 0.0


def test_build_targets_passes_only_likely_params(tmp_path):
    module = SQLInjectionModule("example.com", str(tmp_path), {})
    scored = [
        {"url": "https://example.com/p?id=1&utm=x", "param": "id", "score": 0.9, "sources": ["fuzzer"]},
        {"url": "https://example.com/p?id=1&utm=x", "param": "utm", "score": 0.2, "sources": ["fuzzer"]},
    ]
    targets = module._build_targets(scored, strong=0.5, cfg={"max_targets": 5})
    assert len(targets) == 1
    assert targets[0]["params"] == ["id"]  # low-scoring 'utm' excluded


def test_sql_injection_command_is_conservative_by_default(tmp_path):
    module = SQLInjectionModule("example.com", str(tmp_path), {}, {})
    cmd = module._sqlmap_command(
        {"url": "https://example.com/item?id=1", "params": ["id"]},
        {},
        tmp_path,
    )

    assert cmd[:3] == ["sqlmap", "-u", "https://example.com/item?id=1"]
    assert ["--level", "1"] == [cmd[cmd.index("--level")], cmd[cmd.index("--level") + 1]]
    assert ["--risk", "1"] == [cmd[cmd.index("--risk")], cmd[cmd.index("--risk") + 1]]
    assert ["-p", "id"] == [cmd[cmd.index("-p")], cmd[cmd.index("-p") + 1]]
    assert "--forms" not in cmd
    assert "--crawl" not in cmd


def test_sql_injection_runs_sqlmap_and_parses_findings(tmp_path, monkeypatch):
    module = SQLInjectionModule(
        "example.com",
        str(tmp_path),
        {"scan": {"sql_injection": {"max_targets": 1, "error_prescreen": False}}},
        parameter_results={"parameterized_targets": ["https://example.com/item?id=1"]},
    )
    executed = {}
    sqlmap_output = """
[INFO] testing GET parameter 'id'
sqlmap identified the following injection point(s)
---
Parameter: id (GET)
    Type: boolean-based blind
---
back-end DBMS: MySQL
"""

    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "sqlmap")

    def fake_exec(cmd, timeout=300, capture=True, shell=False, label=None):
        # sqlmap now streams to a file via a shell command; mirror that, and
        # also simulate a timeout (empty stdout) to prove findings survive it.
        executed["cmd"] = cmd
        executed["timeout"] = timeout
        (module.module_dir / "sqlmap_run_001.txt").write_text(sqlmap_output, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")

    monkeypatch.setattr(module, "exec", fake_exec)

    result = module.run()

    # exec receives a shell string (shlex-quoted) with the redirect.
    assert isinstance(executed["cmd"], str)
    assert executed["cmd"].startswith("sqlmap -u ")
    assert "-p id" in executed["cmd"]
    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "sql_injection_sqlmap_1_1"
    assert finding["evidence"]["param"] == "id"
    assert finding["evidence"]["method"] == "GET"
    assert finding["evidence"]["dbms"] == "MySQL"
    assert (tmp_path / "sql_injection" / "sqlmap_run_001.txt").exists()


def test_sql_injection_skips_when_sqlmap_missing(tmp_path, monkeypatch):
    module = SQLInjectionModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "has_tool", lambda tool: False)

    result = module.run()

    assert result["status"] == "skipped"
    assert result["missing_tools"] == ["sqlmap"]


def test_sql_injection_reports_candidates_without_sqlmap(tmp_path, monkeypatch):
    module = SQLInjectionModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False}, "scan": {"sql_injection": {"error_prescreen": False}}},
        parameter_results={"parameters": [{"url": "https://example.com/product?id=5", "param": "id"}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda tool: False)
    result = module.run()
    # sqlmap missing → still emits the scored candidate finding.
    assert result["candidate_count"] == 1
    assert any(f["id"] == "sqli_candidate_parameter" for f in result["findings"])


def test_error_prescreen_force_promotes_on_sql_error(tmp_path, monkeypatch):
    module = SQLInjectionModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False}, "scan": {"sql_injection": {}}},
        parameter_results={"parameters": [{"url": "https://example.com/x?ref=abc", "param": "ref"}]},
    )

    class _R:
        text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"

    monkeypatch.setattr(module, "http_get", lambda url, **kw: _R())
    candidates = module._collect_candidates()
    module._error_prescreen(candidates, {"prescreen_min_score": 0.0})

    ref = next(c for c in candidates if c["param"] == "ref")
    assert ref["score"] >= 0.95
    assert ref.get("error_dbms")
