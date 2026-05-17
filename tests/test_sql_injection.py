import subprocess

from modules.sql_injection import SQLInjectionModule


def test_sql_injection_collects_parameterized_targets(tmp_path):
    module = SQLInjectionModule(
        "example.com",
        str(tmp_path),
        {},
        parameter_results={
            "parameters": [
                {"url": "https://example.com/item", "param": "id"},
                {"url": "https://example.com/list?page=1", "param": "sort"},
            ],
            "parameterized_targets": ["https://example.com/search?q=term"],
        },
        fuzzer_results={
            "classified": {"with_params": ["https://api.example.com/users?user=1"]},
            "all_endpoints": ["https://example.com/plain", "https://example.com/filter?tag=a"],
        },
    )

    targets = module._collect_targets()

    assert {"url": "https://example.com/item?id=reconx", "params": ["id"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://example.com/list?page=1&sort=reconx", "params": ["sort"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://example.com/search?q=term", "params": ["q"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://api.example.com/users?user=1", "params": ["user"], "sources": ["fuzzer"]} in targets
    assert {"url": "https://example.com/filter?tag=a", "params": ["tag"], "sources": ["fuzzer"]} in targets


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
        {"scan": {"sql_injection": {"max_targets": 1}}},
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
        executed["cmd"] = cmd
        executed["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, 0, stdout=sqlmap_output, stderr="")

    monkeypatch.setattr(module, "exec", fake_exec)

    result = module.run()

    assert executed["cmd"][0] == "sqlmap"
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
