from pathlib import Path

from modules.vulnscan import VulnScanModule


def test_nuclei_dashboard_flag_requires_pdcp_key(tmp_path, monkeypatch):
    module = VulnScanModule(
        "example.com",
        str(tmp_path),
        {
            "api_keys": {"pdcp": "pdcp-token"},
            "scan": {"nuclei": {"dashboard_upload": True}},
        },
    )
    captured = {}
    monkeypatch.setattr(module, "exec", lambda cmd, timeout=300: captured.setdefault("cmd", cmd))
    monkeypatch.setattr(module, "_line_count", lambda path: 1)
    monkeypatch.setattr(module, "has_tool", lambda tool: False)

    module._run_nuclei(Path("targets.txt"), Path("out.jsonl"))

    assert "-dashboard" in captured["cmd"]


def test_nuclei_dashboard_flag_not_added_without_pdcp_key(tmp_path, monkeypatch):
    module = VulnScanModule(
        "example.com",
        str(tmp_path),
        {"scan": {"nuclei": {"dashboard_upload": True}}},
    )
    captured = {}
    monkeypatch.setattr(module, "exec", lambda cmd, timeout=300: captured.setdefault("cmd", cmd))
    monkeypatch.setattr(module, "_line_count", lambda path: 1)
    monkeypatch.setattr(module, "has_tool", lambda tool: False)

    module._run_nuclei(Path("targets.txt"), Path("out.jsonl"))

    assert "-dashboard" not in captured["cmd"]


def test_oob_disabled_adds_no_interactsh_flag(tmp_path):
    module = VulnScanModule("example.com", str(tmp_path), {"scan": {"nuclei": {}}})
    cmd = ["nuclei"]

    runtime = module._apply_oob_flags(cmd, {"oob": {"enabled": False}})

    assert "-ni" in cmd
    assert runtime["enabled"] is False


def test_interactsh_callback_parser_and_server_derivation(tmp_path):
    module = VulnScanModule("example.com", str(tmp_path), {})

    callback = module._extract_interactsh_callback("[INF] abc123.oast.pro")

    assert callback == "abc123.oast.pro"
    assert module._server_from_callback(callback) == "https://oast.pro"
