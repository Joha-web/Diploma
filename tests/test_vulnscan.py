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

    module._run_nuclei(Path("targets.txt"), Path("out.jsonl"))

    assert "-dashboard" not in captured["cmd"]
