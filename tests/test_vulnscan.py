from pathlib import Path

import modules.vulnscan as vulnscan_module
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


def test_waf_detection_selects_waf_rate_limit(tmp_path, monkeypatch):
    module = VulnScanModule(
        "example.com",
        str(tmp_path),
        {"scan": {"nuclei": {"rate_limit": 100, "waf_rate_limit": 7}}},
        tech_results={"hosts": [{"waf": ["Cloudflare"], "technologies": []}]},
    )
    captured = {}
    monkeypatch.setattr(module, "exec", lambda cmd, timeout=300: captured.setdefault("cmd", cmd))
    monkeypatch.setattr(module, "_line_count", lambda path: 1)
    monkeypatch.setattr(module, "has_tool", lambda tool: False)

    module._run_nuclei(Path("targets.txt"), Path("out.jsonl"))

    rl_index = captured["cmd"].index("-rl")
    assert captured["cmd"][rl_index + 1] == "7"
    assert module.nuclei_runtime["rate_limit"] == 7
    assert module.nuclei_runtime["waf_detected"] is True


def test_oob_process_is_kept_out_of_json_runtime(tmp_path, monkeypatch):
    module = VulnScanModule("example.com", str(tmp_path), {})

    class FakeProcess:
        pid = 12345

        def poll(self):
            return None

        def wait(self, timeout=0):
            return 0

        def kill(self):
            return None

    fake_proc = FakeProcess()
    monkeypatch.setattr(vulnscan_module.subprocess, "Popen", lambda *args, **kwargs: fake_proc)
    monkeypatch.setattr(module, "_read_interactsh_callback", lambda proc, timeout=10: "abc123.oast.pro")
    monkeypatch.setattr(vulnscan_module.os, "killpg", lambda pid, sig: None)

    runtime = module._start_interactsh_client({})

    assert runtime["client_started"] is True
    assert runtime["callback_url"] == "abc123.oast.pro"
    assert "_process" not in runtime
    assert module._oob_process is fake_proc

    module._stop_oob_client(runtime)

    assert module._oob_process is None


def test_nuclei_zero_findings_on_live_targets_records_warning(tmp_path, monkeypatch):
    module = VulnScanModule("example.com", str(tmp_path), {})
    warnings = []

    monkeypatch.setattr(module, "_extract_urls", lambda: ["https://example.com"])
    monkeypatch.setattr(module, "_update_templates", lambda: None)
    monkeypatch.setattr(module, "_run_nuclei", lambda url_file, out_file: None)
    monkeypatch.setattr(module, "warn", lambda msg: warnings.append(msg))

    result = module.run()

    assert result["total"] == 0
    assert "warning" in result["runtime"]
    assert "Nuclei returned 0 findings" in result["runtime"]["warning"]
    assert warnings
