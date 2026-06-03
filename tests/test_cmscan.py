from modules.cmscan import CMS_SCANNERS, CMSScanModule


def test_wpscan_token_prefers_cms_config(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSCAN_API_TOKEN", "env-token")
    module = CMSScanModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"wpscan": "api-key-token"}},
        tech_results={},
    )

    token = module._wpscan_api_token({"wpscan_api_token": "cms-token"})

    assert token == "cms-token"


def test_wpscan_token_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSCAN_API_TOKEN", "env-token")
    module = CMSScanModule("example.com", str(tmp_path), {}, tech_results={})

    token = module._wpscan_api_token({})

    assert token == "env-token"


def test_wpscan_command_includes_api_token():
    cmd = CMS_SCANNERS["WordPress"]["build"](
        "https://example.com",
        {"enumerate": "vp", "wpscan_api_token": "test-token"},
    )

    assert "--api-token" in cmd
    assert cmd[cmd.index("--api-token") + 1] == "test-token"


def test_wpscan_command_uses_full_enumeration_by_default():
    cmd = CMS_SCANNERS["WordPress"]["build"]("https://example.com", {})
    assert "-e" in cmd
    assert cmd[cmd.index("-e") + 1] == "ap,at,tt,cb,dbe,u,m"
    # No token → no --api-token flag
    assert "--api-token" not in cmd


def test_joomscan_and_droopescan_use_full_enumeration():
    joom = CMS_SCANNERS["Joomla"]["build"]("https://example.com", {})
    assert joom == ["joomscan", "-u", "https://example.com", "-ec"]

    drupal = CMS_SCANNERS["Drupal"]["build"]("https://example.com", {})
    assert drupal[:3] == ["droopescan", "scan", "drupal"]
    assert drupal[drupal.index("-e") + 1] == "a"


def test_no_wpscan_token_adds_report_notice(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com", str(tmp_path), {},
        tech_results={"hosts": [{"url": "https://example.com",
                                 "technologies": [{"name": "WordPress"}]}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "wpscan")
    monkeypatch.setattr(module, "exec",
                        lambda *a, **k: __import__("subprocess").CompletedProcess(a, 0, "{}", ""))

    result = module.run()

    assert result["wordpress_detected"] is True
    assert result["wpscan_api_token_used"] is False
    notices = [f for s in result["scans"] for f in s["findings"]
               if f["type"] == "wpscan_no_api_token"]
    assert len(notices) == 1


def test_wpscan_token_present_no_notice(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com", str(tmp_path), {"api_keys": {"wpscan": "tok"}},
        tech_results={"hosts": [{"url": "https://example.com",
                                 "technologies": [{"name": "WordPress"}]}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "wpscan")
    monkeypatch.setattr(module, "exec",
                        lambda *a, **k: __import__("subprocess").CompletedProcess(a, 0, "{}", ""))

    result = module.run()

    assert result["wpscan_api_token_used"] is True
    notices = [f for s in result["scans"] for f in s["findings"]
               if f["type"] == "wpscan_no_api_token"]
    assert notices == []


def test_subprocess_env_passes_wpscan_token_from_config(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"wpscan": "wpscan-token"}},
        tech_results={},
    )

    assert module._subprocess_env()["WPSCAN_API_TOKEN"] == "wpscan-token"
