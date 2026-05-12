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


def test_subprocess_env_passes_wpscan_token_from_config(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"wpscan": "wpscan-token"}},
        tech_results={},
    )

    assert module._subprocess_env()["WPSCAN_API_TOKEN"] == "wpscan-token"
