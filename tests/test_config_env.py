from main import apply_config_preset, apply_env_overrides


def test_apply_env_overrides_fills_empty_secret_config(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-token")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-token")
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "securitytrails-token")
    monkeypatch.setenv("BINARYEDGE_API_KEY", "binaryedge-token")
    monkeypatch.setenv("GITHUB_TOKEN", "github-token")
    monkeypatch.setenv("PDCP_API_KEY", "pdcp-token")
    monkeypatch.setenv("WPSCAN_API_TOKEN", "wpscan-token")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-token")
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.example:11434")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "telegram-token")

    cfg = apply_env_overrides({})

    assert cfg["api_keys"]["shodan"] == "shodan-token"
    assert cfg["api_keys"]["virustotal"] == "vt-token"
    assert cfg["api_keys"]["securitytrails"] == "securitytrails-token"
    assert cfg["api_keys"]["binaryedge"] == "binaryedge-token"
    assert cfg["api_keys"]["github"] == "github-token"
    assert cfg["api_keys"]["pdcp"] == "pdcp-token"
    assert cfg["api_keys"]["wpscan"] == "wpscan-token"
    assert cfg["ai"]["openai_api_key"] == "openai-token"
    assert cfg["ai"]["ollama_url"] == "http://ollama.example:11434"
    assert cfg["telegram"]["bot_token"] == "telegram-token"


def test_apply_env_overrides_does_not_replace_explicit_config(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "env-token")
    cfg = {"api_keys": {"shodan": "yaml-token"}}

    apply_env_overrides(cfg)

    assert cfg["api_keys"]["shodan"] == "yaml-token"


def test_intrusive_preset_retains_raw_secrets_for_live_validation():
    cfg = apply_config_preset({}, "intrusive")

    assert cfg["scan"]["api_key_validator"]["live_validation"] is True
    assert cfg["scan"]["fuzzing"]["retain_raw_secrets"] is True
    assert cfg["scan"]["secret_scanner"]["retain_raw_secrets"] is True
