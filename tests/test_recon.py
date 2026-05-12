from modules.recon import ReconModule


def test_merge_subdomains_rejects_boundary_bypass(tmp_path):
    module = ReconModule("example.com", str(tmp_path), {})

    added = module._merge_subs(
        ["www.example.com", "*.api.example.com", "evil-example.com", "example.org"],
        "test",
    )

    assert added == 2
    assert "www.example.com" in module.subdomains
    assert "api.example.com" in module.subdomains
    assert "evil-example.com" not in module.subdomains


def test_get_json_uses_standard_json_parser(tmp_path, monkeypatch):
    module = ReconModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "_get_text", lambda *args, **kwargs: '{"ok": true}')

    assert module._get_json("unit", "https://example.com") == {"ok": True}


def test_shodan_api_extracts_domain_subdomains(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"shodan": "token"}},
    )
    monkeypatch.setattr(module, "_request_json", lambda *args, **kwargs: {
        "subdomains": ["www", "*.api"],
        "data": [{"subdomain": "mail"}],
    })

    hosts = module._api_shodan()

    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "mail.example.com" in hosts


def test_censys_uses_platform_token_without_api_id(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"censys_api_secret": "secret"}},
    )
    monkeypatch.setattr(module, "_post_json", lambda *args, **kwargs: {
        "result": {"hits": [{"web": {"name": "app.example.com"}}]}
    })

    assert module._api_censys() == ["app.example.com"]


def test_censys_uses_legacy_auth_when_api_id_is_present(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"censys_api_id": "id", "censys_api_secret": "secret"}},
    )
    monkeypatch.setattr(module, "_request_json", lambda *args, **kwargs: {
        "result": {"hits": [{"name": "legacy.example.com"}]}
    })

    assert module._api_censys() == ["legacy.example.com"]


def test_github_api_extracts_subdomains(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"github": "token"}},
    )
    monkeypatch.setattr(module, "_request_json", lambda *args, **kwargs: {
        "items": [{"html_url": "https://github.com/acme/repo", "fragment": "dev.example.com"}]
    })

    assert module._api_github() == ["dev.example.com"]
