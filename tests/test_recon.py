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


def test_securitytrails_api_extracts_subdomains(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"securitytrails": "token"}},
    )
    monkeypatch.setattr(module, "_request_json", lambda *args, **kwargs: {
        "subdomains": ["www", "api", "*.mail"]
    })

    hosts = module._api_securitytrails()

    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "mail.example.com" in hosts


def test_binaryedge_api_extracts_subdomains(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"binaryedge": "token"}},
    )
    monkeypatch.setattr(module, "_request_json", lambda *args, **kwargs: {
        "events": ["dev.example.com", "staging.example.com"]
    })

    hosts = module._api_binaryedge()

    assert "dev.example.com" in hosts
    assert "staging.example.com" in hosts


def test_collect_urls_feeds_waybackurls_via_stdin_pipeline(tmp_path, monkeypatch):
    module = ReconModule("example.com", str(tmp_path), {})
    calls = []

    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "waybackurls")

    def fake_exec(cmd, timeout=300, capture=True, shell=False, label=None):
        calls.append({"cmd": cmd, "shell": shell, "label": label})
        class Result:
            stdout = "https://www.example.com/login\n"
        return Result()

    monkeypatch.setattr(module, "exec", fake_exec)

    result = module._collect_urls()

    assert result["total"] == 1
    assert calls[0]["shell"] is True
    assert "waybackurls" in calls[0]["cmd"]
    assert calls[0]["label"] == "waybackurls"


def test_active_dns_bruteforce_uses_dnsx_wordlist_domain_flags(tmp_path, monkeypatch):
    module = ReconModule("example.com", str(tmp_path), {})
    captured = {}

    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "dnsx")
    monkeypatch.setattr(module, "_subdomain_wordlist", lambda filename: "/tmp/subs.txt")

    def fake_exec(cmd, timeout=300, capture=True, shell=False, label=None):
        captured["cmd"] = cmd
        class Result:
            stdout = "www.example.com [A] [192.0.2.10]\n"
        return Result()

    monkeypatch.setattr(module, "exec", fake_exec)

    added = module._active_dns_bruteforce({"active_wordlist": "subs.txt"})

    assert added == 1
    assert captured["cmd"][:5] == ["dnsx", "-d", "example.com", "-w", "/tmp/subs.txt"]
    assert "-silent" in captured["cmd"]
    assert "-a" in captured["cmd"]


def test_email_security_generates_requested_findings(tmp_path):
    module = ReconModule("example.com", str(tmp_path), {})

    result = module._analyze_email_security({})

    names = {finding["name"] for finding in result["findings"]}
    assert "Email spoofing possible" in names
    assert "Phishing risk" in names


def test_asn_filter_excludes_cdn_cloud_ips_from_scan_targets(tmp_path):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"scan": {"subdomains": {"exclude_cdn_ips": True}}},
    )
    module.resolved_ips = {"192.0.2.10", "198.51.100.20"}

    scan_ips = module._scan_target_ips([
        {"network": "192.0.2.0/24", "cdn_or_cloud_hint": True},
        {"network": "198.51.100.0/24", "cdn_or_cloud_hint": False},
    ])

    assert scan_ips == ["198.51.100.20"]
    assert (tmp_path / "recon" / "dns" / "excluded_cdn_ips.json").exists()
