import modules.recon as recon_module
from modules.recon import ReconModule


class FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None, headers=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data
        self.headers = headers or {}

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


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


def test_passive_api_retries_rate_limits_before_json_parse(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"scan": {"subdomains": {"api_retries": 1, "api_retry_delay": 0}}},
    )
    responses = [
        FakeResponse(429, headers={"Retry-After": "0"}),
        FakeResponse(200, text='{"ok": true}'),
    ]
    warnings = []

    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(module, "warn", lambda message: warnings.append(message))

    assert module._get_json("alienvault", "https://example.test") == {"ok": True}
    assert any("HTTP 429, retrying" in message for message in warnings)


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


def test_censys_platform_auth_failure_mentions_token_mode(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {
            "api_keys": {"censys_api_secret": "secret"},
            "scan": {"subdomains": {"api_retries": 0}},
        },
    )
    warnings = []

    monkeypatch.setattr(module, "http_post", lambda *args, **kwargs: FakeResponse(403, json_data={}))
    monkeypatch.setattr(module, "warn", lambda message: warnings.append(message))

    assert module._api_censys() == []
    assert any("Platform PAT" in message and "CENSYS_API_ID" in message for message in warnings)


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


def test_dns_record_cleaner_drops_dig_resolver_errors(tmp_path):
    module = ReconModule("example.com", str(tmp_path), {})

    lines = module._clean_dns_lines(
        ";; communications error to 192.168.122.1#53: timed out\n"
        "SERVFAIL\n"
        "198.51.100.10\n"
        "mail.example.com.\n"
        ";; no servers could be reached\n"
    )

    assert lines == ["198.51.100.10", "mail.example.com."]


def test_http_probe_saves_clean_urls_from_httpx_plain_output(tmp_path, monkeypatch):
    module = ReconModule("example.com", str(tmp_path), {})
    module.subdomains = {"www.example.com"}

    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "httpx")

    def fake_exec(cmd, timeout=300, capture=True, shell=False, label=None):
        module.save_text("https://www.example.com [200] [Welcome]\n", "subdomains/httpx_live.txt")
        class Result:
            stdout = ""
        return Result()

    monkeypatch.setattr(module, "exec", fake_exec)

    module._http_probe()

    assert module.live_http == ["https://www.example.com"]


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


def test_asn_lookup_spaces_ipinfo_requests(tmp_path, monkeypatch):
    module = ReconModule(
        "example.com",
        str(tmp_path),
        {"scan": {"subdomains": {
            "use_asn_lookup": True,
            "max_asn_lookups": 2,
            "asn_lookup_delay": 0.25,
        }}},
    )
    module.resolved_ips = {"192.0.2.10", "198.51.100.20"}
    sleeps = []
    urls = []

    monkeypatch.setattr(recon_module.time, "sleep", lambda delay: sleeps.append(delay))

    def fake_request_json(source, url, **kwargs):
        urls.append(url)
        return {"org": "AS64500 Example", "country": "ZZ"}

    monkeypatch.setattr(module, "_request_json", fake_request_json)

    result = module._asn_lookup()

    assert len(result) == 2
    assert len(urls) == 2
    assert sleeps == [0.25]
