from modules.takeover_checker import TakeoverCheckerModule


def test_takeover_checker_matches_known_cname(tmp_path):
    module = TakeoverCheckerModule("example.com", str(tmp_path), {}, recon_results={})

    finding = module._match_cname("docs.example.com", ["docs.github.io"])

    assert finding is not None
    assert finding["provider"] == "github_pages"
    assert finding["severity"] == "MEDIUM"


def test_takeover_checker_requires_provider_domain_boundary(tmp_path):
    module = TakeoverCheckerModule("example.com", str(tmp_path), {}, recon_results={})

    finding = module._match_cname("docs.example.com", ["github.io.attacker.example"])

    assert finding is None


def test_takeover_checker_upgrades_when_body_fingerprint_matches(tmp_path, monkeypatch):
    module = TakeoverCheckerModule(
        "example.com",
        str(tmp_path),
        {},
        recon_results={"subdomains": ["docs.example.com"]},
    )
    monkeypatch.setattr(module, "_cnames", lambda host: ["docs.github.io"])
    monkeypatch.setattr(module, "_body_fingerprint", lambda host, provider: "There isn't a GitHub Pages site here")

    result = module.run()

    assert result["findings"][0]["severity"] == "HIGH"
    assert result["findings"][0]["confidence"] == 0.85
