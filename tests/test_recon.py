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
