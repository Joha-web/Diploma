from modules.base import BaseModule


def test_scope_allows_target_and_subdomains(tmp_path):
    module = BaseModule("example.com", str(tmp_path), {"scope": {"enforce": True}})

    assert module.is_in_scope("https://example.com/login")
    assert module.is_in_scope("https://api.example.com/v1")
    assert not module.is_in_scope("https://evil-example.com/")
    assert not module.is_in_scope("https://example.org/")


def test_scope_exclusions_take_priority(tmp_path):
    cfg = {"scope": {"allowed_domains": ["example.com"], "excluded": ["dev.example.com"]}}
    module = BaseModule("example.com", str(tmp_path), cfg)

    assert module.is_in_scope("https://www.example.com/")
    assert not module.is_in_scope("https://dev.example.com/")


def test_scope_ip_requires_allowed_ip(tmp_path):
    module = BaseModule("example.com", str(tmp_path), {"scope": {"allowed_ips": ["192.0.2.10"]}})

    assert module.is_in_scope("http://192.0.2.10:8080/")
    assert not module.is_in_scope("http://192.0.2.11:8080/")
