from modules.vhost_enum import VHostEnumModule


class Response:
    def __init__(self, status_code=200, content=b""):
        self.status_code = status_code
        self.content = content


def test_vhost_baseline_does_not_follow_redirects_and_marks_wildcard(tmp_path, monkeypatch):
    module = VHostEnumModule("example.com", str(tmp_path), {})
    captured = {}

    def fake_http_get(*args, **kwargs):
        captured.update(kwargs)
        return Response(status_code=301, content=b"redirect")

    monkeypatch.setattr(module, "http_get", fake_http_get)

    size = module._baseline_size("192.0.2.10")

    assert size == "8"
    assert captured["allow_redirects"] is False
    assert module._vhost_baseline_redirect is True


def test_vhost_ffuf_excludes_redirect_match_codes_for_wildcard_301(tmp_path, monkeypatch):
    module = VHostEnumModule(
        "example.com",
        str(tmp_path),
        {"scan": {"vhost_enum": {"enabled": True, "max_ips": 1}}},
        resolved_ips=["192.0.2.10"],
    )
    captured = {}

    def fake_baseline(ip):
        module._vhost_baseline_redirect = True
        return "162"

    monkeypatch.setattr(module, "_wordlist", lambda filename: "/tmp/subdomains.txt")
    monkeypatch.setattr(module, "_baseline_size", fake_baseline)
    monkeypatch.setattr(module, "exec", lambda cmd, **kwargs: captured.setdefault("cmd", cmd))
    monkeypatch.setattr(module, "load_json", lambda path: {"results": []})

    result = module.run()

    cmd = captured["cmd"]
    assert result["total"] == 0
    assert cmd[cmd.index("-mc") + 1] == "200,201,204,401,403"
    assert cmd[cmd.index("-fc") + 1] == "301,302,307,308"
