import subprocess

from modules.secret_scanner import SecretScannerModule


class Response:
    text = ""

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def test_secret_scanner_finds_github_clone_urls(tmp_path, monkeypatch):
    module = SecretScannerModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"github": "gh-token"}, "scan": {"secret_scanner": {"max_repos": 2}}},
    )
    captured = {}

    def fake_http_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return Response({
            "items": [
                {"clone_url": "https://github.com/example/app.git"},
                {"clone_url": "https://github.com/example/api.git"},
                {"html_url": "https://github.com/example/no-clone"},
            ]
        })

    monkeypatch.setattr(module, "http_get", fake_http_get)

    repos = module._find_repos()

    assert repos == [
        "https://github.com/example/api.git",
        "https://github.com/example/app.git",
    ]
    assert "q=example.com" in captured["url"]
    assert captured["kwargs"]["enforce_scope"] is False
    assert captured["kwargs"]["headers"]["Authorization"] == "Bearer gh-token"


def test_secret_scanner_normalizes_gitleaks_findings(tmp_path, monkeypatch):
    module = SecretScannerModule("example.com", str(tmp_path), {})

    def fake_exec(cmd, timeout=120):
        report_path = cmd[cmd.index("--report-path") + 1]
        module.save_json([
            {
                "RuleID": "generic-api-key",
                "File": "config/settings.py",
                "StartLine": 12,
                "Fingerprint": "abc",
            }
        ], report_path.replace(str(module.module_dir) + "/", ""))
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(module, "exec", fake_exec)

    findings = module._scan(str(tmp_path), repo_url="https://github.com/example/app.git")

    assert findings[0]["source"] == "secret_scanner"
    assert findings[0]["id"] == "generic-api-key"
    assert findings[0]["url"] == "https://github.com/example/app.git"
    assert findings[0]["evidence"]["file"] == "config/settings.py"
