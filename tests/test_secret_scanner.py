import subprocess

from modules.api_key_validator import APIKeyValidatorModule
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

    clone_urls = [repo["clone_url"] for repo in repos]
    assert clone_urls == [
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
                "Secret": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                "Match": "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            }
        ], report_path.replace(str(module.module_dir) + "/", ""))
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(module, "exec", fake_exec)

    findings = module._scan(str(tmp_path), repo_url="https://github.com/example/app.git")

    assert findings[0]["source"] == "secret_scanner"
    assert findings[0]["id"] == "generic-api-key"
    assert findings[0]["url"] == "https://github.com/example/app.git"
    assert findings[0]["evidence"]["file"] == "config/settings.py"
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in str(findings[0]["evidence"]["raw"])
    assert findings[0]["evidence"]["raw"]["Secret"].startswith("ghp_...")


def test_api_validator_uses_one_redacted_gitleaks_candidate(tmp_path):
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    scanner = SecretScannerModule("example.com", str(tmp_path), {})
    finding = scanner._normalize_secret(
        {
            "RuleID": "generic-api-key",
            "File": "config/settings.py",
            "Fingerprint": "abc",
            "Secret": secret,
            "Match": f"token={secret}",
        },
        "https://github.com/example/app.git",
    )
    validator = APIKeyValidatorModule(
        "example.com",
        str(tmp_path),
        {"scan": {"api_key_validator": {"live_validation": True}}},
        secret_results={"findings": [finding]},
    )

    result = validator.run()

    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "github_token"
    assert result["findings"][0]["evidence"]["validation"]["reason"] == "raw_secret_unavailable"


def test_github_token_from_config_when_env_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    module = SecretScannerModule("example.com", str(tmp_path), {"api_keys": {"github": "cfg-tok"}})
    assert module._github_token() == "cfg-tok"


def test_github_token_env_wins_over_config(tmp_path, monkeypatch):
    # .env / GITHUB_TOKEN is authoritative and must override a config token.
    monkeypatch.setenv("GITHUB_TOKEN", "env-tok")
    module = SecretScannerModule("example.com", str(tmp_path), {"api_keys": {"github": "cfg-tok"}})
    assert module._github_token() == "env-tok"
