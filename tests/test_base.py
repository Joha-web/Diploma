from modules.base import BaseModule
from modules.rate_limiter import TokenBucket


class MissingToolModule(BaseModule):
    name = "missing_tool"
    description = "Missing tool test"
    required_tools = ["definitely-not-a-real-reconx-tool"]

    def run(self):
        raise AssertionError("run should not be called when required tools are absent")


def test_exec_returns_interrupted_for_sigint_exit(tmp_path):
    module = BaseModule("example.com", str(tmp_path), {})

    result = module.exec(
        "python3 -c 'import os, signal; os.kill(os.getpid(), signal.SIGINT)'",
        timeout=5,
    )

    assert result.returncode == 130
    assert module.interrupted_commands


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


def test_subprocess_env_includes_configured_cli_tokens(tmp_path, monkeypatch):
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("BINARYEDGE_API_KEY", raising=False)
    module = BaseModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {
            "pdcp": "pdcp-token",
            "github": "github-token",
            "securitytrails": "st-token",
            "binaryedge": "be-token",
        }},
    )

    env = module._subprocess_env()

    assert env["PDCP_API_KEY"] == "pdcp-token"
    assert env["GITHUB_TOKEN"] == "github-token"
    assert env["SECURITYTRAILS_API_KEY"] == "st-token"
    assert env["BINARYEDGE_API_KEY"] == "be-token"


def test_execute_persists_skipped_result_when_required_tools_missing(tmp_path):
    module = MissingToolModule("example.com", str(tmp_path), {})

    result = module.execute()

    results_file = tmp_path / "missing_tool" / "missing_tool_results.json"
    assert result["status"] == "skipped"
    assert result["reason"] == "no_tools"
    assert "elapsed_seconds" in result
    assert results_file.exists()


def test_token_bucket_instances_are_independent():
    first = TokenBucket(rate=1)
    second = TokenBucket(rate=25)

    assert first is not second
    assert first.rate == 1
    assert second.rate == 25


def test_base_module_uses_per_module_rate_limit(tmp_path):
    class CustomRateModule(BaseModule):
        name = "custom_rate"

    module = CustomRateModule(
        "example.com",
        str(tmp_path),
        {"scan": {"global_rate_limit": 50, "custom_rate": {"rate_limit": 7}}},
    )

    assert module.rate_limiter.rate == 7
