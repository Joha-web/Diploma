import json

from modules.cmscan import CMS_SCANNERS, CMSScanModule


def test_wpscan_token_prefers_cms_config(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSCAN_API_TOKEN", "env-token")
    module = CMSScanModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"wpscan": "api-key-token"}},
        tech_results={},
    )

    token = module._wpscan_api_token({"wpscan_api_token": "cms-token"})

    assert token == "cms-token"


def test_wpscan_token_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSCAN_API_TOKEN", "env-token")
    module = CMSScanModule("example.com", str(tmp_path), {}, tech_results={})

    token = module._wpscan_api_token({})

    assert token == "env-token"


def test_wpscan_command_includes_api_token():
    cmd = CMS_SCANNERS["WordPress"]["build"](
        "https://example.com",
        {"enumerate": "vp", "wpscan_api_token": "test-token"},
    )

    assert "--api-token" in cmd
    assert cmd[cmd.index("--api-token") + 1] == "test-token"


def test_wpscan_command_uses_full_enumeration_by_default():
    cmd = CMS_SCANNERS["WordPress"]["build"]("https://example.com", {})
    assert "-e" in cmd
    assert cmd[cmd.index("-e") + 1] == "ap,at,tt,cb,dbe,u,m"
    # No token → no --api-token flag
    assert "--api-token" not in cmd


def test_joomscan_and_droopescan_use_full_enumeration():
    joom = CMS_SCANNERS["Joomla"]["build"]("https://example.com", {})
    assert joom == ["joomscan", "-u", "https://example.com", "-ec"]

    drupal = CMS_SCANNERS["Drupal"]["build"]("https://example.com", {})
    assert drupal[:3] == ["droopescan", "scan", "drupal"]
    assert drupal[drupal.index("-e") + 1] == "a"


def test_no_wpscan_token_adds_report_notice(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com", str(tmp_path), {},
        tech_results={"hosts": [{"url": "https://example.com",
                                 "technologies": [{"name": "WordPress"}]}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "wpscan")
    monkeypatch.setattr(module, "exec",
                        lambda *a, **k: __import__("subprocess").CompletedProcess(a, 0, "{}", ""))

    result = module.run()

    assert result["wordpress_detected"] is True
    assert result["wpscan_api_token_used"] is False
    notices = [f for s in result["scans"] for f in s["findings"]
               if f["type"] == "wpscan_no_api_token"]
    assert len(notices) == 1


def test_wpscan_token_present_no_notice(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com", str(tmp_path), {"api_keys": {"wpscan": "tok"}},
        tech_results={"hosts": [{"url": "https://example.com",
                                 "technologies": [{"name": "WordPress"}]}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "wpscan")
    monkeypatch.setattr(module, "exec",
                        lambda *a, **k: __import__("subprocess").CompletedProcess(a, 0, "{}", ""))

    result = module.run()

    assert result["wpscan_api_token_used"] is True
    notices = [f for s in result["scans"] for f in s["findings"]
               if f["type"] == "wpscan_no_api_token"]
    assert notices == []


def test_subprocess_env_passes_wpscan_token_from_config(tmp_path, monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    module = CMSScanModule(
        "example.com",
        str(tmp_path),
        {"api_keys": {"wpscan": "wpscan-token"}},
        tech_results={},
    )

    assert module._subprocess_env()["WPSCAN_API_TOKEN"] == "wpscan-token"


def test_cmscan_reads_findings_from_streamed_file_on_timeout(tmp_path, monkeypatch):
    """wpscan output is streamed to a file; a confirmed finding must survive a
    timeout-kill (exec returns empty stdout) by being read back from the file."""
    import subprocess
    module = CMSScanModule(
        "example.com", str(tmp_path), {"api_keys": {"wpscan": "tok"}},
        tech_results={"hosts": [{"url": "https://example.com",
                                 "technologies": [{"name": "WordPress"}]}]},
    )
    monkeypatch.setattr(module, "has_tool", lambda t: t == "wpscan")
    wp_json = '{"version": {"number": "4.0", "status": "insecure"}}'

    def fake_exec(cmd, timeout=600, shell=False, label=None, **k):
        # cmd is the shell string "... > <stdout> 2> <stderr>" — write to the
        # stdout path, then return a timeout-like result with NO stdout.
        path = cmd.split("> ", 1)[1].split(" 2> ", 1)[0].strip().strip("'")
        with open(path, "w") as fh:
            fh.write(wp_json)
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")

    monkeypatch.setattr(module, "exec", fake_exec)
    result = module.run()

    types = {f.get("type") for s in result["scans"] for f in s["findings"]}
    assert "outdated_core" in types   # parsed from the streamed file despite the timeout


def test_wpscan_parses_core_theme_and_interesting_findings(tmp_path):
    module = CMSScanModule("example.com", str(tmp_path), {}, tech_results={})
    wp_json = json.dumps({
        "version": {
            "number": "5.1", "status": "insecure",
            "vulnerabilities": [{
                "title": "Core RCE",
                "references": {"cve": ["2019-1234"]},
                "cvss": {"score": 9.8},
            }],
        },
        "plugins": {
            "contact-form-7": {"version": {"number": "1.0"}, "vulnerabilities": [{
                "title": "CF7 XSS",
                "references": {"cve": ["CVE-2020-9999"]},
                "cvss": {"score": 6.1},
            }]},
        },
        "main_theme": {"slug": "twentytwenty", "vulnerabilities": [{
            "title": "Theme SQLi", "references": {"cve": ["2021-1111"]},
        }]},
        "interesting_findings": [{
            "type": "db_export", "to_s": "https://example.com/wp-content/db.sql",
            "interesting_entries": ["https://example.com/wp-content/db.sql"],
        }],
        "users": {"1": {"username": "admin"}},
    })
    findings = module._parse_wpscan(wp_json)
    by_type = {f["type"]: f for f in findings}

    # Core CVE is captured (previously only outdated_core status was) and rated
    # from its CVSS score.
    assert by_type["vulnerable_core"]["severity"] == "CRITICAL"
    assert by_type["vulnerable_core"]["cve"] == ["CVE-2019-1234"]
    # Plugin severity comes from CVSS (6.1 -> MEDIUM), CVE normalised.
    assert by_type["vulnerable_plugin"]["severity"] == "MEDIUM"
    assert by_type["vulnerable_plugin"]["cve"] == ["CVE-2020-9999"]
    # The active main theme is scanned even though it lives under its own key;
    # no CVSS -> falls back to the MEDIUM floor (not silently LOW).
    assert by_type["vulnerable_theme"]["severity"] == "MEDIUM"
    assert by_type["vulnerable_theme"]["cve"] == ["CVE-2021-1111"]
    # interesting_findings (db export from the dbe enumeration) surfaces.
    assert "interesting_db_export" in by_type
    assert "outdated_core" in by_type
    assert "user_enumerated" in by_type


def test_wpscan_malformed_json_falls_back_to_generic(tmp_path):
    module = CMSScanModule("example.com", str(tmp_path), {}, tech_results={})
    # Not JSON, but contains keyword-scrapable content (e.g. partial output).
    findings = module._parse_wpscan("[!] Found CVE-2017-1000 in core\nrandom banner")
    assert any("CVE-2017-1000" in f.get("title", "") for f in findings)


def test_detect_cms_skips_entries_without_url(tmp_path):
    module = CMSScanModule(
        "example.com", str(tmp_path),
        {}, tech_results={
            "hosts": [{"url": "", "technologies": [{"name": "WordPress"}]}],
            "cms_detected": [{"name": "Joomla", "url": ""}],
        },
    )
    # Empty URLs must not slip through (would launch a scanner against --url "").
    assert module._detect_cms() == {}
