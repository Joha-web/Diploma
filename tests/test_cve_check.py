from modules.cve_check import CVECheckModule


def test_collect_cves_from_vulnscan_and_cms(tmp_path):
    module = CVECheckModule(
        "example.com",
        str(tmp_path),
        {},
        vuln_results={"findings": [{
            "name": "Test CVE-2024-12345",
            "severity": "HIGH",
            "matched_url": "https://example.com",
            "template_id": "cves/test",
        }]},
        all_results={"cmscan": {"scans": [{
            "url": "https://example.com",
            "findings": [{"title": "Plugin CVE-2023-9999", "severity": "MEDIUM"}],
        }]}},
    )

    cves = module._collect_cves_from_findings()

    assert "CVE-2024-12345" in cves
    assert "CVE-2023-9999" in cves


def test_dry_run_simulation_never_attempts_attack():
    sim = CVECheckModule._dry_run_simulation("CVE-2024-12345", True, {"matched_url": "https://example.com"})

    assert sim["mode"] == "dry_run"
    assert sim["attempted"] is False
    assert sim["auto_exploit"] is False


def test_collect_components_drops_non_product_fingerprints(tmp_path):
    """WhatWeb meta/header plugins (Title, HttpOnly, X-UA-Compatible) must not
    become searchsploit queries; real products (PHP) must survive."""
    module = CVECheckModule(
        "kimep.kz", str(tmp_path), {"scope": {"enforce": False}},
        tech_results={"hosts": [{
            "url": "https://www3.kimep.kz",
            "technologies": [
                {"name": "Title", "version": "8.5", "source": "whatweb"},
                {"name": "HttpOnly", "version": "1.0", "source": "whatweb"},
                {"name": "X-UA-Compatible", "version": "8", "source": "whatweb"},
                {"name": "PHP", "version": "7.2.14", "source": "whatweb"},
            ],
        }]},
    )

    queries = {c["query"] for c in module._collect_components()}

    assert "PHP 7.2.14" in queries
    assert not any(q.startswith(("Title", "HttpOnly", "X-UA-Compatible")) for q in queries)


def test_relevant_matches_rejects_substring_collision(tmp_path):
    """The kimep.kz regression: component 'Title' must not match EDB-42145
    ('...Userspace Entitlement Checking...') via the 'enTITLEment' substring."""
    module = CVECheckModule("kimep.kz", str(tmp_path), {})
    edb_42145 = {
        "edb_id": "42145", "type": "local", "platform": "multiple",
        "title": "Apple macOS 10.12.3 / iOS < 10.3.2 - Userspace Entitlement Checking Race Condition",
    }
    assert module._relevant_matches("Title", [edb_42145]) == []


def test_relevant_matches_filters_irrelevant_php_platform_results(tmp_path):
    """A 'PHP' component must drop unrelated php-platform web apps but keep a
    genuine PHP-runtime exploit whose title names PHP."""
    module = CVECheckModule("kimep.kz", str(tmp_path), {})
    matches = [
        {"edb_id": "51963", "type": "webapps", "title": "Axigen < 10.5.7 - Persistent Cross-Site Scripting"},
        {"edb_id": "44272", "type": "webapps", "title": "Bacula-Web < 8.0.0-rc2 - SQL Injection"},
        # "PHP" only in the description segment — must NOT count (real kimep case).
        {"edb_id": "17330", "type": "webapps", "title": "cPanel < 11.25 - Cross-Site Request Forgery (Add User PHP Script)"},
        {"edb_id": "1", "type": "remote", "title": "PHP 7.2 - Remote Code Execution"},
    ]
    relevant = module._relevant_matches("PHP", matches)

    ids = {m["edb_id"] for m in relevant}
    assert ids == {"1"}


def test_relevant_matches_drops_noise_exploit_types(tmp_path):
    module = CVECheckModule("kimep.kz", str(tmp_path), {})
    matches = [{"edb_id": "9", "type": "papers", "title": "jQuery Security Whitepaper"}]
    assert module._relevant_matches("jQuery", matches) == []
