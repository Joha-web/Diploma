import json

from modules.techstack import TechStackModule


def _module(tmp_path):
    return TechStackModule("example.com", str(tmp_path), {"scope": {"enforce": False}})


def test_whatweb_skips_metadata_plugins_keeps_products(tmp_path):
    """WhatWeb header/metadata plugins (Title, X-UA-Compatible, HttpOnly,
    MetaGenerator) must NOT be ingested as technologies; real products are."""
    module = _module(tmp_path)
    raw = module.module_dir / "whatweb_raw.txt"
    raw.write_text(
        "http://example.com [200 OK] Apache[2.4.41], PHP[7.4.3], Title[Welcome Home], "
        "X-UA-Compatible[IE=edge], HttpOnly[1], MetaGenerator[WordPress 6.0], "
        "HTTPServer[Apache/2.4.41], X-Powered-By[PHP/7.4.3]\n",
        encoding="utf-8",
    )
    host = module._parse_whatweb(raw)["http://example.com"]
    names = {t["name"] for t in host["technologies"]}

    assert "Apache" in names and "PHP" in names      # real products kept
    assert host["server"] == "Apache"                # HTTPServer → server
    for junk in ("Title", "X-UA-Compatible", "HttpOnly", "MetaGenerator"):
        assert junk not in names, f"{junk} should be skipped, not a technology"


def test_parse_plugins_handles_nested_brackets():
    plugins = TechStackModule._parse_plugins("Apache[2.4], Script[text/javascript[v2]], PHP")
    assert plugins["Apache"] == "2.4"
    assert plugins["Script"] == "text/javascript[v2]"   # nested brackets preserved
    assert "PHP" in plugins


def test_nuclei_parse_reads_host_and_extracted_results(tmp_path):
    module = _module(tmp_path)
    raw = module.module_dir / "nuclei_tech.jsonl"
    raw.write_text(
        json.dumps({"host": "https://example.com", "info": {"name": "WordPress"},
                    "extracted_results": ["6.0"]}) + "\n",
        encoding="utf-8",
    )
    tech = module._parse_nuclei(raw)["https://example.com"]["technologies"][0]
    assert tech["name"] == "WordPress" and tech["version"] == "6.0"
