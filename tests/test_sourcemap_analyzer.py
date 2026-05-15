from modules.sourcemap_analyzer import SourceMapAnalyzerModule


def test_sourcemap_analyzer_extracts_js_urls_from_fuzzer_results(tmp_path):
    module = SourceMapAnalyzerModule(
        "example.com",
        str(tmp_path),
        {},
        fuzzer_results={
            "all_endpoints": ["https://example.com/app.js", "https://example.com/api"],
            "classified": {"api": ["https://example.com/other.js"]},
        },
    )

    assert module._js_urls() == ["https://example.com/app.js", "https://example.com/other.js"]


def test_sourcemap_analyzer_reports_secret_in_sources_content(tmp_path):
    module = SourceMapAnalyzerModule("example.com", str(tmp_path), {}, fuzzer_results={})
    source_map = {
        "_map_url": "https://example.com/app.js.map",
        "sources": ["src/config.js"],
        "sourcesContent": ['const api_key = "abcdef123456";'],
    }

    _, findings = module._analyse_map("https://example.com/app.js", source_map)

    assert any(f["type"] == "sourcemap_secret" for f in findings)
    assert any(f["type"] == "sourcemap_interesting_path" for f in findings)
    secret = next(f for f in findings if f["type"] == "sourcemap_secret")
    assert "abcdef123456" not in secret["evidence"]["match"]
    assert secret["evidence"]["fingerprint"]
