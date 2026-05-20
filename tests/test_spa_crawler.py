import importlib

import modules.spa_crawler as spa_module
from modules.spa_crawler import SPACrawlerModule


def test_spa_crawler_disabled_via_config_returns_disabled(tmp_path):
    module = SPACrawlerModule(
        "example.com",
        str(tmp_path),
        {"scan": {"spa_crawler": {"enabled": False}}},
        live_hosts=["https://example.com"],
    )
    result = module.run()
    assert result["status"] == "disabled"
    assert result["endpoints"] == []


def test_spa_crawler_reports_skipped_when_playwright_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(spa_module, "_HAS_PLAYWRIGHT", False)
    module = SPACrawlerModule(
        "example.com", str(tmp_path), {}, live_hosts=["https://example.com"]
    )
    result = module.run()
    assert result["status"] == "skipped"
    assert result["reason"] == "playwright_not_installed"
    assert result["endpoints"] == []


def test_spa_crawler_returns_zero_when_no_live_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(spa_module, "_HAS_PLAYWRIGHT", True)

    # Stub sync_playwright so we never actually open a browser
    class _Stub:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    monkeypatch.setattr(spa_module, "sync_playwright", lambda: _Stub())
    module = SPACrawlerModule("example.com", str(tmp_path), {}, live_hosts=[])
    result = module.run()
    assert result["total"] == 0
    assert result["endpoints"] == []


def test_spa_module_imports_without_playwright_installed():
    # Re-importing should not raise even if the optional dep is absent.
    reloaded = importlib.reload(spa_module)
    assert hasattr(reloaded, "SPACrawlerModule")
