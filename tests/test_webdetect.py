from modules.webdetect import WebdetectModule


def test_webdetect_attaches_screenshot_by_hostname(tmp_path):
    module = WebdetectModule("example.com", str(tmp_path), {})
    live = [{"url": "https://app.example.com", "screenshot": ""}]
    screenshots = [{
        "filename": "https_app_example_com.png",
        "relative_path": "webdetect/screenshots/https_app_example_com.png",
    }]

    module._attach_screenshots(live, screenshots)

    assert live[0]["screenshot"] == "webdetect/screenshots/https_app_example_com.png"
    assert screenshots[0]["url"] == "https://app.example.com"


def test_webdetect_prefers_exact_hostname_over_parent_substring(tmp_path):
    module = WebdetectModule("example.com", str(tmp_path), {})
    live = [{"url": "https://example.com", "screenshot": ""}]
    screenshots = [
        {
            "filename": "https_api_example_com.png",
            "relative_path": "webdetect/screenshots/https_api_example_com.png",
        },
        {
            "filename": "https_example_com.png",
            "relative_path": "webdetect/screenshots/https_example_com.png",
        },
    ]

    module._attach_screenshots(live, screenshots)

    assert live[0]["screenshot"] == "webdetect/screenshots/https_example_com.png"


def test_webdetect_matches_hostname_with_nondefault_port(tmp_path):
    module = WebdetectModule("example.com", str(tmp_path), {})
    shot = WebdetectModule._match_screenshot(
        "https://example.com:8443",
        [
            {
                "filename": "https_example_com.png",
                "relative_path": "webdetect/screenshots/https_example_com.png",
            },
            {
                "filename": "https_example_com_8443.png",
                "relative_path": "webdetect/screenshots/https_example_com_8443.png",
            },
        ],
    )

    assert shot["relative_path"] == "webdetect/screenshots/https_example_com_8443.png"


def test_webdetect_default_host_does_not_steal_port_screenshot(tmp_path):
    shot = WebdetectModule._match_screenshot(
        "https://example.com",
        [{
            "filename": "https_example_com_8443.png",
            "relative_path": "webdetect/screenshots/https_example_com_8443.png",
        }],
    )

    assert shot is None


def test_collect_favicons_attaches_hash_fields(tmp_path, monkeypatch):
    module = WebdetectModule("example.com", str(tmp_path), {})

    favicon_bytes = b"\x00\x00\x01\x00" + b"ABCDE" * 30

    class FakeResponse:
        def __init__(self, status_code, content):
            self.status_code = status_code
            self.content = content

    def fake_http_get(url, **kwargs):
        if url.endswith("/favicon.ico"):
            return FakeResponse(200, favicon_bytes)
        return FakeResponse(404, b"")

    monkeypatch.setattr(module, "http_get", fake_http_get)

    live = [
        {"url": "https://app.example.com"},
        {"url": "https://api.example.com"},
        {"url": ""},  # ignored
    ]
    module._collect_favicons(live)

    assert "favicon_sha256" in live[0]
    assert live[0]["favicon_size"] == len(favicon_bytes)
    assert "favicon_sha256" in live[1]
    assert "favicon_sha256" not in live[2]


def test_collect_favicons_skips_non_200(tmp_path, monkeypatch):
    module = WebdetectModule("example.com", str(tmp_path), {})

    class FakeResponse:
        def __init__(self, status_code):
            self.status_code = status_code
            self.content = b""

    monkeypatch.setattr(module, "http_get", lambda *a, **kw: FakeResponse(404))

    live = [{"url": "https://nofav.example.com"}]
    module._collect_favicons(live)
    assert "favicon_sha256" not in live[0]
