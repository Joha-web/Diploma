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
