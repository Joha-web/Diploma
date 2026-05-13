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
