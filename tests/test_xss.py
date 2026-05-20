import subprocess
from urllib.parse import parse_qs, urlparse

from modules.xss import XSSModule


class Response:
    def __init__(self, text: str, status_code: int = 200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


def test_xss_collects_parameterized_targets(tmp_path):
    module = XSSModule(
        "example.com",
        str(tmp_path),
        {},
        parameter_results={
            "parameters": [
                {"url": "https://example.com/search", "param": "q"},
                {"url": "https://example.com/list?page=1", "param": "sort"},
            ],
            "parameterized_targets": ["https://example.com/filter?tag=a"],
        },
        fuzzer_results={
            "classified": {"with_params": ["https://api.example.com/items?id=1"]},
            "all_endpoints": ["https://example.com/plain", "https://example.com/view?name=bob"],
        },
    )

    targets = module._collect_targets()

    assert {"url": "https://example.com/search?q=reconx", "params": ["q"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://example.com/list?page=1&sort=reconx", "params": ["sort"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://example.com/filter?tag=a", "params": ["tag"], "sources": ["parameter_discovery"]} in targets
    assert {"url": "https://api.example.com/items?id=1", "params": ["id"], "sources": ["fuzzer"]} in targets
    assert {"url": "https://example.com/view?name=bob", "params": ["name"], "sources": ["fuzzer"]} in targets


def test_xss_reflection_probe_detects_unescaped_payload(tmp_path, monkeypatch):
    module = XSSModule(
        "example.com",
        str(tmp_path),
        {"scan": {"xss": {"use_dalfox": False, "fallback_reflection": True, "request_timeout": 7}}},
        parameter_results={"parameterized_targets": ["https://example.com/search?q=test"]},
    )
    requested = []
    timeouts = []

    def fake_http_get(url, **kwargs):
        requested.append(url)
        timeouts.append(kwargs.get("timeout"))
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        return Response(f"<html>{value}</html>")

    monkeypatch.setattr(module, "http_get", fake_http_get)

    result = module.run()

    assert requested
    assert set(timeouts) == {7}
    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "xss_html_injection_candidate"
    assert finding["type"] == "xss"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"]["param"] == "q"
    assert finding["evidence"]["context"] == "html_tag"
    assert "reconx-xss" in finding["evidence"]["payload"]


def test_xss_reflection_probe_marks_escaped_payload_low_confidence(tmp_path, monkeypatch):
    module = XSSModule(
        "example.com",
        str(tmp_path),
        {"scan": {"xss": {"use_dalfox": False, "fallback_reflection": True, "max_payloads": 2}}},
        parameter_results={"parameterized_targets": ["https://example.com/search?q=test"]},
    )

    def fake_http_get(url, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        return Response(f"<html>{value.replace('<', '&lt;').replace('>', '&gt;')}</html>")

    monkeypatch.setattr(module, "http_get", fake_http_get)

    result = module.run()

    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "xss_reflected_input"
    assert finding["severity"] == "LOW"
    assert finding["evidence"]["escaped"] is True


def test_xss_dalfox_mode_runs_and_parses_findings(tmp_path, monkeypatch):
    module = XSSModule(
        "example.com",
        str(tmp_path),
        {"scan": {"xss": {"use_dalfox": True, "fallback_reflection": False}}},
        parameter_results={"parameterized_targets": ["https://example.com/search?q=test"]},
    )
    dalfox_output = "[V] XSS Found\n[POC][GET] https://example.com/search?q=%3Csvg%3E\n"
    executed = {}

    monkeypatch.setattr(module, "has_tool", lambda tool: tool == "dalfox")

    def fake_exec(cmd, timeout=300, capture=True, shell=False, label=None):
        executed["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=dalfox_output, stderr="")

    monkeypatch.setattr(module, "exec", fake_exec)

    result = module.run()

    assert executed["cmd"][:3] == ["dalfox", "url", "https://example.com/search?q=test"]
    assert "--skip-discovery" in executed["cmd"]
    assert executed["cmd"][-2:] == ["-p", "q"]
    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "xss_dalfox_confirmed"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"]["tool"] == "dalfox"
    assert finding["evidence"]["param"] == "q"
    assert (tmp_path / "xss" / "dalfox_run_001.txt").exists()
