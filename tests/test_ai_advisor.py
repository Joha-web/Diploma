"""Tests for the shared LLM completion path used by realtime advice and the
false-positive triage pass. Focus: the reasoning-model handling that previously
made advice always-empty on the default deepseek-r1 model, and that the caller's
max_tokens budget is actually honoured per provider."""

import json

from modules.ai_advisor import AIAdvisor


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_is_reasoning_model_detection():
    assert AIAdvisor._is_reasoning_model("deepseek-r1:7b")
    assert AIAdvisor._is_reasoning_model("qwq:32b")
    assert not AIAdvisor._is_reasoning_model("qwen2.5:7b-instruct")
    assert not AIAdvisor._is_reasoning_model("gpt-4o-mini")


def test_strip_reasoning_removes_complete_and_unterminated_blocks():
    assert AIAdvisor._strip_reasoning(
        "<think>deciding</think>\n- bullet one") == "- bullet one"
    # cut off mid-think: no chain-of-thought leaks into advice
    assert AIAdvisor._strip_reasoning("- intro\n<think>still going") == "- intro"
    assert AIAdvisor._strip_reasoning("<think>only reasoning") == ""


def test_ollama_raises_token_budget_for_reasoning_model(monkeypatch):
    advisor = AIAdvisor({"ai": {"provider": "ollama", "model": "deepseek-r1:7b"}})
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["num_predict"] = json["options"]["num_predict"]
        return _Resp({"response": "<think>reasoning</think>\n- do X"})

    monkeypatch.setattr("modules.ai_advisor.requests.post", fake_post)
    out = advisor.complete("prompt")
    # reasoning model gets headroom (not the 512 that yields empty output)
    assert captured["num_predict"] >= 2048
    assert out == "- do X"


def test_ollama_honours_caller_max_tokens(monkeypatch):
    advisor = AIAdvisor({"ai": {"provider": "ollama", "model": "qwen2.5:7b"}})
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["num_predict"] = json["options"]["num_predict"]
        return _Resp({"response": "ok"})

    monkeypatch.setattr("modules.ai_advisor.requests.post", fake_post)
    advisor.complete("prompt", max_tokens=3000)  # e.g. fp_triage asks for more
    assert captured["num_predict"] == 3000


def test_ollama_returns_empty_on_error_without_raising(monkeypatch):
    advisor = AIAdvisor({"ai": {"provider": "ollama", "model": "qwen2.5:7b"}})

    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr("modules.ai_advisor.requests.post", boom)
    assert advisor.complete("prompt") == ""
