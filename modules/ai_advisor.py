"""
ReconX - Realtime AI advice helper.

This is intentionally lightweight and optional. It is triggered by main.py in a
background thread after configured modules complete.
"""

import json
import os
import re

import requests

# Models that emit a <think>...</think> reasoning block before the answer. They
# need a larger token budget (the reasoning eats it first) and their reasoning
# must be stripped from the returned text.
_REASONING_HINTS = ("r1", "qwq", "deepseek-r1", "thinking", "reasoner")


class AIAdvisor:
    def __init__(self, config: dict):
        self.config = config
        self.ai_cfg = config.get("ai", {})
        self.enabled = bool(self.ai_cfg.get("enabled", True) and self.ai_cfg.get("realtime_advice", False))
        self.advise_on = set(self.ai_cfg.get("advise_on", [
            "recon", "portscan", "techstack", "fuzzer", "vulnscan", "cve_check",
        ]))

    def should_advise(self, module_name: str, result: dict) -> bool:
        if not self.enabled or module_name not in self.advise_on:
            return False
        return isinstance(result, dict) and result.get("status") == "completed"

    def analyse(self, module_name: str, result: dict, target: str) -> str:
        prompt = self._prompt(module_name, result, target)
        return self.complete(prompt)

    def complete(self, prompt: str, system: str | None = None,
                 max_tokens: int | None = None) -> str:
        """Provider-agnostic single-shot completion.

        Centralised so other components (e.g. the false-positive triage pass)
        can reuse the configured LLM without duplicating provider plumbing.
        Returns "" on any failure so callers can fall back gracefully.
        """
        provider = str(self.ai_cfg.get("provider", "ollama")).lower()
        if provider in ("anthropic", "claude"):
            return self._anthropic(prompt, system=system, max_tokens=max_tokens)
        if provider == "ollama":
            return self._ollama(prompt, max_tokens=max_tokens)
        return self._openai(prompt, max_tokens=max_tokens)

    @staticmethod
    def _is_reasoning_model(model: str) -> bool:
        name = (model or "").lower()
        return any(hint in name for hint in _REASONING_HINTS)

    @staticmethod
    def _strip_reasoning(text: str) -> str:
        """Drop <think>...</think> blocks (and an unterminated trailing one) so
        a reasoning model's chain-of-thought never leaks into the advice."""
        text = text or ""
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
        m = re.search(r"<think>", text, flags=re.IGNORECASE)
        if m:
            text = text[:m.start()]
        return text.strip()

    def _prompt(self, module_name: str, result: dict, target: str) -> str:
        compact_result = self._compact_result(module_name, result)
        compact = json.dumps(compact_result, ensure_ascii=False, default=str)[:3000]
        return (
            "You are a security testing assistant. Give concise, evidence-based next steps. "
            "Do not invent findings. Mention manual verification when needed.\n\n"
            f"Target: {target}\nModule: {module_name}\nResult JSON:\n{compact}\n\n"
            "Return 3-6 bullets only."
        )

    def _compact_result(self, module_name: str, result: dict) -> dict:
        if module_name == "vulnscan":
            findings = sorted(
                result.get("findings", []) or [],
                key=lambda f: self._severity_rank(str(f.get("severity", "INFO"))),
            )[:10]
            return {
                "status": result.get("status"),
                "total": result.get("total", len(result.get("findings", []) or [])),
                "by_severity": result.get("by_severity", {}),
                "runtime": result.get("runtime", {}),
                "top_findings": [
                    {
                        "severity": f.get("severity"),
                        "name": f.get("name"),
                        "template_id": f.get("template_id"),
                        "matched_url": f.get("matched_url"),
                        "cves": f.get("cves", []),
                    }
                    for f in findings
                ],
            }
        if module_name == "fuzzer":
            classified = result.get("classified", {}) or {}
            return {
                "status": result.get("status"),
                "total_endpoints": result.get("total_endpoints"),
                "js_secrets_count": result.get("js_secrets_count"),
                "graphql_details": result.get("graphql_details", [])[:5],
                "cloud_assets": result.get("cloud_assets", [])[:10],
                "classified_counts": {
                    k: len(v) for k, v in classified.items() if isinstance(v, list)
                },
            }
        return result

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            severity.upper(), 5
        )

    def _ollama(self, prompt: str, max_tokens: int | None = None) -> str:
        url = self.ai_cfg.get("ollama_url", "http://localhost:11434")
        model = self.ai_cfg.get("model", "deepseek-r1:7b")
        # Honour the caller's budget (fp_triage asks for more than advice does).
        num_predict = int(max_tokens or self.ai_cfg.get("advisor_max_tokens", 512))
        # A reasoning model burns its budget on <think> before answering, so 512
        # tokens yields an empty response. Give it room for reasoning + answer.
        if self._is_reasoning_model(model):
            num_predict = max(num_predict, 2048)
        timeout = int(self.ai_cfg.get("advisor_timeout", 90))
        try:
            resp = requests.post(
                f"{url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": num_predict},
                },
                timeout=timeout,
            )
            if resp.status_code == 200:
                return self._strip_reasoning(resp.json().get("response", "") or "")
        except Exception:
            return ""
        return ""

    def _openai(self, prompt: str, max_tokens: int | None = None) -> str:
        key = self.ai_cfg.get("openai_api_key") or os.getenv("OPENAI_API_KEY", "")
        if not key:
            return ""
        base_url = self.ai_cfg.get("openai_base_url", "https://api.openai.com/v1")
        try:
            resp = requests.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": self.ai_cfg.get("model", "gpt-4o-mini"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens": int(max_tokens or self.ai_cfg.get("advisor_max_tokens", 512)),
                },
                timeout=int(self.ai_cfg.get("advisor_timeout", 90)),
            )
            if resp.status_code == 200:
                return self._strip_reasoning(resp.json()["choices"][0]["message"]["content"])
        except Exception:
            return ""
        return ""

    def _anthropic(self, prompt: str, system: str | None = None,
                   max_tokens: int | None = None) -> str:
        key = (
            self.ai_cfg.get("anthropic_api_key")
            or os.getenv("ANTHROPIC_API_KEY", "")
        )
        if not key:
            return ""
        base_url = self.ai_cfg.get("anthropic_base_url", "https://api.anthropic.com")
        model = self.ai_cfg.get("anthropic_model") or self.ai_cfg.get(
            "model", "claude-sonnet-4-6"
        )
        body = {
            "model": model,
            "max_tokens": int(max_tokens or self.ai_cfg.get("max_tokens", 1024)),
            "temperature": float(self.ai_cfg.get("temperature", 0.2)),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        try:
            resp = requests.post(
                f"{base_url}/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=body,
                timeout=90,
            )
            if resp.status_code == 200:
                blocks = resp.json().get("content", []) or []
                text = "".join(
                    b.get("text", "") for b in blocks if b.get("type") == "text"
                )
                return text.strip()
        except Exception:
            return ""
        return ""
