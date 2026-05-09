"""
ReconX — Module: AI-Powered Security Analysis
Provider: Ollama (local, free) — DeepSeek-R1, Qwen2.5, Llama3
Fallback:  OpenRouter / OpenAI-compatible API
"""

import json
import requests
from modules.base import BaseModule


class AIReportModule(BaseModule):
    name = "ai_report"
    description = "AI-Powered Security Analysis"
    required_tools = []   # uses HTTP API, no CLI tools needed

    def __init__(self, target: str, output_dir: str, config: dict,
                 all_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.all_results = all_results or {}

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        ai_cfg = self.config.get("ai", {})

        if not ai_cfg.get("enabled", True):
            self.info("AI analysis disabled in config")
            return {"analysis": "", "status": "disabled"}

        provider = ai_cfg.get("provider", "ollama")
        model    = ai_cfg.get("model", "deepseek-r1:7b")
        lang     = ai_cfg.get("language", "ru")

        # Build structured prompt from scan results
        prompt = self._build_prompt(lang)
        self.save_text(prompt, "ai_prompt.txt")

        self.info(f"Provider: {provider}  Model: {model}")

        if provider == "ollama":
            ollama_url = ai_cfg.get("ollama_url", "http://localhost:11434")
            if not self._ollama_alive(ollama_url):
                self.warn("Ollama not running — skipping AI analysis")
                self.warn(f"Start it with:  ollama serve && ollama pull {model}")
                return {"analysis": "", "status": "ollama_unavailable"}
            analysis = self._ollama_generate(ollama_url, model, prompt, ai_cfg)
        else:
            analysis = self._openai_compatible_generate(ai_cfg, prompt)

        if not analysis:
            self.warn("AI returned empty response")
            return {"analysis": "", "status": "empty"}

        self.save_text(analysis, "ai_analysis.md")
        self.success(f"AI analysis ready ({len(analysis):,} chars)")
        return {"analysis": analysis, "model": model, "provider": provider,
                "status": "completed"}

    def summary(self) -> str:
        return "🤖 AI analysis complete" if self.results.get("analysis") else "🤖 Skipped"

    # ── Prompt builder ────────────────────────────────────────────────────────

    def _build_prompt(self, lang: str = "ru") -> str:
        r      = self.all_results
        recon  = r.get("recon", {})
        ports  = r.get("portscan", {})
        tech   = r.get("techstack", {})
        fuzz   = r.get("fuzzer", {})
        cms    = r.get("cmscan", {})
        vuln   = r.get("vulnscan", {})
        ssl    = r.get("ssl_checker", {})

        blocks: list[str] = []

        # ── Target overview
        blocks.append(f"TARGET: {self.target}")
        blocks.append(f"Subdomains: {recon.get('subdomains_total', 0)}")
        blocks.append(f"Live HTTP hosts: {len(recon.get('live_http', []))}")
        blocks.append(f"Unique IPs: {len(recon.get('resolved_ips', []))}")

        # ── Open ports
        ps = ports.get("summary", {})
        if ps:
            blocks.append(f"\nOPEN PORTS ({ps.get('total_open_ports', 0)} total):")
            for hr in ps.get("high_risk", [])[:20]:
                blocks.append(f"  [HIGH RISK] {hr['ip']}:{hr['port']} ({hr['service']})")

        # ── Technology stack
        ts = tech.get("technologies_summary", {})
        if ts:
            blocks.append(f"\nTECHNOLOGIES ({len(ts)}):")
            for name, cnt in list(ts.items())[:25]:
                blocks.append(f"  {name} ({cnt} hosts)")

        # ── CMS findings
        for scan in cms.get("scans", []):
            if scan["findings_count"]:
                blocks.append(f"\nCMS {scan['cms']} @ {scan['url']}:")
                for f in scan.get("findings", [])[:10]:
                    blocks.append(
                        f"  [{f.get('severity','?')}] {f.get('type','')}: "
                        f"{f.get('title', f.get('detail', f.get('name','')))}"
                    )

        # ── Nuclei findings
        vf = vuln.get("findings", [])
        if vf:
            blocks.append(f"\nVULNERABILITIES ({len(vf)}):")
            for f in vf[:30]:
                blocks.append(
                    f"  [{f['severity']}] {f['name']} → {f['matched_url']}"
                )

        # ── Fuzzing
        fc = fuzz.get("classified", {})
        if fc:
            blocks.append(f"\nFUZZING (total endpoints: {fuzz.get('total_endpoints', 0)}):")
            for cat, items in fc.items():
                if cat != "js_secrets" and items:
                    blocks.append(f"  {cat}: {len(items)}")
                    for url in items[:5]:
                        blocks.append(f"    {url}")

        # ── JS Secrets
        secrets = fc.get("js_secrets", []) if fc else []
        if secrets:
            blocks.append(f"\nJS SECRETS ({len(secrets)}):")
            for s in secrets[:10]:
                blocks.append(f"  {s.get('file','')}: {s.get('match','')[:80]}")

        # ── SSL / Headers
        ssl_issues = ssl.get("ssl_issues", [])
        if ssl_issues:
            blocks.append(f"\nSSL/TLS ISSUES:")
            for si in ssl_issues[:10]:
                blocks.append(f"  {si.get('host','')}: {', '.join(si.get('issues', []))}")

        missing_headers = ssl.get("total_missing_headers", 0)
        if missing_headers:
            blocks.append(f"\nMISSING SECURITY HEADERS: {missing_headers} total")

        data = "\n".join(blocks)

        if lang == "ru":
            return f"""Ты — опытный пентестер с 15 годами в AppSec и Red Team. \
Проанализируй результаты автоматизированной разведки и дай профессиональный отчёт.

ДАННЫЕ СКАНИРОВАНИЯ:
{data}

Напиши отчёт на русском языке в следующем формате (строго):

## 🎯 Executive Summary
Краткое резюме (3-4 предложения) для руководства. Укажи общую оценку безопасности: A (отлично) / B / C / D / F (критически опасно).

## 🔴 Критические зоны атаки
Конкретные находки с наибольшим риском. Для каждой:
- Что найдено (IP, порт, URL)
- Почему опасно (вектор атаки)
- Рекомендация

## 🟡 Средний риск
Находки среднего приоритета.

## 🟢 Низкий риск / Информационные находки

## 🛡️ Рекомендации
Конкретные действия, отсортированные по приоритету.

## 📊 Attack Surface Summary
Размер поверхности атаки: кол-во субдоменов, открытых портов, технологий, критичных endpoint'ов.

Используй только реальные данные из сканирования. Не выдумывай уязвимостей."""
        else:
            return f"""You are an expert penetration tester with 15 years in AppSec and Red Team. \
Analyze the automated reconnaissance results and produce a professional security report.

SCAN DATA:
{data}

Write the report with these sections:
## Executive Summary (with A-F security grade)
## Critical Attack Zones (specific IPs, URLs, attack vectors)
## Medium Risk Findings
## Low Risk / Informational
## Recommendations (prioritized)
## Attack Surface Summary

Use only data provided. Do not invent vulnerabilities."""

    # ── Ollama ────────────────────────────────────────────────────────────────

    def _ollama_alive(self, url: str) -> bool:
        try:
            r = requests.get(f"{url}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def _ollama_generate(self, url: str, model: str, prompt: str, cfg: dict) -> str:
        """Call Ollama API with streaming disabled for simplicity."""
        try:
            resp = requests.post(
                f"{url}/api/generate",
                json={
                    "model":  model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature":   cfg.get("temperature", 0.3),
                        "num_predict":   cfg.get("max_tokens", 4096),
                        "top_p":         0.9,
                    },
                },
                timeout=600,
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "")
                # Strip <think>...</think> blocks that DeepSeek-R1 may include
                import re
                text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
                return text
            else:
                self.error(f"Ollama error {resp.status_code}: {resp.text[:200]}")
                return ""
        except requests.exceptions.Timeout:
            self.error("Ollama request timed out (600s)")
            return ""
        except Exception as e:
            self.error(f"Ollama request failed: {e}")
            return ""

    # ── OpenAI-compatible fallback ────────────────────────────────────────────

    def _openai_compatible_generate(self, cfg: dict, prompt: str) -> str:
        api_key  = cfg.get("openai_api_key", "")
        base_url = cfg.get("openai_base_url", "https://api.openai.com/v1")
        model    = cfg.get("model", "gpt-4o-mini")

        if not api_key:
            self.warn("OpenAI API key not set in config.yaml")
            return ""

        try:
            resp = requests.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}",
                         "Content-Type": "application/json"},
                json={
                    "model":       model,
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": cfg.get("temperature", 0.3),
                    "max_tokens":  cfg.get("max_tokens", 4096),
                },
                timeout=120,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            else:
                self.error(f"API error {resp.status_code}: {resp.text[:200]}")
                return ""
        except Exception as e:
            self.error(f"API request failed: {e}")
            return ""
