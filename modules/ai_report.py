"""
ReconX — Module: AI-Powered Security Analysis
Provider: Ollama (local, free) — DeepSeek-R1, Qwen2.5, Llama3
Fallback:  OpenRouter / OpenAI-compatible API
"""

import json
import os
import re
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
        lang     = self._normalize_language(ai_cfg.get("language", "en"))

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

        rejection_reason = self._report_rejection_reason(analysis, lang)
        if rejection_reason:
            self.warn(f"AI analysis rejected ({rejection_reason}) — using static fallback")
            return {"analysis": "", "status": "invalid_language", "rejection_reason": rejection_reason}

        self.save_text(analysis, "ai_analysis.md")
        self.success(f"AI analysis ready ({len(analysis):,} chars)")
        return {"analysis": analysis, "model": model, "provider": provider,
                "status": "completed"}

    def summary(self) -> str:
        return "🤖 AI analysis complete" if self.results.get("analysis") else "🤖 Skipped"

    # ── Prompt builder ────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_language(lang: str | None) -> str:
        """Return a supported report language, defaulting to English."""
        value = (lang or "en").strip().lower()
        return "ru" if value == "ru" else "en"

    def _build_prompt(self, lang: str = "en") -> str:
        lang = self._normalize_language(lang)
        r      = self.all_results
        recon  = r.get("recon", {})
        web    = r.get("webdetect", {})
        ports  = r.get("portscan", {})
        tech   = r.get("techstack", {})
        fuzz   = r.get("fuzzer", {})
        cms    = r.get("cmscan", {})
        vuln   = r.get("vulnscan", {})
        cve    = r.get("cve_check", {})
        ssl    = r.get("ssl_checker", {})
        corr   = r.get("correlator", {})

        blocks: list[str] = []

        # ── Target overview
        blocks.append(f"TARGET: {self.target}")
        blocks.append(f"Subdomains: {recon.get('subdomains_total', 0)}")
        blocks.append(f"Live HTTP hosts: {len(web.get('live_urls') or recon.get('live_http', []))}")
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

        cves = cve.get("cves", [])
        if cves:
            blocks.append(f"\nCVE / EXPLOITDB CORRELATION ({len(cves)} CVEs):")
            for item in cves[:20]:
                edb = "ExploitDB match" if item.get("exploit_available") else "no ExploitDB match"
                blocks.append(
                    f"  [{item.get('severity','?')}] {item.get('cve','')} "
                    f"→ {item.get('matched_url','')} ({edb}, dry-run only)"
                )

        correlated = corr.get("findings", [])
        if correlated:
            blocks.append(f"\nCROSS-FINDING PRIORITIES ({len(correlated)}):")
            for item in correlated[:10]:
                blocks.append(
                    f"  [{item.get('severity','?')}] {item.get('title','')} "
                    f"→ {item.get('matched_url') or item.get('url','')}"
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
            return f"""You are a senior application security consultant writing a client-ready penetration testing report.

CRITICAL LANGUAGE RULES:
- Write the entire report in clear professional English only.
- Use ASCII English section titles and labels only.
- Do not use German, Russian, Kazakh, Chinese, mixed-language phrases, emojis, or malformed translated words.
- Use standard security terminology. Do not invent header names, product names, vulnerabilities, or mitigations.
- If evidence is weak or missing, say "requires manual verification" instead of presenting it as confirmed.
- Use only the scan data below. Do not add findings that are not supported by the data.
- Do not claim the project is "fully secure" or "fully safe"; security is risk-managed, not absolute.

FINDING QUALITY RULES:
- Every Critical or High finding must cite concrete evidence: IP, port, URL, technology, CVE, or exact issue from scan data.
- Missing security headers are usually Medium unless paired with a concrete exploit path.
- Open ports are not automatically vulnerabilities; explain the exposed service and why it matters.
- Do not recommend fake headers. Valid examples include Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Do not mention CSRF unless the scan data explicitly contains CSRF evidence.
- Do not mention DRDoS unless UDP amplification services or related evidence exists in the scan data.
- Do not describe missing headers as missing authentication. They are browser-side hardening controls.

SCAN DATA:
{data}

Write the report in Markdown with exactly these sections:

## Executive Summary
3-5 sentences for management. Include an A-F security grade and one sentence explaining the grade.

## Critical and High Risk Findings
Only include findings supported by concrete evidence. For each finding use:
- Evidence:
- Risk:
- Recommendation:

If there are no supported Critical/High findings, write: "No critical or high-risk findings were confirmed by the automated scan."

## Medium Risk Findings
Prioritized findings with concrete evidence and remediation.

## Low Risk / Informational Findings
Useful context such as exposed technologies, non-critical endpoints, and informational observations.

## Prioritized Remediation Plan
Numbered actions ordered by risk reduction and implementation urgency.

## Attack Surface Summary
Summarize subdomains, live hosts, open ports, high-risk ports, technologies, vulnerabilities, CVEs, endpoints, and JS secrets.

End with this sentence:
"All automated findings should be manually verified before remediation tracking or risk acceptance."
"""

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
                text = self._clean_model_output(resp.json().get("response", ""))
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
        api_key  = cfg.get("openai_api_key") or os.getenv("OPENAI_API_KEY", "")
        base_url = cfg.get("openai_base_url") or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        model    = cfg.get("model", "gpt-4o-mini")

        if not api_key:
            self.warn("OpenAI API key not set (use OPENAI_API_KEY in .env)")
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
                return self._clean_model_output(resp.json()["choices"][0]["message"]["content"])
            else:
                self.error(f"API error {resp.status_code}: {resp.text[:200]}")
                return ""
        except Exception as e:
            self.error(f"API request failed: {e}")
            return ""

    @staticmethod
    def _clean_model_output(text: str) -> str:
        """Remove reasoning blocks and normalize report output."""
        text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL | re.IGNORECASE)
        return text.strip()

    @staticmethod
    def _report_rejection_reason(text: str, lang: str) -> str:
        """Return a human-readable rejection reason, or empty string if the report is acceptable."""
        if not text or len(text.strip()) < 120:
            return "response_too_short"

        # Only apply language checks for English reports
        if lang != "en":
            return ""

        # Reject clearly non-English output (Cyrillic, CJK, German security jargon)
        non_english_patterns = [
            (r"[\u0400-\u04ff]",  "cyrillic_detected"),
            (r"[\u4e00-\u9fff]",  "cjk_detected"),
            (r"\b(Kritische|Risikogebiete|Angriff|Entdeckung|Warum|Empfehlung|Mittelrisiko)\b", "german_detected"),
            (r"\b(Niedrigen|Informations?ale|OffenePorts|fehlende|Überprüfen|Zertifikat)\b",    "german_detected"),
            (r"\b(PROtection|Overprüfung|Angriffssfläche|mutsam|sogenah)\b",                    "german_detected"),
        ]
        for pattern, reason in non_english_patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return reason

        # Reject obviously fabricated / hallucinated claims not present in real scan data.
        # NOTE: CSRF is intentionally NOT listed here — it is a valid security term that
        # LLMs legitimately mention in recommendations even when not in scan data.
        hallucination_patterns = [
            (r"\bDRDoS\b",                   "fabricated_drdos"),
            (r"\bwsgiApparentlyProtected\b",  "hallucinated_term"),
            (r"\bx-forwarded-uri\b",          "hallucinated_header"),
        ]
        for pattern, reason in hallucination_patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return reason

        return ""

    @staticmethod
    def _is_acceptable_english_report(text: str) -> bool:
        """Legacy shim kept for test compatibility."""
        return not AIReportModule._report_rejection_reason(text, "en")
