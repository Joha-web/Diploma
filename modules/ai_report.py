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

# Every finding-producing module, with a short label, so new modules are picked
# up in the prompt automatically instead of via a stale hand-kept list.
PROMPT_MODULE_LABELS = {
    "secret_scanner": "Git Secret", "fuzzer": "Fuzzer", "cors_checker": "CORS",
    "auth_probe": "Auth/Cookie", "host_header_injection": "Host Header",
    "injection_probe": "SSRF/SSTI/XXE Probe", "xss": "XSS", "sql_injection": "SQL Injection",
    "idor_probe": "IDOR/BOLA", "jwt_audit": "JWT", "prototype_pollution": "Prototype Pollution",
    "http_smuggling": "HTTP Smuggling", "oauth_probe": "OAuth", "open_redirect_probe": "Open Redirect",
    "xxe_probe": "XXE", "deserialization_probe": "Deserialization", "race_condition": "Race Condition",
    "websocket_probe": "WebSocket", "api_schema_audit": "API Schema", "js_security_audit": "JS Security",
    "ssrf_probe": "SSRF", "file_inclusion": "LFI/RFI", "command_injection": "Command Injection",
    "error_analyzer": "Server Errors", "endpoint_harvester": "Endpoint Harvest",
    "api_key_validator": "API Key Leak", "sourcemap_analyzer": "Source Map",
    "takeover_checker": "Subdomain Takeover",
}
# Evidence keys worth handing to the model, in priority order.
PROMPT_EVIDENCE_KEYS = (
    "param", "payload", "dbms", "framework", "signature", "match", "redacted",
    "location", "source_path", "marker", "wrapper", "hits", "reasons",
    "value", "status", "tool", "header",
)
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


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
        asset_risk = r.get("asset_risk", {})

        blocks: list[str] = []

        # ── Target overview
        blocks.append(f"TARGET: {self.target}")
        blocks.append(f"Subdomains: {recon.get('subdomains_total', 0)}")
        blocks.append(f"Live HTTP hosts: {len(web.get('live_urls') or recon.get('live_http', []))}")
        blocks.append(f"Unique IPs: {len(recon.get('resolved_ips', []))}")

        # ── Asset risk ranking (highest-leverage triage list for the LLM)
        ranked = asset_risk.get("ranked_assets", []) or []
        if ranked:
            tier_summary = asset_risk.get("tier_summary", {}) or {}
            blocks.append(
                f"\nTOP RISK ASSETS ({len(ranked)} ranked; "
                f"crit={tier_summary.get('critical', 0)}, high={tier_summary.get('high', 0)}):"
            )
            for a in ranked[:10]:
                s = a.get("signals", {}) or {}
                bits = [
                    f"score={a.get('score', 0)}",
                    f"tier={a.get('tier', '?')}",
                    f"ports={s.get('open_ports', 0)}",
                    f"cves={s.get('cve_hits', 0)}",
                    f"confirmed={s.get('findings_confirmed', 0)}",
                ]
                if s.get("exposed_admin"):
                    bits.append("admin_exposed")
                if s.get("takeover_candidate"):
                    bits.append("takeover")
                blocks.append(f"  [{a.get('tier', '?').upper()}] {a.get('asset', '?')} — " + ", ".join(bits))

        # ── Shodan host intelligence (passive open ports + known CVEs)
        shodan_hosts = recon.get("shodan_hosts", []) or []
        if shodan_hosts:
            total_cves = sum(len(h.get("vulns", [])) for h in shodan_hosts)
            blocks.append(f"\nSHODAN HOST INTEL ({len(shodan_hosts)} hosts, {total_cves} known CVEs):")
            for h in shodan_hosts[:10]:
                ports_str = ", ".join(str(p) for p in (h.get("ports", []) or [])[:15])
                line = f"  {h.get('ip', '?')} ({h.get('org', '')}): ports [{ports_str}]"
                if h.get("vulns"):
                    line += " | CVEs: " + ", ".join(h["vulns"][:8])
                blocks.append(line)

        # ── Open ports
        ps = ports.get("summary", {})
        if ps:
            blocks.append(f"\nOPEN PORTS ({ps.get('total_open_ports', 0)} total):")
            for hr in ps.get("high_risk", [])[:20]:
                blocks.append(f"  [HIGH RISK] {hr.get('ip', '?')}:{hr.get('port', '?')} ({hr.get('service', '?')})")

        # ── Technology stack
        ts = tech.get("technologies_summary", {})
        if ts:
            blocks.append(f"\nTECHNOLOGIES ({len(ts)}):")
            for name, cnt in list(ts.items())[:25]:
                blocks.append(f"  {name} ({cnt} hosts)")

        # ── CMS findings
        for scan in cms.get("scans", []):
            if scan.get("findings_count"):
                blocks.append(f"\nCMS {scan.get('cms', '?')} @ {scan.get('url', '?')}:")
                for f in scan.get("findings", [])[:10]:
                    blocks.append(
                        f"  [{f.get('severity','?')}] {f.get('type','')}: "
                        f"{f.get('title', f.get('detail', f.get('name','')))}")

        # ── Nuclei findings
        vf = vuln.get("findings", [])
        if vf:
            blocks.append(f"\nVULNERABILITIES ({len(vf)}):")
            for f in vf[:30]:
                blocks.append(
                    f"  [{f.get('severity', '?')}] {f.get('name', '')} → {f.get('matched_url', '')}"
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
                if cat == "js_secrets" or not items:
                    continue
                if isinstance(items, int):
                    blocks.append(f"  {cat}: {items}")
                    continue
                if not isinstance(items, list):
                    continue
                blocks.append(f"  {cat}: {len(items)}")
                for url in items[:5]:
                    blocks.append(f"    {url}")

        # ── JS Secrets
        secrets = fc.get("js_secrets", []) if fc else []
        if not isinstance(secrets, list):
            secrets = []
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

        # ── All security findings WITH evidence, grouped so the model can write
        # a detailed per-finding analysis (confirmed first, candidates separate).
        confirmed, candidates, mediums = self._collect_findings_for_prompt(r)
        if confirmed:
            blocks.append(f"\nCONFIRMED FINDINGS ({len(confirmed)}) — proven/exploited; analyse each in full detail:")
            blocks.extend(f"  {line}" for line in confirmed[:45])
        if mediums:
            blocks.append(f"\nMEDIUM-RISK FINDINGS ({len(mediums)}):")
            blocks.extend(f"  {line}" for line in mediums[:25])
        if candidates:
            blocks.append(f"\nUNCONFIRMED HIGH/CRITICAL CANDIDATES ({len(candidates)}) — require manual verification:")
            blocks.extend(f"  {line}" for line in candidates[:30])

        data = "\n".join(blocks)

        if lang == "ru":
            return f"""Ты — опытный пентестер. Напиши ПОДРОБНЫЙ технический отчёт по результатам сканирования. Анализируй каждую находку детально по её evidence, а не общим описанием.

ПРАВИЛА:
- Используй ТОЛЬКО данные ниже. Не выдумывай находок, параметров, payload-ов, заголовков, CVE.
- CONFIRMED-находки подтверждены инструментом — разбери каждую подробно (параметр, payload, сигнатура, CWE).
- CANDIDATE-находки не подтверждены — вынеси отдельно как "требует ручной проверки".
- Не утверждай, что система «полностью безопасна». Открытые порты и отсутствующие заголовки — не всегда уязвимость, объясняй контекст.

ДАННЫЕ СКАНИРОВАНИЯ (строка находки: [SEVERITY] Модуль: заголовок @ url (CWE, confidence, verdict) | evidence):
{data}

Формат отчёта (Markdown):

## Executive Summary
3-5 предложений для руководства и оценка A-F с обоснованием.

## Подтверждённые находки (детально)
Для КАЖДОЙ confirmed-находки подраздел "### [SEVERITY] <название>":
- Локация: точный URL и параметр.
- Доказательство / PoC: точный payload, сигнатура или значение из данных.
- Эксплуатация и влияние: как атакующий использует и реальный бизнес-риск.
- Рекомендация: конкретное исправление.

## Цепочки атак
Свяжи связанные находки в 1-3 сквозных сценария атаки, называя конкретные находки.

## Кандидаты для ручной проверки
Неподтверждённые high/critical: причина флага и точная ручная проверка.

## Средний риск

## Низкий риск / Информационные находки

## План устранения по приоритету
Нумерованный список по снижению риска.

## Attack Surface Summary
Числа: субдомены, хосты, порты, технологии, уязвимости, CVE, endpoint'ы, секреты.

В конце добавь: "All automated findings should be manually verified before remediation tracking or risk acceptance."
"""
        else:
            return f"""You are a senior penetration tester writing the DETAILED technical findings section of a client engagement report. Go deep — analyse each finding specifically using its evidence. Do NOT write a short generic overview.

CRITICAL LANGUAGE RULES:
- Write the entire report in clear professional English only.
- Use ASCII English section titles and labels only.
- Do not use German, Russian, Kazakh, Chinese, mixed-language phrases, emojis, or malformed translated words.

EVIDENCE & ACCURACY RULES:
- Use ONLY the scan data below. Never invent findings, parameters, payloads, headers, products, CVEs, or mitigations.
- CONFIRMED findings were proven by the tooling — analyse each one in depth using its exact evidence (parameter, payload, signature, CWE).
- CANDIDATE findings are unconfirmed — present them separately as "requires manual verification"; never describe them as confirmed.
- If evidence is weak, say so. Do not claim the system is "fully secure"; security is risk-managed, not absolute.
- Open ports and missing security headers are not automatically vulnerabilities — explain the exposed service/control and why it matters.

SCAN DATA (each finding line is: [SEVERITY] Module: title @ url (CWE, confidence, verdict) | evidence):
{data}

Write the report in Markdown with these sections:

## Executive Summary
3-5 sentences for management, plus an A-F security grade and one sentence justifying it.

## Confirmed Findings (Detailed)
For EVERY confirmed finding, write a subsection titled "### [SEVERITY] <short title>" containing:
- Location: the exact URL and parameter.
- Evidence / Proof of Concept: quote the exact payload, signature, or value from the scan data.
- Exploitation and Impact: how an attacker leverages it and the realistic business impact.
- Remediation: a specific, actionable fix.
If there are no confirmed findings, write: "No findings were confirmed by the automated scan."

## Attack Chains
Combine related findings (e.g. exposed admin panel + leaked API key + weak auth) into 1-3 concrete end-to-end attack scenarios, naming the specific findings used in each chain.

## Candidate Findings Requiring Manual Verification
List the unconfirmed high/critical candidates. For each, give the reason it was flagged and the exact manual check to confirm or dismiss it.

## Medium Risk Findings
Each with concrete evidence and remediation.

## Low Risk / Informational Observations
Exposed technologies, non-critical endpoints, and other useful context.

## Prioritized Remediation Plan
A numbered list ordered by risk reduction; each item names the finding(s) it resolves.

## Attack Surface Summary
Numbers for subdomains, live hosts, open ports, high-risk ports, technologies, vulnerabilities, CVEs, endpoints, and secrets.

End with exactly:
"All automated findings should be manually verified before remediation tracking or risk acceptance."
"""

    # ── Finding collection for the prompt ─────────────────────────────────────
    def _collect_findings_for_prompt(self, r: dict) -> tuple[list[str], list[str], list[str]]:
        """Gather findings from every module, grouped: confirmed, unconfirmed
        high/critical candidates, and mediums — each line carries evidence."""
        confirmed: list[tuple[int, str]] = []
        candidates: list[tuple[int, str]] = []
        mediums: list[tuple[int, str]] = []

        for module, label in PROMPT_MODULE_LABELS.items():
            data = r.get(module, {})
            if not isinstance(data, dict):
                continue
            for f in data.get("findings", []) or []:
                if not isinstance(f, dict):
                    continue
                sev = str(f.get("severity", "INFO")).upper()
                rank = SEV_RANK.get(sev, 0)
                verdict = str(f.get("verdict") or "").lower()
                exploit = str(f.get("exploitability") or "").lower()
                line = self._finding_line(label, f)
                if verdict == "confirmed" or exploit == "confirmed":
                    confirmed.append((rank, line))
                elif sev == "MEDIUM":
                    mediums.append((rank, line))
                elif rank >= 3:  # unconfirmed CRITICAL/HIGH
                    candidates.append((rank, line))
                # LOW/INFO candidates are intentionally dropped to keep the prompt focused

        srt = lambda items: [line for _, line in sorted(items, key=lambda x: x[0], reverse=True)]
        return srt(confirmed), srt(candidates), srt(mediums)

    def _finding_line(self, label: str, f: dict) -> str:
        sev = str(f.get("severity", "INFO")).upper()
        title = f.get("title") or f.get("name") or f.get("type", "finding")
        url = f.get("url") or f.get("matched_url", "")
        meta = []
        if f.get("cwe"):
            meta.append(str(f["cwe"]))
        if f.get("confidence") is not None:
            meta.append(f"conf={f['confidence']}")
        if f.get("verdict"):
            meta.append(str(f["verdict"]))
        line = f"[{sev}] {label}: {title}"
        if url:
            line += f" @ {url}"
        if meta:
            line += " (" + ", ".join(meta) + ")"
        evidence = self._evidence_brief(f.get("evidence", {}))
        if evidence:
            line += f" | {evidence}"
        return line[:480]

    @staticmethod
    def _evidence_brief(evidence) -> str:
        if not isinstance(evidence, dict):
            return ""
        bits: list[str] = []
        for key in PROMPT_EVIDENCE_KEYS:
            value = evidence.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value[:3])
            elif isinstance(value, dict):
                value = ", ".join(f"{k}={v}" for k, v in list(value.items())[:3])
            bits.append(f"{key}={str(value)[:70]}")
            if len(bits) >= 5:
                break
        return "; ".join(bits)

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
                        # num_ctx must be large enough to hold the (now richer)
                        # prompt — Ollama silently truncates anything beyond it,
                        # which is what made earlier reports thin.
                        "num_ctx":       cfg.get("num_ctx", 8192),
                        "num_predict":   cfg.get("max_tokens", 4096),
                        "top_p":         0.9,
                    },
                },
                # A detailed report from a local 7B model is slow — give it room.
                timeout=int(cfg.get("timeout", 900)),
            )
            if resp.status_code == 200:
                text = self._clean_model_output(resp.json().get("response", ""))
                return text
            else:
                self.error(f"Ollama error {resp.status_code}: {resp.text[:200]}")
                return ""
        except requests.exceptions.Timeout:
            self.error(f"Ollama request timed out ({int(cfg.get('timeout', 900))}s) — "
                       "lower ai.max_tokens or raise ai.timeout for very large scans")
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
                timeout=int(cfg.get("timeout", 900)),
            )
            if resp.status_code == 200:
                data = resp.json()
                return self._clean_model_output(data["choices"][0]["message"]["content"])
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
            # NB: must not collide with normal English (e.g. "protection") — only
            # match genuinely malformed/German tokens.
            (r"\b(Overprüfung|Angriffssfläche|mutsam|sogenah)\b",                                "german_detected"),
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
