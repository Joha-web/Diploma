"""
telegram.py — Telegram Bot Notification Module
Sends scan status updates, module progress, and final report to a Telegram chat.
Includes retry logic with exponential backoff.
"""
import time
import logging
import os
import requests
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("reconx.telegram")


class TelegramNotifier:
    """Telegram notification service with retry and rich formatting."""

    # Status emoji mapping
    STATUS_EMOJI = {
        "completed": "✅",
        "error":     "❌",
        "crashed":   "💥",
        "skipped":   "⏭️",
    }

    MODULE_EMOJI = {
        "recon":       "🌐",
        "portscan":    "🔌",
        "webdetect":   "🖥️",
        "techstack":   "🧰",
        "fuzzer":      "🔎",
        "ssl_checker": "🔒",
        "cmscan":      "🔧",
        "vulnscan":    "🚨",
        "ai_report":   "🤖",
    }

    def __init__(self, config: dict):
        tg = config.get("telegram", {})
        self.enabled = tg.get("enabled", False)
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", tg.get("bot_token", ""))
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", tg.get("chat_id", ""))
        self.notify_on = tg.get("notify_on", ["complete"])
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.max_retries = 3
        self.retry_delay = 1.0  # seconds, doubles each retry

    def is_ready(self) -> bool:
        return bool(self.enabled) and bool(self.bot_token) and bool(self.chat_id)

    # ── Core send methods with retry ─────────────────────────────────────────

    def send_message(self, text: str, parse_mode: str | None = "Markdown") -> bool:
        """Send a text message with retry logic and exponential backoff."""
        if not self.is_ready():
            return False

        delay = self.retry_delay
        for attempt in range(1, self.max_retries + 1):
            try:
                payload = {
                    "chat_id": self.chat_id,
                    "text": text[:4096],
                    "disable_web_page_preview": True,
                }
                if parse_mode:
                    payload["parse_mode"] = parse_mode
                r = requests.post(
                    f"{self.api_url}/sendMessage",
                    json=payload,
                    timeout=15,
                )
                if r.status_code == 200:
                    return True
                elif r.status_code == 400 and parse_mode:
                    logger.warning("Telegram parse failed, retrying as plain text")
                    return self.send_message(text, parse_mode=None)
                elif r.status_code == 429:
                    # Rate limited — respect retry_after
                    retry_after = r.json().get("parameters", {}).get("retry_after", delay)
                    logger.warning(f"Telegram rate limited, waiting {retry_after}s")
                    time.sleep(retry_after)
                else:
                    logger.warning(
                        f"Telegram send failed (attempt {attempt}/{self.max_retries}): "
                        f"HTTP {r.status_code} — {r.text[:200]}"
                    )
            except requests.exceptions.Timeout:
                logger.warning(f"Telegram timeout (attempt {attempt}/{self.max_retries})")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Telegram connection error (attempt {attempt}/{self.max_retries})")
            except Exception as e:
                logger.error(f"Telegram unexpected error: {e}")
                return False

            if attempt < self.max_retries:
                time.sleep(delay)
                delay *= 2  # exponential backoff

        logger.error(f"Telegram: all {self.max_retries} attempts failed")
        return False

    def send_document(self, filepath: str, caption: str = "") -> bool:
        """Send a file document with retry logic."""
        if not self.is_ready():
            return False

        delay = self.retry_delay
        for attempt in range(1, self.max_retries + 1):
            try:
                with open(filepath, "rb") as f:
                    r = requests.post(
                        f"{self.api_url}/sendDocument",
                        data={
                            "chat_id": self.chat_id,
                            "caption": caption[:1024],
                            "parse_mode": "Markdown",
                        },
                        files={"document": f},
                        timeout=60,
                    )
                if r.status_code == 200:
                    return True
                logger.warning(
                    f"Telegram document send failed (attempt {attempt}): "
                    f"HTTP {r.status_code}"
                )
            except Exception as e:
                logger.warning(f"Telegram document error (attempt {attempt}): {e}")

            if attempt < self.max_retries:
                time.sleep(delay)
                delay *= 2

        return False

    # ── Notification methods ─────────────────────────────────────────────────

    def notify_start(self, target: str, modules: list[str] | None = None):
        """Notify when a scan begins."""
        if "start" not in self.notify_on:
            return
        mod_list = ", ".join(modules) if modules else "all"
        self.send_message(
            f"🔍 *ReconX — Сканирование запущено*\n\n"
            f"🎯 Цель: `{target}`\n"
            f"📦 Модули: {mod_list}\n"
            f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def notify_module_complete(self, module_name: str, status: str,
                                elapsed: float = 0, details: str = ""):
        """Notify when a module finishes."""
        if "module_complete" not in self.notify_on:
            return

        emoji = self.MODULE_EMOJI.get(module_name, "📋")
        status_icon = self.STATUS_EMOJI.get(status, "❓")

        msg = (
            f"{status_icon} *{module_name.upper()}* — {status}\n"
            f"{emoji} Время: {elapsed:.1f}s"
        )
        if details:
            msg += f"\n📊 {details}"

        self.send_message(msg)

    def notify_finding(self, finding: str):
        """Notify about a critical finding."""
        if "critical_finding" not in self.notify_on:
            return
        self.send_message(f"🚨 *Критическая находка!*\n\n{finding}")

    def notify_critical_vulns(self, findings: list[dict]):
        """Notify about critical/high vulnerability findings from nuclei."""
        if "critical_finding" not in self.notify_on:
            return
        if not findings:
            return

        critical = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if not critical:
            return

        lines = [f"🚨 *ReconX — Критические уязвимости ({len(critical)})*\n"]
        for f in critical[:10]:  # cap at 10 to avoid message overflow
            sev = f.get("severity", "?")
            icon = "🔴" if sev == "CRITICAL" else "🟠"
            lines.append(
                f"{icon} `{sev}` — {f.get('name', '?')}\n"
                f"   ↳ `{f.get('matched_url', '?')}`"
            )

        if len(critical) > 10:
            lines.append(f"\n_...и ещё {len(critical) - 10} находок_")

        self.send_message("\n".join(lines))

    def notify_error(self, module_name: str, error: str):
        """Notify about a module error/crash."""
        if "module_complete" not in self.notify_on:
            return
        emoji = self.MODULE_EMOJI.get(module_name, "📋")
        self.send_message(
            f"💥 *Ошибка в модуле {module_name.upper()}*\n\n"
            f"{emoji} ```\n{error[:500]}\n```"
        )

    def notify_progress(self, current: int, total: int, module_name: str):
        """Send a lightweight progress update."""
        if "module_complete" not in self.notify_on:
            return
        bar_len = 10
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(100 * current / total) if total > 0 else 0
        self.send_message(
            f"⏳ *Прогресс:* `[{bar}]` {pct}%\n"
            f"▶️ Текущий: *{module_name.upper()}* ({current}/{total})"
        )

    def notify_complete(self, target: str, summary: dict,
                        report_paths: str | list[str] | tuple[str, ...] | None = None):
        """Notify when the entire scan is complete."""
        if "complete" not in self.notify_on:
            return
        msg = (
            f"✅ *ReconX — Сканирование завершено*\n\n"
            f"🎯 Цель: `{target}`\n"
            f"📊 *Результаты:*\n"
            f"  • Субдоменов: {summary.get('subdomains', 0)}\n"
            f"  • Живых хостов: {summary.get('live_hosts', 0)}\n"
            f"  • Открытых портов: {summary.get('open_ports', 0)}\n"
            f"  • Технологий: {summary.get('technologies', 0)}\n"
            f"  • Уязвимостей: {summary.get('vulnerabilities', 0)}\n"
            f"  • Endpoints: {summary.get('endpoints', 0)}\n"
            f"  • JS Secrets: {summary.get('js_secrets', 0)}\n"
            f"  • Время: {summary.get('elapsed', '?')}\n"
        )
        grade = summary.get("ai_grade", "")
        if grade:
            msg += f"\n🛡️ *Оценка безопасности: {grade}*"

        self.send_message(msg)
        if not report_paths:
            return

        if isinstance(report_paths, (str, Path)):
            paths = [report_paths]
        else:
            paths = list(report_paths)

        labels = {
            ".md": "Markdown",
            ".html": "HTML",
            ".pdf": "PDF",
        }
        for report_path in paths:
            path = Path(report_path)
            if path.exists():
                label = labels.get(path.suffix.lower(), path.suffix.upper().lstrip("."))
                self.send_document(str(path), f"📄 ReconX {label} отчёт: {target}")
