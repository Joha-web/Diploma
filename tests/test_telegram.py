import logging

import requests

from reporting.telegram import TelegramNotifier


def test_telegram_document_errors_redact_bot_token(tmp_path, monkeypatch, caplog):
    token = "123456:super-secret-token"
    notifier = TelegramNotifier({
        "telegram": {
            "enabled": True,
            "bot_token": token,
            "chat_id": "42",
        }
    })
    notifier.max_retries = 1
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    def raise_connection_error(*args, **kwargs):
        raise requests.ConnectionError(
            f"HTTPSConnectionPool(host='api.telegram.org'): /bot{token}/sendDocument"
        )

    monkeypatch.setattr(requests, "post", raise_connection_error)

    with caplog.at_level(logging.WARNING, logger="reconx.telegram"):
        assert notifier.send_document(str(report)) is False

    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert token not in logs
    assert "/bot<redacted>/sendDocument" in logs
