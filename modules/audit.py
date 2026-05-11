"""
Append-only audit logger for in-process HTTP requests.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Write request metadata to audit.jsonl in the scan session directory."""

    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, output_dir: str | Path):
        self.path = Path(output_dir) / "audit.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = str(self.path)
        with self._locks_guard:
            self._lock = self._locks.setdefault(key, threading.Lock())

    def log_request(
        self,
        module: str,
        url: str,
        method: str,
        status: int | None,
        elapsed: float,
        in_scope: bool = True,
        error: str = "",
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "module": module,
            "url": url[:2048],
            "method": method.upper(),
            "status": status,
            "elapsed": round(elapsed, 3),
            "in_scope": bool(in_scope),
        }
        if error:
            entry["error"] = error[:300]

        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
