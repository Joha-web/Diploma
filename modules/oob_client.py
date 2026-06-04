"""
Reusable Interactsh out-of-band (OOB) client mixin.

Wraps VulnScanModule's interactsh-client lifecycle so any active-probe module can
confirm server-side fetches (SSRF, RFI) via an OOB callback, instead of relying
only on reflected/in-band signals. Mirrors the plumbing injection_probe already
uses for OOB SSRF; centralised here so file_inclusion (and future modules) reuse
it without duplicating the lifecycle.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from modules.vulnscan import VulnScanModule


class OOBClientMixin:
    """Adds an Interactsh OOB client to a BaseModule subclass.

    Requires the host class to be a BaseModule (provides has_tool, module_dir,
    output_dir, _subprocess_env, success/warn) and to set `self._oob_process`.
    """

    # ── Lifecycle (delegates to VulnScanModule's implementation) ─────────────────
    def _start_oob_runtime(self, cfg: dict) -> dict:
        """Start the interactsh client and return its runtime (callback_url, …)."""
        oob_cfg = dict(self.config.get("scan", {}).get("nuclei", {}).get("oob", {}) or {})
        oob_cfg.update(cfg.get("oob", {}) or {})
        return VulnScanModule._apply_oob_flags(self, [], {"oob": oob_cfg})

    def _start_interactsh_client(self, oob_cfg: dict) -> dict:
        return VulnScanModule._start_interactsh_client(self, oob_cfg)

    def _read_interactsh_callback(self, proc, timeout: float = 10) -> str:
        return VulnScanModule._read_interactsh_callback(self, proc, timeout)

    def _stop_oob_client(self, runtime: dict) -> None:
        VulnScanModule._stop_oob_client(self, runtime)

    _extract_interactsh_callback = staticmethod(VulnScanModule._extract_interactsh_callback)
    _server_from_callback = staticmethod(VulnScanModule._server_from_callback)

    # ── Interaction reading / matching ───────────────────────────────────────────
    def _read_oob_interactions(self, runtime: dict) -> list[dict]:
        rel = runtime.get("interactions_log", "")
        path = (self.output_dir / rel) if rel else (self.module_dir / "interactsh_interactions.jsonl")
        path = Path(path)
        if not path.exists():
            return []
        interactions: list[dict] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                interactions.append(json.loads(line))
            except json.JSONDecodeError:
                interactions.append({"raw": line})
        return interactions

    @staticmethod
    def _callback_host(callback: str) -> str:
        value = str(callback or "").strip()
        if "://" in value:
            return (urlparse(value).hostname or "").strip(".").lower()
        return value.split("/", 1)[0].strip(".").lower()

    @classmethod
    def _oob_url(cls, callback: str, token: str, path: str = "/") -> str:
        """A unique attacker URL on the callback domain: http://<token>.<host><path>."""
        host = cls._callback_host(callback)
        return f"http://{token}.{host}{path}" if host else callback

    @classmethod
    def _matching_interactions(cls, interactions: list[dict], token: str, callback: str) -> list[dict]:
        matched: list[dict] = []
        cb_host = cls._callback_host(callback)
        for item in interactions:
            text = json.dumps(item, default=str).lower()
            if token and token.lower() in text:
                matched.append(item)
            elif not token and cb_host and cb_host in text:
                matched.append(item)
        return matched
