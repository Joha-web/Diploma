"""
ReconX - Module: WebSocket endpoint discovery and low-impact handshake checks.
"""

from __future__ import annotations

import base64
import os
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase


WS_URL_RE = re.compile(r"wss?://[^\s'\"<>\\)]+", re.I)
WS_HINT_RE = re.compile(r"/(ws|wss|websocket|socket|sockjs|signalr|cable|hub|realtime|stream)(/|$|\?)", re.I)
COMMON_WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/sockjs",
    "/signalr",
    "/cable",
    "/realtime",
    "/stream",
]


class WebSocketProbeModule(ActiveProbeBase):
    name = "websocket_probe"
    description = "WebSocket Security Checks"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        live_hosts: list | None = None,
        fuzzer_results: dict | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.fuzzer_results = fuzzer_results or {}

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "endpoints": [], "total": 0, "status": "disabled"}

        endpoints = self.limit(self._endpoints(), "max_endpoints", 50)
        findings: list[dict] = []
        for endpoint in endpoints:
            if endpoint.startswith("ws://"):
                findings.append(self.make_finding(
                    "websocket_insecure_scheme",
                    endpoint,
                    evidence={"endpoint": endpoint},
                ))

        if self.module_config().get("active_handshake", True):
            for endpoint in endpoints:
                findings.extend(self._probe_endpoint(endpoint))

        findings = self.dedup_findings(findings)
        self.save_json(endpoints, "websocket_endpoints.json")
        self.save_json(findings, "websocket_findings.json")
        return {"findings": findings, "endpoints": endpoints, "total": len(findings)}

    def _endpoints(self) -> list[str]:
        endpoints: set[str] = set()

        def add(value: str) -> None:
            for match in WS_URL_RE.findall(str(value or "")):
                cleaned = match.rstrip(".,;]")
                if self._ws_in_scope(cleaned):
                    endpoints.add(cleaned)
            if str(value).startswith(("http://", "https://")) and WS_HINT_RE.search(str(value)):
                converted = self._http_to_ws(str(value))
                if self._ws_in_scope(converted):
                    endpoints.add(converted)

        for key, value in (self.fuzzer_results.get("classified", {}) or {}).items():
            if isinstance(value, list):
                for item in value:
                    add(str(item))
            else:
                add(str(value))
        for item in self.fuzzer_results.get("all_endpoints", []) or []:
            add(str(item))
        for item in self.fuzzer_results.get("js_urls", []) or []:
            add(str(item))

        bases = self.collect_live_urls(self.live_hosts)
        if self.module_config().get("discover_common_paths", True):
            for base in bases[: int(self.module_config().get("max_hosts", 30))]:
                for path in COMMON_WS_PATHS:
                    endpoints.add(self._http_to_ws(urljoin(base.rstrip("/") + "/", path.lstrip("/"))))

        return sorted(endpoint for endpoint in endpoints if self._ws_in_scope(endpoint))

    def _probe_endpoint(self, endpoint: str) -> list[dict]:
        findings: list[dict] = []
        timeout = self.request_timeout()
        normal = self._handshake(endpoint, origin=self._origin_for(endpoint), timeout=timeout)
        if normal.get("status") == 101:
            findings.append(self.make_finding(
                "websocket_unauthenticated_connect",
                endpoint,
                evidence={
                    "status": normal.get("status"),
                    "server": normal.get("headers", {}).get("server", ""),
                    "origin": self._origin_for(endpoint),
                },
            ))

        if self.module_config().get("check_origin", True):
            attacker_origin = self.module_config().get("attacker_origin", "https://attacker.reconx.invalid")
            attacker = self._handshake(endpoint, origin=attacker_origin, timeout=timeout)
            if attacker.get("status") == 101:
                findings.append(self.make_finding(
                    "websocket_origin_not_validated",
                    endpoint,
                    evidence={
                        "status": attacker.get("status"),
                        "origin": attacker_origin,
                        "server": attacker.get("headers", {}).get("server", ""),
                    },
                ))

        if self.module_config().get("message_probe", False) and self.config.get("scan", {}).get("allow_write", False):
            marker = "reconx_ws_probe"
            reflected = self._message_reflected(endpoint, marker, timeout=timeout)
            if reflected:
                findings.append(self.make_finding(
                    "websocket_reflected_message",
                    endpoint,
                    evidence={"marker": marker},
                ))
        return findings

    def _handshake(self, endpoint: str, origin: str = "", timeout: float = 8.0) -> dict:
        sock = None
        try:
            sock, response = self._open_websocket(endpoint, origin=origin, timeout=timeout)
            return response
        except OSError as exc:
            return {"status": 0, "headers": {}, "error": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _message_reflected(self, endpoint: str, marker: str, timeout: float = 8.0) -> bool:
        sock = None
        try:
            sock, response = self._open_websocket(endpoint, origin=self._origin_for(endpoint), timeout=timeout)
            if response.get("status") != 101:
                return False
            self._send_text_frame(sock, marker)
            message = self._recv_text_frame(sock)
            return marker in message
        except OSError:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _open_websocket(self, endpoint: str, origin: str = "", timeout: float = 8.0):
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        sock = raw_sock
        if parsed.scheme == "wss":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        host_header = host
        if parsed.port:
            host_header = f"{host}:{parsed.port}"
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: ReconX/2.0",
        ]
        if origin:
            headers.append(f"Origin: {origin}")
        request = "\r\n".join(headers) + "\r\n\r\n"
        sock.sendall(request.encode("ascii"))
        response_raw = self._recv_headers(sock)
        response = self._parse_handshake_response(response_raw)
        return sock, response

    @staticmethod
    def _recv_headers(sock) -> str:
        chunks: list[bytes] = []
        total = 0
        while total < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        return b"".join(chunks).decode("iso-8859-1", errors="replace")

    @staticmethod
    def _parse_handshake_response(raw: str) -> dict:
        lines = raw.splitlines()
        status = 0
        if lines:
            match = re.search(r"\s(\d{3})\s", lines[0])
            status = int(match.group(1)) if match else 0
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return {"status": status, "headers": headers, "raw": raw[:500]}

    @staticmethod
    def _send_text_frame(sock, message: str) -> None:
        payload = message.encode("utf-8")
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x81])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend([0x80 | 126, (length >> 8) & 0xFF, length & 0xFF])
        else:
            raise OSError("message too large")
        masked = bytes(byte ^ mask[idx % 4] for idx, byte in enumerate(payload))
        sock.sendall(bytes(header) + mask + masked)

    @staticmethod
    def _recv_text_frame(sock) -> str:
        first = sock.recv(2)
        if len(first) < 2:
            return ""
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        masked = bool(first[1] & 0x80)
        if length == 126:
            length = int.from_bytes(sock.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(sock.recv(8), "big")
        mask = sock.recv(4) if masked else b""
        payload = sock.recv(min(length, 4096))
        if masked:
            payload = bytes(byte ^ mask[idx % 4] for idx, byte in enumerate(payload))
        if opcode != 1:
            return ""
        return payload.decode("utf-8", errors="replace")

    def _ws_in_scope(self, endpoint: str) -> bool:
        parsed = urlparse(str(endpoint or ""))
        if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
            return False
        http_url = ("https" if parsed.scheme == "wss" else "http") + "://" + parsed.netloc + (parsed.path or "/")
        return self.is_in_scope(http_url)

    @staticmethod
    def _http_to_ws(url: str) -> str:
        parsed = urlparse(url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urlunparse(parsed._replace(scheme=scheme))

    @staticmethod
    def _origin_for(endpoint: str) -> str:
        parsed = urlparse(endpoint)
        scheme = "https" if parsed.scheme == "wss" else "http"
        return f"{scheme}://{parsed.netloc}"
