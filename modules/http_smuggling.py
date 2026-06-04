"""
ReconX - Module: HTTP request smuggling timing probes.

The module sends malformed framing probes for CL.TE, TE.CL and TE.TE
desync indicators. It does not send a queued backend request.
"""

import socket
import ssl
import time
from urllib.parse import ParseResult, urlparse as _raw_urlparse


def urlparse(url):
    """urlparse that never raises 'Invalid IPv6 URL' on a malformed URL."""
    try:
        return _raw_urlparse(str(url or ""))
    except ValueError:
        return ParseResult("", "", str(url or ""), "", "", "")

from modules.base import BaseModule


CL_TE_PAYLOAD = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

TE_CL_PAYLOAD = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 3\r\n"
    "Connection: close\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
)

TE_TE_VARIANTS = [
    {"Transfer-Encoding": "xchunked"},
    {"Transfer-Encoding": " chunked"},
    {"Transfer-Encoding": "chunked "},
    {"Transfer-Encoding": "CHUNKED"},
    {"Transfer-Encoding": "Chunked"},
    {"Transfer-Encoding": "chunked\x0b"},
    {"Transfer-Encoding": "chunked\x00"},
    {"Transfer-Encoding": "x", "Transfer-encoding": "chunked"},
    {"Transfer-Encoding": "\tchunked"},
    {"Transfer-Encoding": "identity, chunked"},
]


class HTTPSmugglingModule(BaseModule):
    name = "http_smuggling"
    description = "HTTP Request Smuggling Detection (CL.TE / TE.CL / TE.TE)"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self._baseline_cache: dict[tuple[str, int], float | None] = {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("http_smuggling", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "total": 0, "status": "disabled"}

        urls = self._extract_urls()[: int(cfg.get("max_urls", 40))]
        if not urls:
            self.warn("No URLs for HTTP smuggling checks")
            return {"findings": [], "total": 0}

        findings: list[dict] = []
        for url in urls:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                continue
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            for probe in (self._probe_cl_te, self._probe_te_cl, self._probe_te_te):
                finding = probe(host, port, parsed.scheme, path, url, cfg)
                if finding:
                    findings.append(finding)
                    break

        self.save_json(findings, "smuggling_findings.json")
        return {"findings": findings, "total": len(findings)}

    # ── Differential-timing helpers ──────────────────────────────────────────
    def _baseline(self, host: str, port: int, scheme: str, path: str, cfg: dict) -> float | None:
        """Time a well-formed request to the same host so timing is judged
        relative to normal latency — not against a fixed threshold a slow server
        would always trip. Cached per host:port; min of two samples for stability.
        """
        key = (host, port)
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        benign = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        samples = [self._raw_send(host, port, scheme, benign, cfg) for _ in range(2)]
        samples = [s for s in samples if s is not None]
        value = min(samples) if samples else None
        self._baseline_cache[key] = value
        return value

    def _timing_desync(self, host: str, port: int, scheme: str, payload: str,
                       baseline: float | None, cfg: dict) -> float | None:
        """Return elapsed only if the malformed payload stalls *substantially
        longer than baseline* (floor + delta), re-confirmed once to drop jitter."""
        if baseline is None:
            return None
        floor = float(cfg.get("timing_threshold", 4.5))
        delta = float(cfg.get("timing_delta", 3.0))
        elapsed = self._raw_send(host, port, scheme, payload, cfg)
        if elapsed is None or elapsed < floor or (elapsed - baseline) < delta:
            return None
        confirm = self._raw_send(host, port, scheme, payload, cfg)
        if confirm is None or confirm < floor or (confirm - baseline) < delta:
            return None  # one-off stall, not a consistent desync
        return elapsed

    def _probe_cl_te(self, host: str, port: int, scheme: str, path: str,
                     url: str, cfg: dict) -> dict | None:
        baseline = self._baseline(host, port, scheme, path, cfg)
        elapsed = self._timing_desync(host, port, scheme,
                                      CL_TE_PAYLOAD.format(host=host, path=path), baseline, cfg)
        if elapsed is not None:
            return self._finding("http_smuggling_cl_te", "HIGH", url, {
                "method": "CL.TE", "elapsed": round(elapsed, 2),
                "baseline": round(baseline, 2), "threshold": float(cfg.get("timing_threshold", 4.5)),
                "delta_required": float(cfg.get("timing_delta", 3.0)),
            })
        return None

    def _probe_te_cl(self, host: str, port: int, scheme: str, path: str,
                     url: str, cfg: dict) -> dict | None:
        baseline = self._baseline(host, port, scheme, path, cfg)
        elapsed = self._timing_desync(host, port, scheme,
                                      TE_CL_PAYLOAD.format(host=host, path=path), baseline, cfg)
        if elapsed is not None:
            return self._finding("http_smuggling_te_cl", "HIGH", url, {
                "method": "TE.CL", "elapsed": round(elapsed, 2),
                "baseline": round(baseline, 2), "threshold": float(cfg.get("timing_threshold", 4.5)),
                "delta_required": float(cfg.get("timing_delta", 3.0)),
            })
        return None

    def _probe_te_te(self, host: str, port: int, scheme: str, path: str,
                     url: str, cfg: dict) -> dict | None:
        baseline = self._baseline(host, port, scheme, path, cfg)
        for headers in TE_TE_VARIANTS[: int(cfg.get("max_te_variants", len(TE_TE_VARIANTS)))]:
            header_blob = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                f"{header_blob}"
                "Connection: close\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "X"
            )
            elapsed = self._timing_desync(host, port, scheme, payload, baseline, cfg)
            if elapsed is not None:
                return self._finding("http_smuggling_te_te", "HIGH", url, {
                    "method": "TE.TE", "elapsed": round(elapsed, 2),
                    "baseline": round(baseline, 2), "threshold": float(cfg.get("timing_threshold", 4.5)),
                    "delta_required": float(cfg.get("timing_delta", 3.0)),
                    "variant_headers": headers,
                })
        return None

    def _raw_send(self, host: str, port: int, scheme: str, payload: str, cfg: dict) -> float | None:
        try:
            sock = socket.create_connection((host, port), timeout=float(cfg.get("connect_timeout", 8)))
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(float(cfg.get("read_timeout", 6)))
            sock.sendall(payload.encode("utf-8", errors="replace"))
            start = time.monotonic()
            try:
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
            except socket.timeout:
                pass
            finally:
                elapsed = time.monotonic() - start
                sock.close()
            return elapsed
        except (ConnectionRefusedError, OSError, ssl.SSLError) as exc:
            self.info(f"  {host}:{port} — connection failed ({exc.__class__.__name__})")
            return None

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        for path in (
            self.session_path("webdetect", "live_urls.txt"),
            self.session_path("recon", "subdomains", "httpx_live.txt"),
        ):
            urls.update(self.load_lines(path))

        seen: set[str] = set()
        result: list[str] = []
        for url in self.filter_in_scope_urls(urls):
            parsed = urlparse(url)
            if not parsed.hostname:
                continue
            key = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
            if key not in seen:
                seen.add(key)
                result.append(url)
        return result

    def _finding(self, finding_id: str, severity: str, url: str, evidence: dict) -> dict:
        method = evidence.get("method", "")
        title = f"HTTP Request Smuggling timing indicator ({method})"
        return {
            "source": self.name,
            "id": finding_id,
            "type": finding_id,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": (
                "Malformed HTTP framing caused a timing stall consistent with a potential "
                "frontend/backend request parsing desynchronization. Validate manually."
            ),
            "evidence": evidence,
            "references": [
                "https://portswigger.net/web-security/request-smuggling",
                "https://cwe.mitre.org/data/definitions/444.html",
            ],
            "confidence": 0.8,
        }
