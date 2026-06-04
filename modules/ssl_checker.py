"""
ReconX — Module: SSL/TLS & Security Headers Analysis
Uses Python stdlib ssl + requests (no external CLI tools needed).
"""

import re
import ssl
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from modules.base import BaseModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS: dict[str, dict] = {
    "strict-transport-security":   {"name": "HSTS",                    "severity": "HIGH"},
    "content-security-policy":     {"name": "CSP",                     "severity": "HIGH"},
    "x-frame-options":             {"name": "X-Frame-Options",         "severity": "HIGH"},
    "x-content-type-options":      {"name": "X-Content-Type-Options",  "severity": "MEDIUM"},
    "referrer-policy":             {"name": "Referrer-Policy",         "severity": "MEDIUM"},
    "permissions-policy":          {"name": "Permissions-Policy",      "severity": "LOW"},
    "x-xss-protection":            {"name": "X-XSS-Protection",        "severity": "LOW"},
}

DEPRECATED_HEADERS: set[str] = {"x-xss-protection", "expect-ct"}


class SSLCheckerModule(BaseModule):
    name = "ssl_checker"
    description = "SSL/TLS & Security Headers Analysis"
    required_tools = []   # stdlib + requests only

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        urls = self._extract_urls()
        if not urls:
            self.warn("No hosts to check")
            return {"ssl": [], "headers": [], "ssl_issues": [],
                    "total_missing_headers": 0}

        https_urls = [u for u in urls if u.startswith("https://")]

        # SSL/TLS checks
        ssl_results: list[dict] = []
        if https_urls:
            workers = min(20, max(1, len(https_urls[:60])))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._check_ssl, *self._host_port_from_url(url)): url
                    for url in https_urls[:60]
                }
                for future in as_completed(futures):
                    result = future.result()
                    ssl_results.append(result)
                    self._log_ssl(result)

        # Security headers checks
        sess = requests.Session()
        sess.verify = False
        header_results: list[dict] = []
        for url in urls[:60]:
            r = self._check_headers(url, sess)
            if r:
                header_results.append(r)

        self.save_json(ssl_results,    "ssl_results.json")
        self.save_json(header_results, "headers_results.json")

        issues         = [r for r in ssl_results if r.get("issues")]
        missing_total  = sum(len(h.get("missing", [])) for h in header_results)

        self.success(f"SSL checked: {len(ssl_results)} hosts")
        if missing_total:
            self.warn(f"Missing security headers: {missing_total} across {len(header_results)} hosts")

        return {
            "ssl":                   ssl_results,
            "headers":               header_results,
            "ssl_issues":            issues,
            "total_missing_headers": missing_total,
        }

    def summary(self) -> str:
        issues  = len(self.results.get("ssl_issues", []))
        missing = self.results.get("total_missing_headers", 0)
        return f"🔒 {issues} SSL issues | 🛡 {missing} missing headers"

    # ── SSL/TLS ───────────────────────────────────────────────────────────────

    KNOWN_PUBLIC_CAS = {
        "digicert", "comodo", "sectigo", "globalsign", "letsencrypt",
        "let's encrypt", "entrust", "godaddy", "verisign", "geotrust",
        "amazon", "microsoft", "google", "cloudflare", "rapidssl",
        "thawte", "usertrust", "identrust", "isrg", "ssl corporation",
    }

    def _check_ssl(self, host: str, port: int = 443) -> dict:
        base = {"host": host, "port": port, "issues": []}
        issues: list[str] = []

        # Three independent handshakes — each runs regardless of the others so a
        # flaky/failed modern handshake never suppresses a real cert finding:
        #   • lenient (CERT_NONE) → negotiated protocol + cipher
        #   • verifying            → trust/hostname, and the cert dict on success
        #   • weak-protocol probe  → explicit TLS1.0/1.1 (default ctx won't negotiate)
        info = self._handshake_info(host, port)
        verify = self._verify(host, port)
        weak = self._weak_protocols(host, port)

        if not (info.get("version") or verify["ok"] or verify["issue"] or weak):
            base["issues"] = ["CONNECTION_FAILED"]
            base["error"] = info.get("error", "")
            return base

        if info.get("version"):
            base["protocol"] = info["version"]
            base["cipher"] = info.get("cipher")
        elif weak:
            base["protocol"] = weak[-1]      # only weak protocols are accepted
            issues.append("NO_MODERN_TLS")

        if verify["ok"] and verify["cert"]:
            issues.extend(self._analyze_cert(verify["cert"], base))
        elif verify["issue"]:
            issues.append(verify["issue"])

        if weak:
            base["weak_protocols"] = weak
            issues.extend(f"WEAK_PROTOCOL:{w}" for w in weak)

        base["issues"] = sorted(set(issues))
        return base

    def _handshake_info(self, host: str, port: int) -> dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    return {
                        "version": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "cert": ssock.getpeercert(),
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
            return {"error": f"{exc.__class__.__name__}: {exc}"[:120]}

    def _analyze_cert(self, cert: dict, base: dict) -> list[str]:
        """Expiry + self-signed analysis from a parsed cert dict. Pure given the
        cert (unit-testable); also fills base['expires'/'days_until_expiry'/…]."""
        issues: list[str] = []
        if not cert:
            return issues

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                base["expires"] = not_after
                base["days_until_expiry"] = days
                if days < 0:
                    issues.append("CERT_EXPIRED")
                elif days < 30:
                    issues.append(f"EXPIRING_SOON:{days}d")
            except ValueError:
                pass

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer_org = (issuer.get("organizationName") or "").strip().lower()
        subject_org = (subject.get("organizationName") or "").strip().lower()
        issuer_cn = (issuer.get("commonName") or "").strip().lower()
        subject_cn = (subject.get("commonName") or "").strip().lower()
        is_known_ca = any(ca in issuer_org for ca in self.KNOWN_PUBLIC_CAS)
        if (not is_known_ca
                and issuer_org and issuer_org == subject_org
                and issuer_cn and issuer_cn == subject_cn):
            issues.append("SELF_SIGNED")

        base["issuer"] = issuer.get("organizationName", "Unknown")
        base["san"] = [x[1] for x in cert.get("subjectAltName", [])][:10]
        return issues

    def _verify(self, host: str, port: int) -> dict:
        """Strict (trust + hostname) handshake. On success returns the validated
        cert dict; on a verification failure returns the classified issue."""
        ctx = ssl.create_default_context()   # CERT_REQUIRED + check_hostname
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return {"ok": True, "cert": ssock.getpeercert(), "issue": None}
        except ssl.SSLCertVerificationError as exc:
            return {"ok": False, "cert": None, "issue": self._classify_verify_error(str(exc))}
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            return {"ok": False, "cert": None, "issue": None}  # connection issue, handled elsewhere

    @staticmethod
    def _classify_verify_error(msg: str) -> str:
        m = (msg or "").lower()
        if "expired" in m:
            return "CERT_EXPIRED"
        # untrusted root presents as "self signed certificate in certificate chain"
        # — distinguish it from a leaf self-signed cert before the generic check.
        if ("certificate chain" in m or "unable to get local issuer" in m
                or "unable to verify the first certificate" in m):
            return "CERT_UNTRUSTED"
        if "self-signed" in m or "self signed" in m:
            return "SELF_SIGNED"
        if "hostname" in m or "doesn't match" in m or "ip address mismatch" in m:
            return "HOSTNAME_MISMATCH"
        return "CERT_INVALID"

    def _weak_protocols(self, host: str, port: int) -> list[str]:
        """Best-effort: explicitly try TLS 1.0 / 1.1 handshakes; flag any the
        server accepts. Degrades silently if the local OpenSSL refuses the old
        version (so it never false-flags)."""
        found: list[str] = []
        for label, version in (("TLSv1", ssl.TLSVersion.TLSv1),
                                ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # allow legacy ciphers/protocols
                except ssl.SSLError:
                    pass
                with socket.create_connection((host, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        if ssock.version() == label:
                            found.append(label)
            except Exception:
                continue
        return found

    def _log_ssl(self, r: dict):
        host   = r.get("host", "?")
        issues = r.get("issues", [])
        days   = r.get("days_until_expiry")
        if "CERT_EXPIRED" in issues or "SELF_SIGNED" in issues:
            self.warn(f"  🔴 {host}: {', '.join(issues)}")
        elif issues:
            self.warn(f"  🟡 {host}: {', '.join(issues)}")
        elif days is not None:
            self.success(f"  ✓ {host} | expires in {days} days")

    # ── Security headers ──────────────────────────────────────────────────────

    def _check_headers(self, url: str, sess: requests.Session) -> dict | None:
        resp = self.http_get(url, session=sess, timeout=10, allow_redirects=True)
        if resp is None:
            return None

        h = {k.lower(): v for k, v in resp.headers.items()}
        present: list[dict] = []
        missing: list[dict] = []

        for header, info in SECURITY_HEADERS.items():
            if header in h:
                present.append({
                    "header": info["name"],
                    "value":  h[header][:200],
                })
            else:
                missing.append({
                    "header":   info["name"],
                    "severity": info["severity"],
                })

        # CORS check
        cors = h.get("access-control-allow-origin", "")
        cors_issue = None
        if cors == "*":
            cors_issue = {
                "type":     "CORS_WILDCARD",
                "severity": "MEDIUM",
                "detail":   "Access-Control-Allow-Origin: *",
            }
        elif cors:
            cors_issue = {
                "type":   "CORS_SPECIFIC",
                "origin": cors,
            }

        # Information leakage
        leak: list[str] = []
        for lh in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if lh in h:
                leak.append(f"{lh}: {h[lh]}")

        return {
            "url":        url,
            "status":     resp.status_code,
            "present":    present,
            "missing":    missing,
            "cors_issue": cors_issue,
            "info_leak":  leak,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        return self.filter_in_scope_urls(urls)

    @staticmethod
    def _host_port_from_url(url: str) -> tuple[str, int]:
        parsed = urlparse(url)
        host = parsed.hostname or url.split("//", 1)[-1].split("/")[0].split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return host, port
