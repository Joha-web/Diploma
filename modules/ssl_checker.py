"""
ReconX — Module: SSL/TLS & Security Headers Analysis
Uses Python stdlib ssl + requests (no external CLI tools needed).
"""

import re
import ssl
import socket
import urllib3
from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

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
        for url in https_urls[:60]:
            host = self._host_from_url(url)
            result = self._check_ssl(host)
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

    def _check_ssl(self, host: str, port: int = 443) -> dict:
        base = {"host": host, "port": port, "issues": []}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_OPTIONAL

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()

            base["protocol"] = version
            base["cipher"]   = cipher[0] if cipher else None

            issues: list[str] = []

            # Weak protocol
            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                issues.append(f"WEAK_PROTOCOL:{version}")

            if cert:
                # Expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days = (exp - now).days
                        base["expires"]           = not_after
                        base["days_until_expiry"] = days
                        if days < 0:
                            issues.append("CERT_EXPIRED")
                        elif days < 30:
                            issues.append(f"EXPIRING_SOON:{days}d")
                    except ValueError:
                        pass

                # Self-signed detection (issuer == subject)
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                if issuer.get("organizationName") == subject.get("organizationName") \
                        and issuer.get("organizationName"):
                    issues.append("SELF_SIGNED")

                base["issuer"] = issuer.get("organizationName", "Unknown")
                base["san"]    = [x[1] for x in cert.get("subjectAltName", [])][:10]

            base["issues"] = issues
            return base

        except ssl.SSLCertVerificationError as e:
            base["issues"] = ["CERT_INVALID", str(e)[:100]]
            return base
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            base["issues"] = ["CONNECTION_FAILED"]
            base["error"]  = str(e)
            return base
        except Exception as e:
            base["issues"] = ["UNKNOWN_ERROR"]
            base["error"]  = str(e)
            return base

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
        try:
            resp = sess.get(url, timeout=10, allow_redirects=True)
        except RequestException:
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
        for line in self.live_hosts:
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        return sorted(urls)

    @staticmethod
    def _host_from_url(url: str) -> str:
        return url.split("//", 1)[1].split("/")[0].split(":")[0]
