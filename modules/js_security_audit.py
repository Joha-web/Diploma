"""
ReconX - Module: static JavaScript security audit.
"""

from __future__ import annotations

import re
from urllib.parse import ParseResult, urljoin, urlparse as _raw_urlparse


def urlparse(url):
    """urlparse that never raises 'Invalid IPv6 URL' on a malformed URL."""
    try:
        return _raw_urlparse(str(url or ""))
    except ValueError:
        return ParseResult("", "", str(url or ""), "", "", "")

import requests

from modules.active_probe_base import ActiveProbeBase


JS_FILE_RE = re.compile(r"\.m?js(?:[?#].*)?$", re.I)
DOM_SOURCE_RE = re.compile(
    r"(location\.(hash|search|href)|document\.(URL|documentURI|referrer)|"
    r"URLSearchParams|localStorage|sessionStorage|window\.name)",
    re.I,
)
DOM_SINK_RE = re.compile(
    r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[^,)]*(location|URLSearchParams))",
    re.I,
)
GRAPHQL_RE = re.compile(r"""["'`]((?:https?:)?//[^"'`]+/graphql[^"'`]*|/[^"'`]*graphql[^"'`]*)["'`]""", re.I)

# Well-known third-party JavaScript libraries. The `.innerHTML=` and similar sinks
# in these files are part of the library's own implementation, not an application
# bug, so we either skip them entirely or downgrade their findings to INFO.
VENDOR_LIB_FILENAME_RE = re.compile(
    r"(?:^|/)("
    r"jquery(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"jquery\.[a-z0-9_-]+\.m?js|"
    r"jquery-ui(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"react(?:-dom)?(?:[-.][\w.]*)?(?:\.min|\.production|\.development)?\.m?js|"
    r"vue(?:[-.][\w.]*)?(?:\.min|\.runtime|\.common|\.esm)?\.m?js|"
    r"vue-router(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"vuex(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"angular(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"ember(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"backbone(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"underscore(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"lodash(?:[-.][\w.]*)?(?:\.min|\.fp|\.core)?\.m?js|"
    r"moment(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"bootstrap(?:[-.][\w.]*)?(?:\.bundle)?(?:\.min)?\.m?js|"
    r"popper(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"tippy(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"uikit(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"foundation(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"semantic(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"materialize(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"chart(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"d3(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"three(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"axios(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"socket\.io(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"summernote(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"tinymce(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"ckeditor(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"datatables?(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"swiper(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"select2(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"pdf(?:js|\.worker)(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"highlight(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"flatpickr(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"core-js(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"polyfill(?:[-.][\w.]*)?(?:\.min)?\.m?js|"
    r"runtime~?[\w.-]*\.m?js|"
    r"chunk~?[\w.-]*\.m?js|"
    r"vendor[s]?~?[\w.-]*\.m?js|"
    r"vendors~main\.[\w.-]*\.m?js|"
    r"manifest~?[\w.-]*\.m?js"
    r")(?:[?#].*)?$",
    re.I,
)

# URL path tokens that indicate a vendor/library directory
VENDOR_LIB_PATH_RE = re.compile(
    r"/(?:node_modules|vendor|vendors|bower_components|third[_-]?party|"
    r"libs?|jslib|jsLibs|cdn|external)/",
    re.I,
)
REDIRECT_RE = re.compile(
    # A redirect "sink": setting location, calling location.assign/replace, or window.open.
    r"((?:window\.)?location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\()"
    # The bridge between sink and source must stay inside a single statement: no
    # semicolons, newlines, or block-closing braces. In minified Angular bundles,
    # functions are separated only by `}` (not `;`) so we MUST exclude `}` or the
    # match crosses unrelated function boundaries.
    r"[^;\n}]{0,180}"
    # A tainted source: location.hash/.search/.href, document.URL/.documentURI/
    # .referrer, URLSearchParams, window.name, getParameter, queryString, event.data.
    # We deliberately do NOT match a bare `location.` here — that was the previous
    # bug: `location.replace(...)` followed by `window.location.assign(...)` in the
    # NEXT function counts the inner `location.` as a "source" and produces a FP.
    r"(location\.(?:hash|search|href)|document\.URL|document\.documentURI|"
    r"document\.referrer|URLSearchParams|searchParams|window\.name|"
    r"getParameter|queryString|event\.data)",
    re.I,
)
MESSAGE_HANDLER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]\s*,(?P<body>.{0,1200}?)(?:\n\s*\}\s*\)|\)\s*;)",
    re.I | re.S,
)


class JSSecurityAuditModule(ActiveProbeBase):
    name = "js_security_audit"
    description = "Static JavaScript Security Audit"
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
            return {"findings": [], "js_urls": [], "total": 0, "status": "disabled"}

        js_urls = self.limit(self._js_urls(), "max_js", 150)
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        findings: list[dict] = []
        analyzed: list[dict] = []
        timeout = self.request_timeout()

        for url in js_urls:
            resp = self.http_get(url, session=session, timeout=timeout, verify=False)
            if resp is None or resp.status_code != 200:
                continue
            content = resp.text or ""
            analyzed.append({"url": url, "bytes": len(content)})
            findings.extend(self._analyse_js(url, content))

        findings = self.dedup_findings(findings)
        self.save_json(analyzed, "js_security_analyzed.json")
        self.save_json(findings, "js_security_findings.json")
        return {
            "findings": findings,
            "js_urls": js_urls,
            "analyzed": analyzed,
            "total": len(findings),
        }

    def _js_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.fuzzer_results.get("js_urls", []) or []:
            if JS_FILE_RE.search(str(item)):
                urls.add(str(item))
        for item in self.fuzzer_results.get("all_endpoints", []) or []:
            if JS_FILE_RE.search(str(item)):
                urls.add(str(item))
        classified = self.fuzzer_results.get("classified", {}) or {}
        for bucket in classified.values():
            if isinstance(bucket, list):
                for item in bucket:
                    if JS_FILE_RE.search(str(item)):
                        urls.add(str(item))

        for base in self.collect_live_urls(self.live_hosts)[: int(self.module_config().get("max_html_hosts", 40))]:
            for candidate in self._common_js_candidates(base):
                urls.add(candidate)
        return self.filter_in_scope_urls(urls)

    def _analyse_js(self, url: str, content: str) -> list[dict]:
        findings: list[dict] = []
        is_vendor = self._is_vendor_library(url, content)
        # For vendor libraries we still surface GraphQL hardcoded endpoints (those are
        # almost never library-internal) but skip DOM-XSS / unsafe-redirect / postMessage
        # rules because their matches reflect the library's own implementation.
        if not is_vendor:
            is_min = self._is_minified_bundle(content)
            findings.extend(self._dom_xss_findings(url, content, minified=is_min))
            findings.extend(self._postmessage_findings(url, content, minified=is_min))
            findings.extend(self._redirect_findings(url, content))
        findings.extend(self._graphql_findings(url, content))
        return findings

    @staticmethod
    def _is_minified_bundle(content: str) -> bool:
        """Detect a heavily-minified single-line bundle.

        In compiled Angular/React/Vue production bundles the entire file collapses to
        very few extremely long lines. DOM-XSS / postMessage heuristics in those
        bundles produce mostly FPs because we cannot reliably read the surrounding
        context. We downgrade severity / suppress noise in that case.

        Primary signal is average line length — a real source file rarely averages
        more than ~200 chars/line, while minified bundles routinely sit above 800.
        We still apply a small absolute-size floor so 5-line config snippets do not
        get classified as bundles.
        """
        if not content:
            return False
        size = len(content)
        if size < 4000:
            return False
        line_count = content.count("\n") + 1
        return (size / max(line_count, 1)) > 400

    @staticmethod
    def _is_vendor_library(url: str, content: str) -> bool:
        """Best-effort detection of a third-party JS library file."""
        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None
        path = parsed.path if parsed else url
        if VENDOR_LIB_FILENAME_RE.search(path):
            return True
        if VENDOR_LIB_PATH_RE.search(path):
            return True
        # Look for typical library headers in the first ~2KB of content.
        head = (content or "")[:2048]
        head_l = head.lower()
        library_banners = (
            "jquery javascript library",
            "jquery foundation",
            "jquery.com",
            "/*! jquery",
            "/*! react",
            "/*! vue.js",
            "/*! lodash",
            "/*! bootstrap",
            "/*! popper",
            "/*! uikit",
            "/*! axios",
            "/*! chart.js",
            "/*! d3 ",
            "/*! moment.js",
            "/*! tippy.js",
            "/*! ckeditor",
            "/*! summernote",
            "github.com/jquery",
            "github.com/facebook/react",
            "github.com/vuejs/",
            "github.com/lodash/",
            "github.com/twbs/bootstrap",
            "licensed under mit",
            "released under the mit license",
        )
        return any(banner in head_l for banner in library_banners)

    def _dom_xss_findings(self, url: str, content: str, minified: bool = False) -> list[dict]:
        findings: list[dict] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if not DOM_SINK_RE.search(line):
                continue
            sink_match = DOM_SINK_RE.search(line)
            # In a minified bundle a "line" can be hundreds of KB; the original "is a
            # source on the same line?" heuristic flags too aggressively because *any*
            # access to location.search anywhere in the bundle co-occurs with *any*
            # innerHTML elsewhere on the same long line. Require the source and sink
            # to be within a small character window of each other for minified bundles.
            if minified:
                sink_pos = sink_match.start()
                window = line[max(0, sink_pos - 200): sink_pos + 200]
                if not DOM_SOURCE_RE.search(window):
                    continue
                severity_override = "LOW"
                confidence_override = 0.4
            else:
                if not (DOM_SOURCE_RE.search(line) or self._near_source(lines, idx - 1)):
                    continue
                severity_override = None
                confidence_override = None
            sink = sink_match.group(1)
            finding = self.make_finding(
                "js_dom_xss_sink",
                url,
                evidence={
                    "line": idx,
                    "sink": sink,
                    "source_nearby": True,
                    "snippet": self._trim(line),
                    "minified": bool(minified),
                },
            )
            if severity_override:
                finding["severity"] = severity_override
            if confidence_override is not None:
                finding["confidence"] = confidence_override
            findings.append(finding)
        return findings[: int(self.module_config().get("max_findings_per_js", 20))]

    def _postmessage_findings(self, url: str, content: str, minified: bool = False) -> list[dict]:
        findings: list[dict] = []
        for match in MESSAGE_HANDLER_RE.finditer(content):
            body = match.group("body")
            if re.search(r"\borigin\b", body, re.I) and re.search(r"(===|!==|includes|indexOf|endsWith|startsWith)", body):
                continue
            # Minified handlers in framework bundles often deal with their own worker
            # or iframe IPC where origin checks are intentionally absent (canvas-confetti,
            # web3 sandbox iframes, etc.). We surface them at LOW confidence rather than
            # claiming a security defect we can't verify.
            finding = self.make_finding(
                "js_postmessage_missing_origin_check",
                url,
                evidence={
                    "line": self._line_number(content, match.start()),
                    "snippet": self._trim(body),
                    "minified": bool(minified),
                },
            )
            if minified:
                finding["severity"] = "LOW"
                finding["confidence"] = 0.35
            findings.append(finding)
        return findings[: int(self.module_config().get("max_postmessage_findings", 10))]

    def _graphql_findings(self, url: str, content: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for match in GRAPHQL_RE.finditer(content):
            endpoint = match.group(1)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            absolute = self._absolute_url(url, endpoint)
            findings.append(self.make_finding(
                "js_hardcoded_graphql_endpoint",
                absolute or url,
                evidence={
                    "source_js": url,
                    "endpoint": endpoint,
                    "line": self._line_number(content, match.start()),
                },
            ))
        return findings[: int(self.module_config().get("max_graphql_findings", 20))]

    def _redirect_findings(self, url: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for match in REDIRECT_RE.finditer(content):
            findings.append(self.make_finding(
                "js_unsafe_redirect",
                url,
                evidence={
                    "line": self._line_number(content, match.start()),
                    "snippet": self._trim(match.group(0)),
                },
            ))
        return findings[: int(self.module_config().get("max_redirect_findings", 10))]

    @staticmethod
    def _near_source(lines: list[str], zero_idx: int) -> bool:
        start = max(0, zero_idx - 3)
        end = min(len(lines), zero_idx + 2)
        return any(DOM_SOURCE_RE.search(lines[idx]) for idx in range(start, end))

    @staticmethod
    def _line_number(content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1

    @staticmethod
    def _trim(value: str, limit: int = 240) -> str:
        compact = re.sub(r"\s+", " ", str(value or "")).strip()
        return compact[:limit]

    @staticmethod
    def _absolute_url(source_url: str, endpoint: str) -> str:
        if endpoint.startswith("//"):
            parsed = urlparse(source_url)
            return f"{parsed.scheme}:{endpoint}"
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        return urljoin(source_url, endpoint)

    @staticmethod
    def _common_js_candidates(base: str) -> list[str]:
        return [
            urljoin(base.rstrip("/") + "/", path)
            for path in ("app.js", "main.js", "bundle.js", "static/js/main.js")
        ]
