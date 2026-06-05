"""
ReconX - Module: Headless-browser SPA crawler (Playwright).

Visits each live URL with a real Chromium engine, intercepts every fetch/XHR
request the application makes, and harvests SPA routes from anchor hrefs and
the History API. The output is a set of URLs that wayback/gau + traditional
crawlers can't see because they live behind JavaScript rendering.

Playwright is an optional dependency. If it's not installed (or the browser
binary is missing) the module reports `status: skipped` rather than failing
the pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule


try:  # Optional dep — installed via `pip install playwright && playwright install chromium`
    from playwright.sync_api import (
        Error as PlaywrightError,  # type: ignore
        TimeoutError as PlaywrightTimeout,  # type: ignore
        sync_playwright,  # type: ignore
    )
    _HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover — exercised in environments without Playwright
    _HAS_PLAYWRIGHT = False
    PlaywrightError = Exception  # type: ignore
    PlaywrightTimeout = Exception  # type: ignore
    sync_playwright = None  # type: ignore


# Resource types we treat as "API-ish" — these are what manual review usually wants.
_API_RESOURCE_TYPES = {"xhr", "fetch", "websocket"}

# Resource types we skip when listing static assets — but they still inform
# the "JS bundle" discovery downstream.
_SKIP_RESOURCE_TYPES = {"image", "font", "media", "stylesheet"}

# Injected before navigation: wraps history.pushState/replaceState so every
# client-side route change is appended to window.__reconx_routes for harvest.
_HISTORY_HOOK_JS = """
(() => {
  window.__reconx_routes = window.__reconx_routes || [];
  for (const fn of ['pushState', 'replaceState']) {
    const orig = history[fn];
    if (typeof orig !== 'function') continue;
    history[fn] = function (state, title, url) {
      try { if (url) window.__reconx_routes.push(String(url)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  }
})();
"""


class SPACrawlerModule(BaseModule):
    name = "spa_crawler"
    description = "Headless-browser SPA Crawling (Playwright)"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("spa_crawler", {}) or {}
        if not cfg.get("enabled", True):
            return {"endpoints": [], "routes": [], "total": 0, "status": "disabled"}

        if not _HAS_PLAYWRIGHT:
            self.warn("playwright not installed — skipping SPA crawl "
                      "(install with: pip install playwright && playwright install chromium)")
            return {
                "endpoints": [], "routes": [], "total": 0,
                "status": "skipped", "reason": "playwright_not_installed",
            }

        urls = self._extract_urls()
        if not urls:
            self.warn("No live URLs for SPA crawl")
            return {"endpoints": [], "routes": [], "total": 0}

        max_urls = int(cfg.get("max_urls", 30))
        nav_timeout = float(cfg.get("navigation_timeout", 15.0))
        idle_timeout = float(cfg.get("network_idle_timeout", 4.0))
        wait_extra = float(cfg.get("post_load_wait", 1.0))

        urls = urls[:max_urls]
        self.info(f"SPA crawl: visiting {len(urls)} URL(s)…")

        collected_endpoints: set[str] = set()
        per_host_routes: list[dict] = []

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    for url in urls:
                        try:
                            endpoints, routes = self._visit(
                                browser, url, nav_timeout, idle_timeout, wait_extra,
                            )
                        except (PlaywrightError, PlaywrightTimeout) as exc:
                            self.warn(f"  {url} → {exc.__class__.__name__}: {str(exc)[:120]}")
                            continue
                        collected_endpoints.update(endpoints)
                        if endpoints or routes:
                            per_host_routes.append({
                                "url": url,
                                "endpoints": sorted(endpoints),
                                "routes": sorted(routes),
                            })
                finally:
                    browser.close()
        except Exception as exc:  # Playwright install can fail in unexpected ways
            self.warn(f"SPA crawl aborted: {exc.__class__.__name__}: {str(exc)[:160]}")
            return {
                "endpoints": [], "routes": [], "total": 0,
                "status": "error", "reason": str(exc)[:200],
            }

        endpoints_sorted = sorted(self.filter_in_scope_urls(collected_endpoints))
        self.save_text(endpoints_sorted, "endpoints.txt")
        self.save_json(per_host_routes, "routes.json")

        self.success(f"SPA crawl: {len(endpoints_sorted)} unique endpoint(s) discovered")
        return {
            "endpoints": endpoints_sorted,
            "routes": per_host_routes,
            "total": len(endpoints_sorted),
        }

    # ── Per-page visit ────────────────────────────────────────────────────────

    def _visit(
        self,
        browser,
        url: str,
        nav_timeout: float,
        idle_timeout: float,
        wait_extra: float,
    ) -> tuple[set[str], set[str]]:
        endpoints: set[str] = set()
        routes: set[str] = set()
        target_host = (urlparse(url).hostname or "").lower()

        context = browser.new_context(ignore_https_errors=True)
        # Hook the History API so client-side route changes (pushState /
        # replaceState) are recorded even though they fire no network request —
        # this is what lets us see SPA routes a plain crawler can't. Must be
        # installed before navigation so it wraps history early.
        context.add_init_script(_HISTORY_HOOK_JS)
        page = context.new_page()

        def on_request(request) -> None:
            rtype = (request.resource_type or "").lower()
            if rtype in _SKIP_RESOURCE_TYPES:
                return
            req_url = request.url or ""
            if not req_url.startswith(("http://", "https://")):
                return
            req_host = (urlparse(req_url).hostname or "").lower()
            # Only keep same-site or in-scope requests — third-party CDN noise is filtered out
            if self._same_site(req_host, target_host):
                endpoints.add(req_url)
            elif rtype in _API_RESOURCE_TYPES:
                # API call to a different host: still worth recording (might be an SDK backend)
                endpoints.add(req_url)

        page.on("request", on_request)

        try:
            page.goto(url, timeout=int(nav_timeout * 1000), wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=int(idle_timeout * 1000))
            except PlaywrightTimeout:
                pass  # SPAs commonly never reach networkidle; that's OK
            if wait_extra > 0:
                page.wait_for_timeout(int(wait_extra * 1000))

            # Harvest anchor hrefs and form actions (form actions surface POST
            # endpoints that never appear as a navigation request).
            links = page.eval_on_selector_all(
                "a[href], form[action]",
                "els => els.map(e => e.getAttribute('href') || e.getAttribute('action'))",
            )
            # SPA routes captured by the History API hook above.
            try:
                history_routes = page.evaluate("window.__reconx_routes || []") or []
            except (PlaywrightError, PlaywrightTimeout):
                history_routes = []

            for ref in list(links or []) + list(history_routes):
                if not ref or ref.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                try:
                    abs_url = urljoin(url, ref)
                except ValueError:
                    continue
                parsed = urlparse(abs_url)
                if self._same_site((parsed.hostname or "").lower(), target_host):
                    endpoints.add(abs_url)
                    if parsed.path and parsed.path != "/":
                        routes.add(parsed.path)
        finally:
            context.close()

        return endpoints, routes

    @staticmethod
    def _same_site(req_host: str, target_host: str) -> bool:
        """True only for the exact host or a proper subdomain of it.

        A bare endswith() would match notexample.com against example.com, and
        endswith("") matches everything — both pull third-party hosts in.
        """
        if not req_host or not target_host:
            return False
        req_host = req_host.lower()
        target_host = target_host.lower()
        return req_host == target_host or req_host.endswith("." + target_host)

    # ── Input URLs ────────────────────────────────────────────────────────────

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url") if isinstance(item, dict) else str(item)
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                urls.add(url)

        # Fall back to recon's live_http list if we got nothing
        if not urls:
            for line in self.load_lines(self.session_path("recon", "subdomains", "httpx_live.txt")):
                if line.startswith(("http://", "https://")):
                    urls.add(line)
        return sorted(self.filter_in_scope_urls(urls))
