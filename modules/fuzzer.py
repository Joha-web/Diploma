"""
ReconX — Module: Crawling, Directory Fuzzing & JS Mining
Tools: katana (crawl), feroxbuster (dir brute), ffuf (fuzz), requests (JS)
"""

import re
import json
import glob
import hashlib
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import requests

from modules.base import BaseModule

# Suppress InsecureRequestWarning from verify=False calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patterns for file classifications
CLASSIFY_PATTERNS: dict[str, str] = {
    "api":            r"/(api|v[0-9]+|graphql|rest|rpc|json|xml)(/|$|\?)",
    "auth":           r"/(login|logout|signin|signout|auth|oauth|sso|saml|register|signup|password|reset|forgot|token)",
    "sensitive_files":r"\.(env|git|bak|backup|old|sql|db|sqlite|dump|log|config|cfg|conf|ini|key|pem|p12|pfx|zip|tar|gz)(\?|$)",
    "admin_panels":   r"/(admin|administrator|dashboard|console|panel|manage|management|debug|test|dev|staging|internal|actuator|monitor|metrics)",
    "with_params":    r"\?.*=",
    # Folders/directories that often contain leftover artifacts, credentials,
    # or unintended exposure. Matches a path segment, not a substring.
    "interesting_directories": (
        r"/(backup|backups|bak|old|legacy|archive|archives|trash|deleted|"
        r"dev|devel|test|tests|staging|stage|internal|private|hidden|"
        r"tmp|temp|cache|caches|uploads?|files?|storage|store|"
        r"data|database|db|logs?|server-status|server-info|"
        r"\.well-known|\.git|\.svn|\.hg|\.env|\.aws|\.ssh|\.docker|"
        r"config|configs|configuration|conf|etc|secrets?)(/|\?|$)"
    ),
    # Concrete API-like resource paths (e.g. /api/users, /v1/orders/123).
    # Distinguished from the broader "api" bucket by requiring a resource segment.
    "interesting_endpoints": (
        r"/(api|rest|rpc|graphql|v[0-9]+(?:\.[0-9]+)?)/[a-zA-Z][a-zA-Z0-9_.-]*"
    ),
}

# Static asset extensions — never classify these as admin panels
STATIC_ASSET_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp",
    ".mp4", ".mp3", ".webm", ".ogg", ".pdf", ".avif",
}

# Admin panel indicators in HTML response body
ADMIN_PANEL_INDICATORS = [
    b"<form", b"login", b"password", b"dashboard", b"sign in",
    b"username", b"authentication", b"admin panel", b"console",
    b"manage", b"log in", b"\xd0\xb2\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8",  # войти (Russian)
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/query",
    "/graphiql", "/playground", "/api",
]

GRAPHQL_TYPENAME_QUERY = "{ __typename }"
GRAPHQL_INTROSPECTION_QUERY = """
query ReconXIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
"""

CLOUD_PATTERNS: dict[str, re.Pattern] = {
    "aws_s3_virtual": re.compile(
        r"https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[^\s'\"<>)]*)?",
        re.I,
    ),
    "aws_s3_path": re.compile(
        r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:/[^\s'\"<>)]*)?",
        re.I,
    ),
    "gcp_storage_virtual": re.compile(
        r"https?://([a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9])\.storage\.googleapis\.com(?:/[^\s'\"<>)]*)?",
        re.I,
    ),
    "gcp_storage_path": re.compile(
        r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9])(?:/[^\s'\"<>)]*)?",
        re.I,
    ),
    "azure_blob": re.compile(
        r"https?://([a-z0-9][a-z0-9-]{1,61})\.blob\.core\.windows\.net/([a-z0-9][a-z0-9-]{1,62})(?:/[^\s'\"<>)]*)?",
        re.I,
    ),
}

# JS secret patterns
SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(
        r'(api[_\-]?key|secret[_\-]?key|access[_\-]?key|private[_\-]?key|'
        r'auth[_\-]?token|bearer|password|passwd|api[_\-]?secret|'
        r'client[_\-]?secret)\s*[:=]\s*["\'][^\s"\']{8,}["\']',
        re.IGNORECASE,
    ),
    re.compile(
        r'(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|'
        r'SLACK_TOKEN|STRIPE_SECRET|TWILIO_AUTH)',
        re.IGNORECASE,
    ),
]


class FuzzerModule(BaseModule):
    name = "fuzzer"
    description = "Crawling, Directory Fuzzing & JS Mining"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        self.graphql_details: list[dict] = []
        self.cloud_assets: list[dict] = []
        for sub in ("crawl", "ferox", "ffuf", "js_mining", "graphql", "merged", "cloud", "well_known"):
            (self.module_dir / sub).mkdir(exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        urls = self._extract_urls()
        if not urls:
            self.warn("No URLs for fuzzing")
            return {"total_endpoints": 0, "classified": {}, "js_secrets_count": 0}

        self.save_text(urls, "clean_hosts.txt")
        all_endpoints: set[str] = set()

        # 1. Crawling
        crawled = self._crawl(urls)
        all_endpoints.update(crawled)

        # 2. Directory bruteforce
        ferox = self._feroxbuster(urls)
        all_endpoints.update(ferox)

        # 3. ffuf dir + backup fuzzing
        ffuf_results = self._ffuf(urls)
        all_endpoints.update(ffuf_results)

        # 4. JS mining
        js_eps, js_secrets, js_urls, cloud_from_js = self._js_mining(crawled)
        all_endpoints.update(js_eps)

        # 5. robots.txt and sitemap.xml endpoint discovery
        well_known: list[str] = []
        if self.config.get("scan", {}).get("fuzzing", {}).get("robots_sitemap", True):
            well_known = self._robots_sitemap(urls)
            all_endpoints.update(well_known)

        # 6. GraphQL endpoint detection and schema mapping
        graphql = []
        if self.config.get("scan", {}).get("fuzzing", {}).get("graphql_probe", True):
            graphql = self._detect_graphql(urls)
            all_endpoints.update(graphql)

        # 7. Cloud storage assets discovered from crawled URLs and JS bundles
        cloud_assets: list[dict] = []
        if self.config.get("scan", {}).get("fuzzing", {}).get("cloud_assets", True):
            cloud_assets = self._analyze_cloud_assets(list(crawled) + list(all_endpoints), cloud_from_js)

        findings = self._build_findings(cloud_assets, self.graphql_details)
        if findings:
            self.save_json(findings, "fuzzer_findings.json")

        # 8. Classify & save
        merged = sorted(all_endpoints)
        self.save_text(merged, "merged/all_endpoints.txt")
        classified = self._classify(merged)
        classified["js_secrets"] = js_secrets
        classified["graphql"] = graphql
        classified["well_known"] = well_known
        classified["cloud_assets"] = cloud_assets

        self.success(f"Total unique endpoints: {len(merged)}")
        return {
            "total_endpoints":  len(merged),
            "all_endpoints":    merged,
            "js_urls":          js_urls,
            "classified":       classified,
            "js_secrets_count": len(js_secrets),
            "graphql_endpoints": graphql,
            "graphql_details":   self.graphql_details,
            "cloud_assets":      cloud_assets,
            "well_known_urls":   well_known,
            "findings":          findings,
            "total_findings":    len(findings),
        }

    def summary(self) -> str:
        total   = self.results.get("total_endpoints", 0)
        secrets = self.results.get("js_secrets_count", 0)
        return f"🔎 {total} endpoints | 🔑 {secrets} JS secrets"

    # ── Crawling ──────────────────────────────────────────────────────────────

    def _crawl(self, urls: list[str]) -> set[str]:
        if not self.has_tool("katana"):
            return set()
        self.info("Crawling (katana)")
        cfg  = self.config.get("scan", {}).get("fuzzing", {})
        depth = str(cfg.get("depth", 3))
        found: set[str] = set()

        for host in urls:
            self.info(f"  katana → {host}")
            safe = re.sub(r"https?://|[/:]", "_", host)
            out  = self.module_dir / "crawl" / f"{safe}.txt"
            if not self._reuse_output(out):
                self.exec(
                    ["katana", "-u", host, "-d", depth, "-jc", "-kf", "all",
                     "-c", "10", "-p", "10", "-silent", "-o", str(out)],
                    timeout=300,
                    label=f"katana {host}",
                )
            found.update(self.filter_in_scope_urls(self.load_lines(out)))

        self.success(f"katana → {len(found)} URLs")
        return found

    # ── Feroxbuster ───────────────────────────────────────────────────────────

    def _feroxbuster(self, urls: list[str]) -> set[str]:
        if not self.has_tool("feroxbuster"):
            return set()
        wl = self._wordlist("dirs")
        if not wl:
            self.warn("No wordlist found for feroxbuster")
            return set()

        self.info("Directory bruteforce (feroxbuster)")
        found: set[str] = set()
        rate = str(self.config.get("scan", {}).get("fuzzing", {}).get("rate", 100))

        for host in urls:
            self.info(f"  feroxbuster → {host}")
            safe = re.sub(r"https?://|[/:]", "_", host)
            out  = self.module_dir / "ferox" / f"{safe}.txt"
            if not self._reuse_output(out):
                self.exec(
                    ["feroxbuster", "--url", host, "--wordlist", wl,
                     "--depth", "2", "--threads", "30", "--timeout", "10",
                     "--rate-limit", rate, "--auto-tune", "--redirects",
                     "--filter-status", "404,400,503",
                     "--output", str(out), "--no-state", "--quiet"],
                    timeout=600,
                    label=f"feroxbuster {host}",
                )
            for line in self.load_lines(out):
                found.update(self.filter_in_scope_urls(self.extract_urls(line)))

        self.success(f"feroxbuster → {len(found)} URLs")
        return found

    # ── ffuf ──────────────────────────────────────────────────────────────────

    def _ffuf(self, urls: list[str]) -> set[str]:
        if not self.has_tool("ffuf"):
            return set()
        wl = self._wordlist("dirs")
        if not wl:
            return set()

        self.info("Fuzzing (ffuf)")
        found: set[str] = set()
        rate = str(self.config.get("scan", {}).get("fuzzing", {}).get("rate", 100))

        for host in urls:
            self.info(f"  ffuf dirs → {host}")
            safe = re.sub(r"https?://|[/:]", "_", host)

            # Dir fuzzing
            out = self.module_dir / "ffuf" / f"dirs_{safe}.json"
            if not self._reuse_output(out):
                self.exec(
                    ["ffuf", "-u", f"{host}/FUZZ", "-w", wl,
                     "-mc", "200,201,204,301,302,307,401,403,405",
                     "-t", "40", "-timeout", "10", "-rate", rate,
                     "-recursion", "-recursion-depth", "2",
                     "-of", "json", "-o", str(out), "-s"],
                    timeout=600,
                    label=f"ffuf dirs {host}",
                )
            data = self.load_json(out)
            for r in data.get("results", []):
                if r.get("url") and self.is_in_scope(r["url"]):
                    found.add(r["url"])

            # Backup / sensitive file fuzzing
            self.info(f"  ffuf backups → {host}")
            out_bak = self.module_dir / "ffuf" / f"backup_{safe}.json"
            if not self._reuse_output(out_bak):
                self.exec(
                    ["ffuf", "-u", f"{host}/FUZZ", "-w", self._backup_wordlist(),
                     "-mc", "200,201,301,302",
                     "-t", "20", "-timeout", "10", "-rate", str(max(1, int(rate) // 2)),
                     "-of", "json", "-o", str(out_bak), "-s"],
                    timeout=300,
                    label=f"ffuf backups {host}",
                )
            bak_data = self.load_json(out_bak)
            for r in bak_data.get("results", []):
                if r.get("url") and self.is_in_scope(r["url"]):
                    found.add(r["url"])
                    self.warn(f"  ⚠ Sensitive file found: {r['url']}")

        self.success(f"ffuf → {len(found)} URLs")
        return found

    # ── JS Mining ─────────────────────────────────────────────────────────────

    def _js_mining(self, crawled: set[str]) -> tuple[set[str], list[dict], list[str], list[dict]]:
        self.info("JS Mining — endpoints & secrets")
        js_urls = sorted({
            u for u in crawled
            if re.search(r"\.js(\?.*)?$", u, re.IGNORECASE)
        })

        endpoints: set[str] = set()
        secrets:   list[dict] = []
        cloud_assets: list[dict] = []

        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/1.0"

        rate_delay = 1.0 / max(1, self.config.get("scan", {}).get("rate_limit", 30))

        for jsurl in js_urls[:150]:   # cap at 150 JS files
            try:
                resp = self.http_get(jsurl, session=sess, timeout=15)
                if resp is None:
                    continue
                if resp.status_code != 200:
                    continue
                content = resp.text

                # Extract URL paths
                for m in re.findall(r"""["'`](/[a-zA-Z0-9_/.\-]{2,100})["'`]""", content):
                    endpoints.add(m)
                endpoints.update(self._extract_js_routes(content))
                cloud_assets.extend(self._extract_cloud_assets(content, source=jsurl))

                # Extract secrets
                retain_raw = self.config.get("scan", {}).get("fuzzing", {}).get("retain_raw_secrets", False)
                for pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(content):
                        raw_match = m.group(0)
                        raw_context = content[max(0, m.start()-30):m.end()+30]
                        match_text = raw_match if retain_raw else self._redact_js_secret_match(raw_match)
                        context_text = raw_context if retain_raw else raw_context.replace(raw_match, match_text)
                        secrets.append({
                            "file":    jsurl,
                            "type":    m.group(1) if m.lastindex else "secret",
                            "match":   match_text[:200],
                            "context": context_text,
                            "fingerprint": self._fingerprint_secret(raw_match),
                        })

                time.sleep(rate_delay)
            except Exception:
                continue

        self.save_json(secrets, "js_mining/js_secrets.json")
        self.save_json(sorted(endpoints), "js_mining/js_endpoints.json")
        self.save_json(cloud_assets, "js_mining/cloud_assets.json")
        self.success(f"JS Mining → {len(endpoints)} endpoints, {len(secrets)} secrets")
        return endpoints, secrets, js_urls, cloud_assets

    # ── robots.txt / sitemap.xml ─────────────────────────────────────────────

    def _robots_sitemap(self, urls: list[str]) -> list[str]:
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        found: set[str] = set()
        sitemaps: set[str] = set()

        for base in urls[:80]:
            robots_url = urljoin(base.rstrip("/") + "/", "robots.txt")
            resp = self.http_get(robots_url, session=sess, timeout=8, verify=False)
            if resp is not None and resp.status_code == 200:
                body = resp.text or ""
                self.save_text(body, f"well_known/robots_{self._safe_name(base)}.txt")
                for line in body.splitlines():
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip()
                    if not value:
                        continue
                    if key in {"allow", "disallow"} and value != "/":
                        candidate = urljoin(base.rstrip("/") + "/", value.lstrip("/"))
                        if self.is_in_scope(candidate):
                            found.add(candidate)
                    elif key == "sitemap":
                        sitemaps.add(value)

            sitemaps.add(urljoin(base.rstrip("/") + "/", "sitemap.xml"))

        for sitemap_url in sorted(sitemaps)[:120]:
            found.update(self._parse_sitemap(sitemap_url, sess, depth=0))

        result = self.filter_in_scope_urls(found)
        if result:
            self.save_text(result, "well_known/robots_sitemap_urls.txt")
            self.success(f"robots/sitemap → {len(result)} URLs")
        return result

    def _parse_sitemap(self, sitemap_url: str, sess: requests.Session, depth: int = 0) -> set[str]:
        if depth > 2 or not self.is_in_scope(sitemap_url):
            return set()
        resp = self.http_get(sitemap_url, session=sess, timeout=12, verify=False)
        if resp is None or resp.status_code != 200 or not resp.text:
            return set()

        found: set[str] = set()
        try:
            root = ElementTree.fromstring(resp.content)
            locs = [
                (node.text or "").strip()
                for node in root.iter()
                if node.tag.lower().endswith("loc") and (node.text or "").strip()
            ]
        except ElementTree.ParseError:
            locs = self.extract_urls(resp.text)

        for loc in locs[:1000]:
            if not loc.startswith(("http://", "https://")):
                loc = urljoin(sitemap_url, loc)
            if not self.is_in_scope(loc):
                continue
            if loc.lower().endswith(".xml") and "sitemap" in loc.lower():
                found.update(self._parse_sitemap(loc, sess, depth + 1))
            else:
                found.add(loc)
        return found

    # ── GraphQL detection ───────────────────────────────────────────────────

    def _detect_graphql(self, urls: list[str]) -> list[str]:
        found: set[str] = set()
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        details: list[dict] = []

        for base in urls[:80]:
            for path in GRAPHQL_PATHS:
                endpoint = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                if not self.is_in_scope(endpoint):
                    continue
                try:
                    resp = self._graphql_probe(endpoint, sess)
                    if resp is None:
                        continue
                    text = (resp.text or "")[:2000].lower()
                    content_type = resp.headers.get("content-type", "").lower()
                    if resp.status_code == 200 and (
                        "application/json" in content_type
                        or '"data"' in text
                        or '"errors"' in text
                        or "graphql" in text
                    ):
                        found.add(endpoint)
                        self.warn(f"  GraphQL endpoint candidate: {endpoint}")
                        details.append(self._graphql_details(endpoint, sess, resp))
                except Exception:
                    continue

        result = sorted(found)
        if result:
            self.save_text(result, "graphql/endpoints.txt")
            self.graphql_details = self._dedupe_graphql_details(details)
            self.save_json(self.graphql_details, "graphql/details.json")
        return result

    def _graphql_probe(self, endpoint: str, sess: requests.Session) -> requests.Response | None:
        resp = self.http_get(
            endpoint,
            session=sess,
            params={"query": GRAPHQL_TYPENAME_QUERY},
            timeout=8,
            verify=False,
        )
        if resp is not None and resp.status_code == 200:
            return resp
        return self.http_post(
            endpoint,
            session=sess,
            safe_readonly=True,
            json={"query": GRAPHQL_TYPENAME_QUERY},
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 ReconX/2.0"},
            timeout=8,
            verify=False,
        )

    def _graphql_details(
        self,
        endpoint: str,
        sess: requests.Session,
        probe_resp: requests.Response,
    ) -> dict:
        detail = {
            "endpoint": endpoint,
            "status": probe_resp.status_code,
            "content_type": probe_resp.headers.get("content-type", ""),
            "introspection_enabled": False,
            "query_type": "",
            "mutation_type": "",
            "mutation_fields": [],
            "schema_file": "",
            "findings": [],
        }
        cfg = self.config.get("scan", {}).get("fuzzing", {})
        if not cfg.get("graphql_introspection", True):
            return detail

        resp = self.http_post(
            endpoint,
            session=sess,
            safe_readonly=True,
            json={"query": GRAPHQL_INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 ReconX/2.0"},
            timeout=12,
            verify=False,
        )
        if resp is None or resp.status_code != 200:
            return detail

        try:
            data = resp.json()
        except ValueError:
            return detail
        schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
        if not isinstance(schema, dict):
            return detail

        detail["introspection_enabled"] = True
        query_type = schema.get("queryType") or {}
        mutation_type = schema.get("mutationType") or {}
        detail["query_type"] = query_type.get("name", "") if isinstance(query_type, dict) else ""
        detail["mutation_type"] = mutation_type.get("name", "") if isinstance(mutation_type, dict) else ""
        detail["mutation_fields"] = self._graphql_mutation_fields(schema, detail["mutation_type"])

        schema_path = self.save_json(data, f"graphql/schema_{self._safe_name(endpoint)}.json")
        detail["schema_file"] = str(schema_path.relative_to(self.output_dir))
        detail["findings"].append({
            "type": "graphql_introspection_enabled",
            "severity": "MEDIUM",
            "description": "GraphQL schema is available without authentication context.",
        })
        if detail["mutation_fields"]:
            detail["findings"].append({
                "type": "graphql_mutations_exposed",
                "severity": "HIGH",
                "description": "Unauthenticated introspection exposed mutation field names.",
                "fields": detail["mutation_fields"][:50],
            })
        return detail

    @staticmethod
    def _graphql_mutation_fields(schema: dict, mutation_type: str) -> list[str]:
        if not mutation_type:
            return []
        for typ in schema.get("types", []) or []:
            if not isinstance(typ, dict) or typ.get("name") != mutation_type:
                continue
            fields = typ.get("fields", []) or []
            names: set[str] = set()
            for field in fields:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name", "")).strip()
                if name and not name.startswith("__"):
                    names.add(name)
            return sorted(names)
        return []

    @staticmethod
    def _dedupe_graphql_details(details: list[dict]) -> list[dict]:
        seen: set[str] = set()
        result: list[dict] = []
        for item in details:
            endpoint = item.get("endpoint", "")
            if endpoint and endpoint not in seen:
                seen.add(endpoint)
                result.append(item)
        return result

    # ── Classification ────────────────────────────────────────────────────────

    def _classify(self, urls: list[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for cat, pattern in CLASSIFY_PATTERNS.items():
            matches = sorted({u for u in urls if re.search(pattern, u, re.IGNORECASE)})
            result[cat] = matches

        # Verify admin panels — filter out static assets and check via HTTP
        raw_admin = result.get("admin_panels", [])
        if raw_admin:
            self.info(f"Verifying {len(raw_admin)} admin panel candidates...")
            result["admin_panels"] = self._verify_admin_panels(raw_admin)
            result["admin_panels_unverified"] = len(raw_admin)

        # Verify sensitive files — check that they actually exist (return 200)
        raw_sensitive = result.get("sensitive_files", [])
        if raw_sensitive:
            self.info(f"Verifying {len(raw_sensitive)} sensitive file candidates...")
            result["sensitive_files"] = self._verify_sensitive_files(raw_sensitive)
            result["sensitive_files_unverified"] = len(raw_sensitive)

        for cat in CLASSIFY_PATTERNS:
            items = result.get(cat, [])
            if items:
                self.save_text(items, f"merged/{cat}.txt")
                self.success(f"  {cat}: {len(items)}")
        return result

    def _verify_admin_panels(self, urls: list[str]) -> list[str]:
        """Filter admin panel URLs to only those that are actual admin pages.

        Removes:
        - Static assets (CSS, JS, images, fonts)
        - URLs that are just subdomains with 'admin' in hostname pointing to normal pages
        - URLs that don't respond with HTML containing login/dashboard indicators
        """
        # Step 1: Filter out obvious static assets
        candidates: list[str] = []
        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            # Skip static assets
            if any(path_lower.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
                continue
            # Skip paths that are clearly asset directories
            if re.search(r'/(assets|static|dist|build|node_modules|vendor|fonts|img|images|media|css|js)/', path_lower):
                continue
            # Skip URLs with typical asset patterns in the path
            if re.search(r'/[a-f0-9]{6,}\.(js|css|chunk|bundle)', path_lower):
                continue
            candidates.append(url)

        if not candidates:
            return []

        # Step 2: Deduplicate by origin — only probe unique root paths
        seen_origins: set[str] = set()
        unique_candidates: list[str] = []
        for url in candidates:
            parsed = urlparse(url)
            # Normalize to origin + first path segment
            segments = [s for s in parsed.path.strip('/').split('/') if s]
            key_path = '/' + segments[0] if segments else '/'
            origin_key = f"{parsed.scheme}://{parsed.netloc}{key_path}"
            if origin_key not in seen_origins:
                seen_origins.add(origin_key)
                unique_candidates.append(url)

        # Step 3: HTTP verification — probe top candidates
        verified: list[str] = []
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        probe_limit = min(len(unique_candidates), 50)  # cap probing

        for url in unique_candidates[:probe_limit]:
            try:
                resp = self.http_get(url, session=sess, timeout=8, verify=False)
                if resp is None:
                    continue
                if resp.status_code not in (200, 301, 302, 307, 308, 401, 403):
                    continue
                # 401/403 on admin path is likely a real admin panel
                if resp.status_code in (401, 403):
                    verified.append(url)
                    continue
                # Check content type — must be HTML
                ct = resp.headers.get("content-type", "").lower()
                if "text/html" not in ct and "application/xhtml" not in ct:
                    continue
                # Check body for admin panel indicators
                body_lower = (resp.content or b"")[:5000].lower()
                if any(indicator in body_lower for indicator in ADMIN_PANEL_INDICATORS):
                    verified.append(url)
            except Exception:
                continue

        if verified:
            self.warn(f"  Verified admin panels: {len(verified)} / {len(urls)} candidates")
        else:
            self.info(f"  No verified admin panels (all {len(urls)} were false positives)")
        return sorted(set(verified))

    def _verify_sensitive_files(self, urls: list[str]) -> list[str]:
        """Verify sensitive files by checking HTTP response status.

        Only includes files that actually return 200 with non-trivial content.
        """
        # Deduplicate by actual URL (not regex pattern artifacts)
        unique_urls: list[str] = []
        seen: set[str] = set()
        for url in urls:
            if url.startswith("http") and url not in seen:
                seen.add(url)
                unique_urls.append(url)

        if not unique_urls:
            return []

        verified: list[str] = []
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"
        probe_limit = min(len(unique_urls), 80)

        for url in unique_urls[:probe_limit]:
            try:
                resp = self.http_get(url, session=sess, timeout=6, verify=False)
                if resp is None:
                    continue
                if resp.status_code != 200:
                    continue
                # Must have some content (not empty or tiny error page)
                body = resp.content or b""
                if len(body) < 10:
                    continue
                # Check it's not a generic 404/error page returned as 200
                body_lower = body[:2000].lower()
                if any(marker in body_lower for marker in (
                    b"page not found", b"404", b"not found",
                    b"does not exist", b"no such file",
                )):
                    continue
                verified.append(url)
                self.warn(f"  ⚠ Verified sensitive file: {url}")
            except Exception:
                continue

        if verified:
            self.warn(f"  Verified sensitive files: {len(verified)} / {len(urls)} candidates")
        else:
            self.info(f"  No verified sensitive files (all {len(urls)} were false positives)")
        return sorted(set(verified))

    # ── Cloud asset analysis ─────────────────────────────────────────────────

    def _analyze_cloud_assets(self, text_items: list[str], seeded_assets: list[dict]) -> list[dict]:
        assets: list[dict] = list(seeded_assets)
        for item in text_items:
            assets.extend(self._extract_cloud_assets(str(item), source="endpoint"))

        deduped = self._dedupe_cloud_assets(assets)
        if deduped:
            cfg = self.config.get("scan", {}).get("fuzzing", {})
            try:
                configured_workers = int(cfg.get("cloud_listing_threads", 10))
            except (TypeError, ValueError):
                configured_workers = 10
            workers = min(max(1, configured_workers), len(deduped))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._check_cloud_listing, asset): asset
                    for asset in deduped
                }
                for future in as_completed(futures):
                    asset = futures[future]
                    try:
                        asset["listing"] = future.result()
                    except Exception as exc:
                        asset["listing"] = {
                            "checked": True,
                            "public": False,
                            "error": str(exc),
                        }

        for asset in deduped:
            if asset["listing"].get("public"):
                asset["severity"] = "CRITICAL"
                self.warn(f"  Public cloud listing: {asset['provider']} {asset['bucket']}")
            else:
                asset["severity"] = "INFO"

        self.save_json(deduped, "cloud/cloud_assets.json")
        public = [a for a in deduped if a.get("listing", {}).get("public")]
        if public:
            self.save_json(public, "cloud/public_listings.json")
        return deduped

    def _extract_cloud_assets(self, text: str, source: str = "") -> list[dict]:
        assets: list[dict] = []
        for kind, pattern in CLOUD_PATTERNS.items():
            for match in pattern.finditer(text or ""):
                full_url = match.group(0).rstrip(".,;")
                if kind.startswith("aws_s3"):
                    provider = "aws_s3"
                    bucket = match.group(1)
                    container = ""
                elif kind.startswith("gcp_storage"):
                    provider = "gcp_storage"
                    bucket = match.group(1)
                    container = ""
                else:
                    provider = "azure_blob"
                    bucket = match.group(1)
                    container = match.group(2)
                assets.append({
                    "provider": provider,
                    "kind": kind,
                    "bucket": bucket,
                    "container": container,
                    "url": full_url,
                    "source": source,
                })
        return assets

    @staticmethod
    def _dedupe_cloud_assets(assets: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for asset in assets:
            key = (
                str(asset.get("provider", "")),
                str(asset.get("bucket", "")),
                str(asset.get("container", "")),
            )
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            result.append(asset)
        return result

    def _check_cloud_listing(self, asset: dict) -> dict:
        provider = asset.get("provider", "")
        bucket = asset.get("bucket", "")
        container = asset.get("container", "")
        if provider == "aws_s3":
            url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=5"
        elif provider == "gcp_storage":
            url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=5"
        elif provider == "azure_blob" and container:
            url = f"https://{bucket}.blob.core.windows.net/{container}?restype=container&comp=list"
        else:
            return {"checked": False, "public": False, "reason": "unsupported_provider"}

        resp = self.http_get(url, enforce_scope=False, timeout=10, verify=False)
        if resp is None:
            return {"checked": True, "public": False, "url": url, "error": "request_failed"}
        body = (resp.text or "")[:2000]
        public = resp.status_code == 200 and any(
            marker in body for marker in (
                "<ListBucketResult", "<EnumerationResults", '"items"', '"kind": "storage#objects"',
            )
        )
        return {
            "checked": True,
            "public": public,
            "url": url,
            "status": resp.status_code,
            "evidence": body[:300] if public else "",
        }

    def _build_findings(self, cloud_assets: list[dict], graphql_details: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for asset in cloud_assets:
            if not asset.get("listing", {}).get("public"):
                continue
            findings.append({
                "source": self.name,
                "id": "public_cloud_storage_listing",
                "type": "public_cloud_storage_listing",
                "name": "Public cloud storage listing exposed",
                "title": "Public cloud storage listing exposed",
                "severity": "CRITICAL",
                "url": asset.get("url", ""),
                "matched_url": asset.get("listing", {}).get("url", asset.get("url", "")),
                "description": (
                    "Cloud storage bucket or container allows anonymous object listing."
                ),
                "evidence": {
                    "provider": asset.get("provider", ""),
                    "bucket": asset.get("bucket", ""),
                    "container": asset.get("container", ""),
                    "listing": asset.get("listing", {}),
                    "source": asset.get("source", ""),
                },
                "confidence": 0.95,
            })

        for detail in graphql_details:
            for finding in detail.get("findings", []) or []:
                findings.append({
                    "source": self.name,
                    "id": finding.get("type", ""),
                    "type": finding.get("type", ""),
                    "name": finding.get("description", "GraphQL finding"),
                    "title": finding.get("description", "GraphQL finding"),
                    "severity": finding.get("severity", "MEDIUM"),
                    "url": detail.get("endpoint", ""),
                    "matched_url": detail.get("endpoint", ""),
                    "description": finding.get("description", ""),
                    "evidence": {
                        "endpoint": detail.get("endpoint", ""),
                        "query_type": detail.get("query_type", ""),
                        "mutation_type": detail.get("mutation_type", ""),
                        "mutation_fields": detail.get("mutation_fields", [])[:50],
                        "schema_file": detail.get("schema_file", ""),
                    },
                    "confidence": 0.9,
                })
        return findings

    # ── JS framework route extraction ────────────────────────────────────────

    def _extract_js_routes(self, content: str) -> set[str]:
        routes: set[str] = set()
        route_patterns = [
            r"""(?:path|route|pathname|href)\s*:\s*["'`](/[A-Za-z0-9_./:$*?\-\[\]]{1,160})["'`]""",
            r"""(?:component|page)\s*:\s*["'`](/[A-Za-z0-9_./:$*?\-\[\]]{1,160})["'`]""",
            r"""sortedPages\s*:\s*\[([^\]]{1,6000})\]""",
            r"""__BUILD_MANIFEST[^=]*=\s*({.*?});""",
        ]
        for pattern in route_patterns[:2]:
            for match in re.findall(pattern, content, re.I):
                route = self._normalise_route(match)
                if route:
                    routes.add(route)

        for block in re.findall(route_patterns[2], content, re.I | re.S):
            for route in re.findall(r"""["'`](/[A-Za-z0-9_./:$*?\-\[\]]{0,160})["'`]""", block):
                route = self._normalise_route(route)
                if route:
                    routes.add(route)

        # React Router JSX and object route configs:
        # <Route path="/admin" ...>, createBrowserRouter([{ path: "/users/:id" }])
        for route in re.findall(r"""<Route\b[^>]*\bpath\s*=\s*["'`]([^"'`]+)["'`]""", content, re.I):
            route = self._normalise_route(route)
            if route:
                routes.add(route)

        # Next.js build manifests:
        # self.__BUILD_MANIFEST["/dashboard"] = [...]
        # __SSG_MANIFEST = new Set(["/","/blog/[slug]"])
        next_blocks = re.findall(
            r"""(?:__BUILD_MANIFEST|__SSG_MANIFEST|_buildManifest)[^;]{1,12000}""",
            content,
            re.I | re.S,
        )
        for block in next_blocks:
            for route in re.findall(r"""["'`](/[A-Za-z0-9_./:$*?\-\[\]]{0,160})["'`]""", block):
                route = self._normalise_route(route)
                if route:
                    routes.add(route)

        # Vue-router commonly serializes path keys in route arrays.
        for block in re.findall(r"""(?:routes|children)\s*:\s*\[([^\]]{1,12000})\]""", content, re.I | re.S):
            for route in re.findall(r"""\bpath\s*:\s*["'`]([^"'`]+)["'`]""", block, re.I):
                route = self._normalise_route(route)
                if route:
                    routes.add(route)

        for chunk_route in re.findall(r"""static/chunks/pages/([^"'`]+?)\-[a-f0-9]{4,}\.js""", content, re.I):
            route = "/" + chunk_route.replace("/index", "").replace("[", ":").replace("]", "")
            route = self._normalise_route(route)
            if route:
                routes.add(route)
        return routes

    @staticmethod
    def _normalise_route(route: str) -> str:
        route = str(route or "").strip()
        if not route.startswith("/"):
            return ""
        if route.startswith("//") or route in {"/", "/*"}:
            return ""
        route = route.replace("\\/", "/")
        route = re.sub(r"/+", "/", route)
        return route[:180]

    # ── Wordlist helpers ──────────────────────────────────────────────────────

    def _wordlist(self, kind: str) -> str:
        """Find a wordlist by type (dirs/files/params) from configured search paths."""
        wl_cfg   = self.config.get("wordlists", {})
        filename = wl_cfg.get(kind, {
            "dirs":   "directory-list-2.3-medium.txt",
            "files":  "raft-medium-files.txt",
            "params": "burp-parameter-names.txt",
        }.get(kind, "directory-list-2.3-medium.txt"))

        for search_dir in wl_cfg.get("search_paths", [
            "/opt/SecLists", "/usr/share/seclists", "/usr/share/wordlists",
        ]):
            matches = glob.glob(f"{search_dir}/**/{filename}", recursive=True)
            if matches:
                return matches[0]

        # Fallback to dirb common
        fallback = "/usr/share/dirb/wordlists/common.txt"
        if Path(fallback).exists():
            return fallback
        return ""

    def _reuse_output(self, path: Path) -> bool:
        cfg = self.config.get("scan", {}).get("fuzzing", {})
        if not cfg.get("reuse_host_outputs", True):
            return False
        if path.exists() and path.stat().st_size > 0:
            self.info(f"  resume checkpoint → {path.name}")
            return True
        return False

    @staticmethod
    def _safe_name(value: str) -> str:
        parsed = urlparse(str(value))
        base = parsed.netloc + parsed.path if parsed.netloc else str(value)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_")
        return safe[:140] or "target"

    @staticmethod
    def _redact_js_secret_match(value: str) -> str:
        text = str(value or "")
        return re.sub(
            r"""([:=]\s*["'])([^"']{4,})(["'])""",
            lambda m: f"{m.group(1)}{FuzzerModule._redact_secret_value(m.group(2))}{m.group(3)}",
            text,
            count=1,
        )

    @staticmethod
    def _redact_secret_value(value: str) -> str:
        if len(value) <= 10:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    @staticmethod
    def _fingerprint_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _backup_wordlist(self) -> str:
        """Return path to a temporary backup/config extensions wordlist."""
        wl_path = self.module_dir / "backup_extensions.txt"
        if not wl_path.exists():
            extensions = [
                ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".swp", "~",
                ".zip", ".tar.gz", ".tar", ".gz", ".sql", ".sql.gz", ".db",
                ".env", ".env.bak", ".env.local", ".env.prod", ".env.production",
                ".git", ".gitignore", ".htaccess", ".htpasswd", ".DS_Store",
                "config.php.bak", "config.php~", "wp-config.php.bak",
                "settings.py.bak", "database.yml.bak", ".well-known/security.txt",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
            ]
            wl_path.write_text("\n".join(extensions), encoding="utf-8")
        return str(wl_path)

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            line = item.get("url", "") if isinstance(item, dict) else str(item)
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        return self.filter_in_scope_urls(urls)
