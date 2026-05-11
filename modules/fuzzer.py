"""
ReconX — Module: Crawling, Directory Fuzzing & JS Mining
Tools: katana (crawl), feroxbuster (dir brute), ffuf (fuzz), requests (JS)
"""

import re
import json
import glob
import time
import urllib3
from pathlib import Path
from urllib.parse import urljoin

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
}

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/query",
    "/graphiql", "/playground", "/api",
]

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
    required_tools = ["katana", "feroxbuster", "ffuf"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []
        for sub in ("crawl", "ferox", "ffuf", "js_mining", "graphql", "merged"):
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
        js_eps, js_secrets = self._js_mining(crawled)
        all_endpoints.update(js_eps)

        # 5. Lightweight GraphQL endpoint detection
        graphql = []
        if self.config.get("scan", {}).get("fuzzing", {}).get("graphql_probe", True):
            graphql = self._detect_graphql(urls)
            all_endpoints.update(graphql)

        # 6. Classify & save
        merged = sorted(all_endpoints)
        self.save_text(merged, "merged/all_endpoints.txt")
        classified = self._classify(merged)
        classified["js_secrets"] = js_secrets
        classified["graphql"] = graphql

        self.success(f"Total unique endpoints: {len(merged)}")
        return {
            "total_endpoints":  len(merged),
            "classified":       classified,
            "js_secrets_count": len(js_secrets),
            "graphql_endpoints": graphql,
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
            safe = re.sub(r"https?://|[/:]", "_", host)
            out  = self.module_dir / "crawl" / f"{safe}.txt"
            self.exec(
                ["katana", "-u", host, "-d", depth, "-jc", "-kf", "all",
                 "-c", "10", "-p", "10", "-silent", "-o", str(out)],
                timeout=300,
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
            safe = re.sub(r"https?://|[/:]", "_", host)
            out  = self.module_dir / "ferox" / f"{safe}.txt"
            self.exec(
                ["feroxbuster", "--url", host, "--wordlist", wl,
                 "--depth", "2", "--threads", "30", "--timeout", "10",
                 "--rate-limit", rate, "--auto-tune", "--redirects",
                 "--filter-status", "404,400,503",
                 "--output", str(out), "--no-state", "--quiet"],
                timeout=600,
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
            safe = re.sub(r"https?://|[/:]", "_", host)

            # Dir fuzzing
            out = self.module_dir / "ffuf" / f"dirs_{safe}.json"
            self.exec(
                ["ffuf", "-u", f"{host}/FUZZ", "-w", wl,
                 "-mc", "200,201,204,301,302,307,401,403,405",
                 "-t", "40", "-timeout", "10", "-rate", rate,
                 "-recursion", "-recursion-depth", "2",
                 "-of", "json", "-o", str(out), "-s"],
                timeout=600,
            )
            data = self.load_json(out)
            for r in data.get("results", []):
                if r.get("url") and self.is_in_scope(r["url"]):
                    found.add(r["url"])

            # Backup / sensitive file fuzzing
            out_bak = self.module_dir / "ffuf" / f"backup_{safe}.json"
            self.exec(
                ["ffuf", "-u", f"{host}/FUZZ", "-w", self._backup_wordlist(),
                 "-mc", "200,201,301,302",
                 "-t", "20", "-timeout", "10", "-rate", str(max(1, int(rate) // 2)),
                 "-of", "json", "-o", str(out_bak), "-s"],
                timeout=300,
            )
            bak_data = self.load_json(out_bak)
            for r in bak_data.get("results", []):
                if r.get("url") and self.is_in_scope(r["url"]):
                    found.add(r["url"])
                    self.warn(f"  ⚠ Sensitive file found: {r['url']}")

        self.success(f"ffuf → {len(found)} URLs")
        return found

    # ── JS Mining ─────────────────────────────────────────────────────────────

    def _js_mining(self, crawled: set[str]) -> tuple[set[str], list[dict]]:
        self.info("JS Mining — endpoints & secrets")
        js_urls = sorted({
            u for u in crawled
            if re.search(r"\.js(\?.*)?$", u, re.IGNORECASE)
        })

        endpoints: set[str] = set()
        secrets:   list[dict] = []

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

                # Extract secrets
                for pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(content):
                        secrets.append({
                            "file":    jsurl,
                            "type":    m.group(1) if m.lastindex else "secret",
                            "match":   m.group(0)[:200],
                            "context": content[max(0, m.start()-30):m.end()+30],
                        })

                time.sleep(rate_delay)
            except Exception:
                continue

        self.save_json(secrets, "js_mining/js_secrets.json")
        self.success(f"JS Mining → {len(endpoints)} endpoints, {len(secrets)} secrets")
        return endpoints, secrets

    # ── GraphQL detection ───────────────────────────────────────────────────

    def _detect_graphql(self, urls: list[str]) -> list[str]:
        found: set[str] = set()
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 ReconX/2.0"

        for base in urls[:80]:
            for path in GRAPHQL_PATHS:
                endpoint = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                if not self.is_in_scope(endpoint):
                    continue
                try:
                    resp = self.http_get(
                        endpoint,
                        session=sess,
                        params={"query": "{ __typename }"},
                        timeout=8,
                    )
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
                except Exception:
                    continue

        result = sorted(found)
        if result:
            self.save_text(result, "graphql/endpoints.txt")
        return result

    # ── Classification ────────────────────────────────────────────────────────

    def _classify(self, urls: list[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for cat, pattern in CLASSIFY_PATTERNS.items():
            matches = sorted({u for u in urls if re.search(pattern, u, re.IGNORECASE)})
            result[cat] = matches
            if matches:
                self.save_text(matches, f"merged/{cat}.txt")
                self.success(f"  {cat}: {len(matches)}")
        return result

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
