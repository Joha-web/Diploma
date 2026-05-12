"""
recon.py — DNS & Subdomain Enumeration Module
Fixes: wildcard DNS detection, API rate limiting, better filtering.
"""

import re
import shlex
import time
import random
import json
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

requests.packages.urllib3.disable_warnings()


class ReconModule(BaseModule):
    name = "recon"
    description = "DNS & Subdomain Enumeration"
    required_tools = ["dig"]

    def __init__(self, target: str, output_dir: str, config: dict):
        super().__init__(target, output_dir, config)
        self.domain = self._clean_domain(target)
        self.is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", target))
        self.subdomains: set[str] = set()
        self.resolved_hosts: list[str] = []
        self.resolved_ips: set[str] = set()
        self.live_http: list[str] = []
        self.wildcard_ips: set[str] = set()
        for sub in ("subdomains", "dns", "urls", "passive"):
            (self.module_dir / sub).mkdir(exist_ok=True)

    def run(self) -> dict:
        rdns = ""
        if self.is_ip:
            rdns = self._reverse_dns(self.target)
            if rdns:
                self.domain = rdns
        if not self.domain:
            self.warn("No domain — skipping")
            return self._empty()

        self._detect_wildcard()
        whois  = self._whois()
        dns    = self._dns_records()
        zone   = self._zone_transfer()
        self._enumerate_subdomains()
        self._resolve_subdomains()
        self._http_probe()
        urls   = self._collect_urls()

        return {
            "target": self.target, "domain": self.domain, "is_ip": self.is_ip,
            "reverse_dns": rdns, "wildcard_detected": bool(self.wildcard_ips),
            "wildcard_ips": sorted(self.wildcard_ips), "whois": whois,
            "dns_records": dns, "zone_transfer": zone,
            "subdomains_total": len(self.subdomains),
            "subdomains": sorted(self.subdomains),
            "resolved_hosts": self.resolved_hosts,
            "resolved_ips": sorted(self.resolved_ips),
            "live_http": self.live_http, "urls": urls,
        }

    # ── Wildcard detection ────────────────────────────────────────────────────

    def _detect_wildcard(self) -> None:
        """Probe 3 random subdomains; if all resolve to same IPs → wildcard."""
        probe_results = []
        for _ in range(3):
            rand = f"nxdomain-{random.randint(100000, 999999)}.{self.domain}"
            r = self.exec(["dig", "+short", "A", rand], timeout=10)
            ips = set(re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", r.stdout))
            probe_results.append(ips)

        if all(probe_results):
            common = set.intersection(*probe_results)
            if common:
                self.wildcard_ips = common
                self.warn(f"Wildcard DNS! IPs {common} — filtering false positives")
                return
        self.success("No wildcard DNS detected")

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    def _whois(self) -> dict:
        if not self.has_tool("whois"):
            return {}
        self.info("WHOIS")
        r = self.exec(["whois", self.domain], timeout=30)
        if not r.stdout:
            return {}
        self.save_text(r.stdout, "passive/whois.txt")
        data: dict = {}
        for line in r.stdout.splitlines():
            ll = line.lower()
            if "registrar:" in ll:
                data.setdefault("registrar", line.split(":", 1)[1].strip())
            elif "creation date" in ll or ll.startswith("created:"):
                data.setdefault("created", line.split(":", 1)[1].strip())
            elif "expir" in ll and "date" in ll:
                data.setdefault("expires", line.split(":", 1)[1].strip())
            elif ll.startswith("name server:"):
                data.setdefault("nameservers", []).append(line.split(":", 1)[1].strip())
        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", r.stdout)))
        if emails:
            data["emails"] = emails
        return data

    # ── DNS Records ───────────────────────────────────────────────────────────

    def _dns_records(self) -> dict:
        self.info("DNS records (A/AAAA/MX/NS/TXT/SOA)")
        records: dict = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            r = self.exec(["dig", "+short", rtype, self.domain], timeout=15)
            if r.stdout.strip():
                records[rtype] = [x.strip() for x in r.stdout.splitlines() if x.strip()]
        self.save_json(records, "dns/dns_records.json")
        return records

    # ── Zone Transfer ─────────────────────────────────────────────────────────

    def _zone_transfer(self) -> list:
        self.info("Zone transfer (AXFR attempt)")
        results = []
        r = self.exec(["dig", "+short", "NS", self.domain], timeout=15)
        for ns in r.stdout.strip().splitlines():
            ns = ns.strip().rstrip(".")
            if not ns:
                continue
            r2 = self.exec(["dig", "AXFR", f"@{ns}", self.domain], timeout=30)
            if r2.stdout and re.search(r"IN\s+A\s+", r2.stdout):
                results.append({"nameserver": ns, "records": len(r2.stdout.splitlines())})
                self.success(f"AXFR successful via {ns}!")
        return results

    # ── Subdomain enum ────────────────────────────────────────────────────────

    def _enumerate_subdomains(self) -> None:
        self.info("Passive subdomain enumeration")
        cfg = self.config.get("scan", {}).get("subdomains", {})

        # Parallel API calls with staggered starts to avoid rate limits
        api_fns = [
            ("crt.sh",       "use_crtsh",        self._api_crtsh),
            ("hackertarget", "use_hackertarget", self._api_hackertarget),
            ("alienvault",   "use_alienvault",   self._api_alienvault),
            ("threatminer",  "use_threatminer",  self._api_threatminer),
            ("rapiddns",     "use_rapiddns",     self._api_rapiddns),
            ("wayback_cdx",  "use_wayback_cdx",  self._api_wayback),
            ("shodan",       "use_shodan",       self._api_shodan),
            ("censys",       "use_censys",       self._api_censys),
            ("github",       "use_github",       self._api_github),
            ("securitytrails", "use_securitytrails", self._api_securitytrails),
            ("binaryedge",   "use_binaryedge",   self._api_binaryedge),
        ]
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for i, (src, cfg_key, fn) in enumerate(api_fns):
                if not cfg.get(cfg_key, True):
                    continue
                time.sleep(i * 0.2)
                futures[pool.submit(fn)] = src
            for fut in as_completed(futures):
                src = futures[fut]
                try:
                    n = self._merge_subs(fut.result(), src)
                    if n:
                        self.success(f"  {src} → +{n}")
                except Exception as e:
                    self.warn(f"  {src}: {e}")

        # Active tools
        if cfg.get("use_subfinder", True) and self.has_tool("subfinder"):
            self.info("  subfinder")
            r = self.exec(["subfinder", "-d", self.domain, "-silent", "-all"],
                          timeout=cfg.get("subfinder_timeout", 300))
            self._merge_subs(r.stdout.splitlines(), "subfinder")

        if cfg.get("use_assetfinder", True) and self.has_tool("assetfinder"):
            self.info("  assetfinder")
            r = self.exec(["assetfinder", "--subs-only", self.domain], timeout=120)
            self._merge_subs(r.stdout.splitlines(), "assetfinder")

        if cfg.get("use_amass", True) and self.has_tool("amass"):
            t = cfg.get("amass_timeout", 180)
            self.info(f"  amass (timeout {t}s)")
            r = self.exec(["amass", "enum", "-passive", "-d", self.domain], timeout=t)
            self._merge_subs(r.stdout.splitlines(), "amass")

        self.save_text(sorted(self.subdomains), "subdomains/all_subdomains.txt")
        self.success(f"Total unique subdomains: {len(self.subdomains)}")

    # ── API sources ───────────────────────────────────────────────────────────

    def _get_text(self, source: str, url: str, timeout: int = 20) -> str | None:
        r = self.http_get(
            url,
            enforce_scope=False,
            timeout=timeout,
            headers={"User-Agent": "ReconX/2.0"},
        )
        if r is None:
            self.warn(f"  {source}: request failed")
            return None
        if r.status_code != 200:
            self.warn(f"  {source}: HTTP {r.status_code}")
            return None
        return r.text or ""

    def _get_json(self, source: str, url: str, timeout: int = 20):
        text = self._get_text(source, url, timeout)
        if text is None:
            return None
        if not text.strip():
            self.warn(f"  {source}: empty response")
            return None
        try:
            return json.loads(text)
        except ValueError:
            preview = text.strip().replace("\n", " ")[:120]
            self.warn(f"  {source}: non-JSON response ({preview})")
            return None

    def _request_json(
        self,
        source: str,
        url: str,
        timeout: int = 20,
        headers: dict | None = None,
        params: dict | None = None,
        auth=None,
    ):
        r = self.http_get(
            url,
            enforce_scope=False,
            timeout=timeout,
            headers=headers or {"User-Agent": "ReconX/2.0"},
            params=params,
            auth=auth,
        )
        if r is None:
            self.warn(f"  {source}: request failed")
            return None
        if r.status_code in (401, 403):
            self.warn(f"  {source}: authentication failed or rate limited (HTTP {r.status_code})")
            return None
        if r.status_code != 200:
            self.warn(f"  {source}: HTTP {r.status_code}")
            return None
        try:
            return r.json()
        except ValueError:
            self.warn(f"  {source}: non-JSON response")
            return None

    def _post_json(
        self,
        source: str,
        url: str,
        payload: dict,
        timeout: int = 20,
        headers: dict | None = None,
        params: dict | None = None,
    ):
        r = self.http_post(
            url,
            safe_readonly=True,
            enforce_scope=False,
            timeout=timeout,
            headers=headers or {"User-Agent": "ReconX/2.0"},
            params=params,
            json=payload,
        )
        if r is None:
            self.warn(f"  {source}: request failed")
            return None
        if r.status_code in (401, 403):
            self.warn(f"  {source}: authentication failed or rate limited (HTTP {r.status_code})")
            return None
        if r.status_code != 200:
            self.warn(f"  {source}: HTTP {r.status_code}")
            return None
        try:
            return r.json()
        except ValueError:
            self.warn(f"  {source}: non-JSON response")
            return None

    def _api_crtsh(self) -> list:
        data = self._get_json(
            "crt.sh",
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            timeout=30,
        )
        if not isinstance(data, list):
            return []
        return [n.strip().lstrip("*.")
                for e in data
                for n in e.get("name_value", "").split("\n")]

    def _api_hackertarget(self) -> list:
        text = self._get_text(
            "hackertarget",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
            timeout=20,
        )
        if text is None:
            return []
        return [l.split(",")[0] for l in text.splitlines() if "," in l]

    def _api_alienvault(self) -> list:
        data = self._get_json(
            "alienvault",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
            timeout=25,
        )
        if not isinstance(data, dict):
            return []
        return [e.get("hostname", "") for e in data.get("passive_dns", [])]

    def _api_threatminer(self) -> list:
        data = self._get_json(
            "threatminer",
            f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5",
            timeout=20,
        )
        if not isinstance(data, dict):
            return []
        return data.get("results", []) or []

    def _api_rapiddns(self) -> list:
        text = self._get_text(
            "rapiddns",
            f"https://rapiddns.io/subdomain/{self.domain}?full=1",
            timeout=20,
        )
        if text is None:
            return []
        return re.findall(r"[a-zA-Z0-9._-]+\." + re.escape(self.domain), text)

    def _api_wayback(self) -> list:
        cfg = self.config.get("scan", {}).get("subdomains", {})
        timeout = int(cfg.get("wayback_timeout", 15))
        limit = int(cfg.get("wayback_limit", 1000))
        text = self._get_text(
            "wayback_cdx",
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}"
            f"&output=text&fl=original&collapse=urlkey&limit={limit}",
            timeout=timeout,
        )
        if text is None:
            return []
        return re.findall(
            r"https?://([a-zA-Z0-9._-]+\." + re.escape(self.domain) + r")", text)

    def _api_shodan(self) -> list:
        key = self.config.get("api_keys", {}).get("shodan", "")
        if not key:
            return []
        data = self._request_json(
            "shodan",
            f"https://api.shodan.io/dns/domain/{self.domain}",
            params={"key": key},
            timeout=30,
        )
        if not isinstance(data, dict):
            return []
        subs = data.get("subdomains", []) or []
        hosts = []
        for sub in subs:
            sub = str(sub).strip().lstrip("*.")
            hosts.append(self.domain if not sub else f"{sub}.{self.domain}")
        for row in data.get("data", []) or []:
            sub = str(row.get("subdomain", "")).strip().lstrip("*.")
            if sub:
                hosts.append(f"{sub}.{self.domain}")
        return hosts

    def _api_censys(self) -> list:
        keys = self.config.get("api_keys", {})
        api_id = keys.get("censys_api_id", "")
        api_secret = keys.get("censys_api_secret", "")
        if not api_secret:
            return []
        if api_id:
            data = self._request_json(
                "censys",
                "https://search.censys.io/api/v2/hosts/search",
                params={
                    "q": f"dns.names: *.{self.domain}",
                    "per_page": 100,
                    "virtual_hosts": "INCLUDE",
                    "fields": "name,dns.names",
                },
                auth=HTTPBasicAuth(api_id, api_secret),
                timeout=30,
            )
        else:
            data = self._post_json(
                "censys",
                "https://api.platform.censys.io/v3/global/search/query",
                {
                    "query": f'"{self.domain}"',
                    "page_size": 100,
                },
                headers={
                    "Authorization": f"Bearer {api_secret}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ReconX/2.0",
                },
                timeout=30,
            )
        if not isinstance(data, dict):
            return []
        hosts = []
        for hit in data.get("result", {}).get("hits", []) or []:
            name = hit.get("name", "")
            if name:
                hosts.append(name)
            dns_names = hit.get("dns", {}).get("names", []) if isinstance(hit.get("dns"), dict) else []
            hosts.extend(dns_names)
        hosts.extend(re.findall(r"[a-zA-Z0-9._-]+\." + re.escape(self.domain), json.dumps(data)))
        return self.unique(hosts)

    def _api_github(self) -> list:
        token = self.config.get("api_keys", {}).get("github", "")
        if not token:
            return []
        cfg = self.config.get("scan", {}).get("subdomains", {})
        per_page = int(cfg.get("github_per_page", 30))
        data = self._request_json(
            "github",
            "https://api.github.com/search/code",
            params={"q": f'"{self.domain}"', "per_page": min(max(per_page, 1), 100)},
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ReconX/2.0",
            },
            timeout=30,
        )
        if not isinstance(data, dict):
            return []
        text = json.dumps(data, ensure_ascii=False, default=str)
        return re.findall(r"[a-zA-Z0-9._-]+\." + re.escape(self.domain), text)

    def _api_securitytrails(self) -> list:
        key = self.config.get("api_keys", {}).get("securitytrails", "")
        if not key:
            return []
        data = self._request_json(
            "securitytrails",
            f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains",
            headers={
                "APIKEY": key,
                "Accept": "application/json",
                "User-Agent": "ReconX/2.0",
            },
            timeout=30,
        )
        if not isinstance(data, dict):
            return []
        return [
            f"{str(sub).strip().lstrip('*.')}.{self.domain}"
            for sub in data.get("subdomains", []) or []
            if isinstance(sub, str) and sub.strip()
        ]

    def _api_binaryedge(self) -> list:
        key = self.config.get("api_keys", {}).get("binaryedge", "")
        if not key:
            return []
        data = self._request_json(
            "binaryedge",
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.domain}",
            headers={
                "X-Key": key,
                "Accept": "application/json",
                "User-Agent": "ReconX/2.0",
            },
            params={"page": 1},
            timeout=30,
        )
        if not isinstance(data, dict):
            return []
        hosts = [
            str(item).strip().lstrip("*.")
            for item in data.get("events", []) or []
            if isinstance(item, str) and item.strip()
        ]
        return self.unique(hosts)

    # ── Resolution ────────────────────────────────────────────────────────────

    def _resolve_subdomains(self) -> None:
        if not self.subdomains:
            return
        self.info(f"DNS resolution ({len(self.subdomains)} hosts)")
        subs_file = self.module_dir / "subdomains" / "all_subdomains.txt"

        if self.has_tool("dnsx"):
            r = self.exec(
                ["dnsx", "-l", str(subs_file), "-a", "-cname", "-resp",
                 "-threads", "100", "-silent", "-no-color"], timeout=600)
            for line in r.stdout.splitlines():
                line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                if not line:
                    continue
                self.resolved_hosts.append(line)
                for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", line):
                    if ip not in self.wildcard_ips:
                        self.resolved_ips.add(ip)
        else:
            for sub in sorted(self.subdomains):
                r = self.exec(["dig", "+short", "A", sub], timeout=10)
                for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", r.stdout):
                    if ip not in self.wildcard_ips:
                        self.resolved_hosts.append(f"{sub} [A] [{ip}]")
                        self.resolved_ips.add(ip)
                        break

        self.save_text(self.resolved_hosts, "dns/resolved_hosts.txt")
        self.save_text(sorted(self.resolved_ips), "dns/resolved_ips.txt")
        self.success(f"Resolved: {len(self.resolved_hosts)} hosts | "
                     f"{len(self.resolved_ips)} unique IPs")

    # ── HTTP probe ────────────────────────────────────────────────────────────

    def _http_probe(self) -> None:
        if not self.subdomains or not self.has_tool("httpx"):
            return
        self.info(f"HTTP probing ({len(self.subdomains)} hosts)")
        subs_file = self.module_dir / "subdomains" / "all_subdomains.txt"
        out_file  = self.module_dir / "subdomains" / "httpx_live.txt"
        self.exec(
            ["httpx", "-l", str(subs_file),
             "-title", "-status-code", "-tech-detect",
             "-follow-redirects", "-threads", "50", "-silent",
             "-o", str(out_file)], timeout=600)
        self.live_http = self.filter_in_scope_urls(self.load_lines(out_file))
        self.success(f"Live HTTP hosts: {len(self.live_http)}")

    # ── URL collection ────────────────────────────────────────────────────────

    def _collect_urls(self) -> dict:
        all_urls: set[str] = set()
        if self.has_tool("waybackurls"):
            self.info("waybackurls")
            cmd = f"printf '%s\\n' {shlex.quote(self.domain)} | waybackurls"
            r = self.exec(cmd, timeout=120, shell=True, label="waybackurls")
            urls = [u.strip() for u in r.stdout.splitlines() if u.strip()]
            all_urls.update(urls)
            self.success(f"waybackurls → {len(urls)} URLs")

        if self.has_tool("gau"):
            self.info("gau")
            r = self.exec(["gau", "--subs", self.domain], timeout=120)
            urls = [u.strip() for u in r.stdout.splitlines() if u.strip()]
            all_urls.update(urls)
            self.success(f"gau → {len(urls)} URLs")
        lst = self.filter_in_scope_urls(all_urls)
        self.save_text(lst, "urls/all_urls.txt")
        return {"all_urls": lst, "total": len(lst)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _merge_subs(self, items, source: str) -> int:
        esc = re.escape(self.domain)
        pat = re.compile(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*" + esc + r"$",
            re.IGNORECASE)
        n = 0
        for item in items:
            s = str(item).strip().lower().lstrip("*.")
            if s and pat.match(s) and s not in self.subdomains:
                self.subdomains.add(s)
                n += 1
        return n

    def _reverse_dns(self, ip: str) -> str:
        r = self.exec(["dig", "+short", "-x", ip], timeout=15)
        rdns = r.stdout.strip().rstrip(".")
        if rdns:
            self.success(f"Reverse DNS: {rdns}")
        return rdns

    @staticmethod
    def _clean_domain(t: str) -> str:
        return BaseModule._clean_domain(t)

    def _empty(self) -> dict:
        return {"target": self.target, "domain": self.domain,
                "subdomains_total": 0, "subdomains": [],
                "resolved_hosts": [], "resolved_ips": [],
                "live_http": [], "urls": {}}
