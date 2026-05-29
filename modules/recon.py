"""
recon.py — DNS & Subdomain Enumeration Module
Fixes: wildcard DNS detection, API rate limiting, better filtering.
"""

import re
import shlex
import time
import random
import json
import ipaddress
import requests
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

requests.packages.urllib3.disable_warnings()


class ReconModule(BaseModule):
    name = "recon"
    description = "DNS & Subdomain Enumeration"
    required_tools = ["dig"]
    TRANSIENT_API_STATUSES = {429, 500, 502, 503, 504}

    def __init__(self, target: str, output_dir: str, config: dict):
        super().__init__(target, output_dir, config)
        self.domain = self._clean_domain(target)
        self.is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", target))
        self.subdomains: set[str] = set()
        self.resolved_hosts: list[str] = []
        self.resolved_ips: set[str] = set()
        self.live_http: list[str] = []
        self.pingable_hosts: list[str] = []
        self.live_subdomains: list[dict] = []
        self.wildcard_ips: set[str] = set()
        for sub in ("subdomains", "dns", "urls", "passive", "screenshots", "cloud", "certs"):
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
        siblings = self._reverse_whois(whois)
        dns    = self._dns_records()
        email_security = self._analyze_email_security(dns)
        zone   = self._zone_transfer()
        self._enumerate_subdomains()
        cloud_buckets = self._enumerate_cloud_buckets()
        self._resolve_subdomains()
        self._ping_check()
        self._http_probe()
        self._classify_live_subdomains()
        cert_sans = self._collect_cert_sans()
        urls   = self._collect_urls()
        asn_info = self._asn_lookup()
        scan_ips = self._scan_target_ips(asn_info)
        origins = self._origin_discovery(asn_info)
        screenshots = self._take_screenshots()
        asset_graph = self._build_asset_graph(
            asn_info=asn_info, urls=urls, cert_sans=cert_sans,
        )

        return {
            "target": self.target, "domain": self.domain, "is_ip": self.is_ip,
            "reverse_dns": rdns, "wildcard_detected": bool(self.wildcard_ips),
            "wildcard_ips": sorted(self.wildcard_ips), "whois": whois,
            "reverse_whois": siblings,
            "dns_records": dns, "zone_transfer": zone,
            "email_security": email_security,
            "subdomains_total": len(self.subdomains),
            "subdomains": sorted(self.subdomains),
            "pingable_hosts": sorted(self.pingable_hosts),
            "resolved_hosts": self.resolved_hosts,
            "resolved_ips": sorted(self.resolved_ips),
            "scan_ips": scan_ips,
            "live_http": self.live_http, "urls": urls,
            "live_subdomains": self.live_subdomains,
            "live_subdomains_total": sum(1 for s in self.live_subdomains if s["live"]),
            "asn": asn_info,
            "origin_discovery": origins,
            "screenshots": screenshots,
            "cloud_buckets": cloud_buckets,
            "cert_sans": cert_sans,
            "asset_graph_summary": asset_graph,
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
        orgs: list[str] = []
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
            elif "organization:" in ll or "registrant org" in ll:
                org = line.split(":", 1)[1].strip()
                if org and org.lower() not in {"redacted for privacy", "redacted"}:
                    orgs.append(org)
        if orgs:
            seen: set[str] = set()
            data["organizations"] = [o for o in orgs if not (o in seen or seen.add(o))]
        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", r.stdout)))
        if emails:
            data["emails"] = emails
        return data

    # ── Reverse WHOIS / org-pivoting ─────────────────────────────────────────

    def _reverse_whois(self, whois_data: dict) -> dict:
        """Find sibling domains issued certificates for the same organization.

        Uses crt.sh ?O=<org>&output=json — works without an API key and tends
        to be the highest-signal free reverse-WHOIS surrogate.
        """
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("use_reverse_whois", False):
            return {}
        orgs = whois_data.get("organizations") or []
        if not orgs:
            self.info("Reverse-WHOIS skipped (no organization in WHOIS)")
            return {}

        max_domains = max(1, int(cfg.get("reverse_whois_max_domains", 100)))
        self.info(f"Reverse-WHOIS via crt.sh (orgs: {len(orgs)})")

        try:
            import tldextract
            extractor = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            extractor = None

        def registered(name: str) -> str:
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if not name or "." not in name:
                return ""
            if extractor is not None:
                parts = extractor(name)
                if parts.domain and parts.suffix:
                    return f"{parts.domain}.{parts.suffix}"
            labels = name.split(".")
            return ".".join(labels[-2:]) if len(labels) >= 2 else name

        target_root = registered(self.domain)
        siblings: dict[str, dict] = {}
        per_org: dict[str, list[str]] = {}

        for org in orgs[:5]:
            data = self._get_json(
                "crt.sh_org",
                f"https://crt.sh/?O={requests.utils.quote(org)}&output=json",
                timeout=45,
            )
            if not isinstance(data, list):
                continue
            org_hits: set[str] = set()
            for entry in data:
                names = str(entry.get("name_value", "")).split("\n")
                for raw in names:
                    base = registered(raw)
                    if not base or base == target_root:
                        continue
                    org_hits.add(base)
                    rec = siblings.setdefault(base, {"sources": set(), "issuers": set()})
                    rec["sources"].add(org)
                    issuer = str(entry.get("issuer_name", "")).strip()
                    if issuer:
                        rec["issuers"].add(issuer[:160])
                    if len(siblings) >= max_domains:
                        break
                if len(siblings) >= max_domains:
                    break
            per_org[org] = sorted(org_hits)[:max_domains]
            if len(siblings) >= max_domains:
                break

        normalized = {
            domain: {
                "sources": sorted(rec["sources"]),
                "issuers": sorted(rec["issuers"]),
            }
            for domain, rec in siblings.items()
        }
        result = {
            "target_root": target_root,
            "queried_orgs": orgs[:5],
            "sibling_domains_total": len(normalized),
            "sibling_domains": dict(sorted(normalized.items())),
            "per_org": per_org,
        }
        self.save_json(result, "passive/sibling_domains.json")
        if normalized:
            self.success(f"Sibling domains: {len(normalized)} via org pivot")
        return result

    # ── DNS Records ───────────────────────────────────────────────────────────

    def _dns_records(self) -> dict:
        self.info("DNS records (A/AAAA/MX/NS/TXT/SOA)")
        records: dict = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            r = self.exec(["dig", "+short", rtype, self.domain], timeout=15)
            lines = self._clean_dns_lines(r.stdout)
            if lines:
                records[rtype] = lines
        dmarc = self.exec(["dig", "+short", "TXT", f"_dmarc.{self.domain}"], timeout=15)
        dmarc_lines = self._clean_dns_lines(dmarc.stdout)
        if dmarc_lines:
            records["DMARC_TXT"] = dmarc_lines
        self.save_json(records, "dns/dns_records.json")
        return records

    @staticmethod
    def _clean_dns_lines(output: str) -> list[str]:
        error_markers = (
            "timed out",
            "servfail",
            "nxdomain",
            "communications error",
            "connection refused",
            "no servers could be reached",
        )
        lines: list[str] = []
        for raw in str(output or "").splitlines():
            line = raw.strip()
            lowered = line.lower()
            if not line or line.startswith(";;"):
                continue
            if any(marker in lowered for marker in error_markers):
                continue
            lines.append(line)
        return lines

    def _analyze_email_security(self, records: dict) -> dict:
        """Extract SPF/DMARC posture from already-collected DNS records."""
        txt_records = [self._normalize_txt(r) for r in records.get("TXT", [])]
        dmarc_records = [self._normalize_txt(r) for r in records.get("DMARC_TXT", [])]
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
        dmarc_policy = ""
        if dmarc_records:
            policy_match = re.search(r"(?:^|;)\s*p\s*=\s*([a-z0-9_-]+)", dmarc_records[0], re.I)
            dmarc_policy = policy_match.group(1).lower() if policy_match else ""

        findings: list[dict] = []
        # When BOTH SPF and DMARC are absent we emit a single combined finding
        # instead of two near-identical ones. This avoids triple-counting (recon
        # used to emit two findings AND the correlator emitted a third combined
        # one for the same posture).
        if not spf_records and not dmarc_records:
            findings.append({
                "source": self.name,
                "id": "missing_spf_and_dmarc",
                "type": "missing_spf_and_dmarc",
                "name": "Email spoofing and phishing controls missing",
                "title": "Email spoofing and phishing controls missing",
                "severity": "MEDIUM",
                "description": (
                    "Domain has neither an SPF TXT record nor a DMARC TXT record. "
                    "Mail receivers cannot validate the legitimacy of mail claiming "
                    "to come from this domain, leaving it open to spoofing and "
                    "phishing-from-domain attacks."
                ),
                "evidence": {
                    "spf_record": "TXT",
                    "spf_expected_prefix": "v=spf1",
                    "dmarc_record": f"_dmarc.{self.domain} TXT",
                },
                "confidence": 0.9,
            })
        elif not spf_records:
            findings.append({
                "source": self.name,
                "id": "missing_spf",
                "type": "missing_spf",
                "name": "Email spoofing possible",
                "title": "Email spoofing possible",
                "severity": "MEDIUM",
                "description": "Domain has no SPF TXT record.",
                "evidence": {"record": "TXT", "expected_prefix": "v=spf1"},
                "confidence": 0.9,
            })
        elif not dmarc_records:
            findings.append({
                "source": self.name,
                "id": "missing_dmarc",
                "type": "missing_dmarc",
                "name": "Phishing risk",
                "title": "Phishing risk",
                "severity": "MEDIUM",
                "description": "Domain has no _dmarc TXT record.",
                "evidence": {"record": f"_dmarc.{self.domain} TXT"},
                "confidence": 0.9,
            })
        elif dmarc_policy in ("", "none"):
            findings.append({
                "source": self.name,
                "id": "weak_dmarc_policy",
                "type": "weak_dmarc_policy",
                "name": "DMARC policy is not enforcing",
                "title": "DMARC policy is not enforcing",
                "severity": "LOW",
                "description": f"DMARC policy is '{dmarc_policy or 'unset'}'.",
                "evidence": {"dmarc_policy": dmarc_policy or "unset"},
                "confidence": 0.85,
            })

        result = {
            "has_spf": bool(spf_records),
            "spf_records": spf_records,
            "has_dmarc": bool(dmarc_records),
            "dmarc_records": dmarc_records,
            "dmarc_policy": dmarc_policy,
            "findings": findings,
        }
        self.save_json(result, "dns/email_security.json")
        if findings:
            self.warn(f"Email DNS findings: {len(findings)}")
        return result

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

        if cfg.get("use_active_bruteforce", False) or cfg.get("enable_active_enum", False):
            added = self._active_dns_bruteforce(cfg)
            if added:
                self.success(f"  active dnsx brute-force → +{added}")

        if cfg.get("use_permutations", False):
            added = self._permutation_brute(cfg)
            if added:
                self.success(f"  permutations → +{added}")

        self.save_text(sorted(self.subdomains), "subdomains/all_subdomains.txt")
        self.success(f"Total unique subdomains: {len(self.subdomains)}")

    def _active_dns_bruteforce(self, cfg: dict) -> int:
        if not self.has_tool("dnsx"):
            self.warn("  active dns brute-force requested but dnsx is not installed")
            return 0

        wordlist = self._subdomain_wordlist(cfg.get("active_wordlist", "subdomains-top1million-5000.txt"))
        if not wordlist:
            self.warn("  active dns brute-force requested but no subdomain wordlist was found")
            return 0

        self.info(f"  dnsx brute-force ({wordlist})")
        out = self.module_dir / "subdomains" / "dnsx_bruteforce.txt"
        threads = str(cfg.get("active_threads", 100))
        timeout = int(cfg.get("active_timeout", 900))
        r = self.exec(
            [
                "dnsx", "-d", self.domain, "-w", wordlist,
                "-a", "-resp", "-t", threads,
                "-silent", "-no-color", "-o", str(out),
            ],
            timeout=timeout,
            label="dnsx active brute-force",
        )
        lines = self.load_lines(out) or r.stdout.splitlines()
        candidates = []
        pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+" + re.escape(self.domain) + r"\b", re.I)
        for line in lines:
            match = pattern.search(line)
            if match:
                candidates.append(match.group(0).lower())
        return self._merge_subs(candidates, "dnsx_bruteforce")

    # ── Permutation / alteration enumeration ─────────────────────────────────

    DEFAULT_PERMUTATION_WORDS = (
        "dev", "test", "testing", "staging", "stage", "qa", "uat", "prod", "prd",
        "preprod", "beta", "alpha", "demo", "internal", "int", "intranet",
        "admin", "adm", "api", "api2", "v1", "v2", "v3", "www", "ww1", "ww2",
        "m", "mobile", "app", "apps", "web", "secure", "ssl", "vpn", "remote",
        "mail", "smtp", "imap", "ftp", "sftp", "git", "gitlab", "jenkins",
        "kibana", "grafana", "monitor", "monitoring", "prometheus",
        "old", "new", "legacy", "backup", "bak", "db", "sql", "mysql", "pg",
        "portal", "dashboard", "panel", "cms", "wp", "auth", "sso", "id",
        "dev1", "dev2", "stg", "qa1", "test1",
    )

    def _permutation_brute(self, cfg: dict) -> int:
        """Generate altdns-style permutations from known subdomains, validate via dnsx."""
        if not self.has_tool("dnsx"):
            self.warn("  permutations requested but dnsx is not installed")
            return 0
        if not self.subdomains:
            return 0

        extra = [str(w).strip().lower() for w in cfg.get("permutation_extra_words", []) if str(w).strip()]
        words = sorted(set(self.DEFAULT_PERMUTATION_WORDS) | set(extra))
        max_perms = max(100, int(cfg.get("permutation_max", 5000)))

        candidates: set[str] = set()

        if self.has_tool("gotator"):
            self.info("  permutations via gotator")
            seeds_path = self.module_dir / "subdomains" / "perm_seeds.txt"
            words_path = self.module_dir / "subdomains" / "perm_words.txt"
            self.save_text(sorted(self.subdomains), "subdomains/perm_seeds.txt")
            self.save_text(words, "subdomains/perm_words.txt")
            r = self.exec(
                ["gotator", "-sub", str(seeds_path), "-perm", str(words_path),
                 "-depth", "1", "-numbers", "0", "-mindup", "-adv", "-md", "-silent"],
                timeout=180,
                label="gotator permutations",
            )
            esc = re.escape(self.domain)
            valid = re.compile(r"^(?:[a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+" + esc + r"$")
            for line in r.stdout.splitlines():
                s = line.strip().lower().rstrip(".")
                if s and valid.match(s):
                    candidates.add(s)
                    if len(candidates) >= max_perms:
                        break
        else:
            self.info("  permutations (built-in generator)")
            base = self.domain
            for sub in list(self.subdomains):
                if not sub.endswith(base):
                    continue
                prefix = sub[:-(len(base) + 1)] if sub != base else ""
                parts = prefix.split(".") if prefix else []
                for w in words:
                    if parts:
                        candidates.add(f"{w}.{sub}")
                        candidates.add(f"{'.'.join(parts)}-{w}.{base}")
                        candidates.add(f"{w}-{'.'.join(parts)}.{base}")
                        for i in range(len(parts)):
                            replaced = list(parts)
                            replaced[i] = w
                            candidates.add(f"{'.'.join(replaced)}.{base}")
                    else:
                        candidates.add(f"{w}.{base}")
                    if len(candidates) >= max_perms:
                        break
                if len(candidates) >= max_perms:
                    break

        candidates -= self.subdomains
        if not candidates:
            return 0

        candidates_file = self.module_dir / "subdomains" / "permutation_candidates.txt"
        self.save_text(sorted(candidates), "subdomains/permutation_candidates.txt")

        self.info(f"  validating {len(candidates)} permutations via dnsx")
        out = self.module_dir / "subdomains" / "permutations_resolved.txt"
        threads = str(int(cfg.get("permutation_threads", 100)))
        timeout = int(cfg.get("permutation_timeout", 600))
        r = self.exec(
            ["dnsx", "-l", str(candidates_file), "-a", "-resp",
             "-t", threads, "-silent", "-no-color", "-o", str(out)],
            timeout=timeout,
            label="dnsx permutation validation",
        )
        lines = self.load_lines(out) or r.stdout.splitlines()
        resolved = []
        pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+" + re.escape(self.domain) + r"\b", re.I)
        for line in lines:
            m = pattern.search(line)
            if m:
                resolved.append(m.group(0).lower())
        return self._merge_subs(resolved, "permutations")

    # ── Cloud-bucket enumeration (S3 / GCS / Azure Blob) ─────────────────────

    CLOUD_BUCKET_SUFFIXES = (
        "", "-prod", "-production", "-dev", "-stage", "-staging", "-test",
        "-qa", "-uat", "-backup", "-bak", "-files", "-assets", "-static",
        "-uploads", "-media", "-data", "-logs", "-archive", "-private",
        "-public", "-internal", "-cdn", "-images", "-img", "-content",
        "-storage", "-bucket", "-s3", "-config",
    )

    def _enumerate_cloud_buckets(self) -> dict:
        """Active S3/GCS/Azure bucket-name guessing seeded from domain + sub labels."""
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("use_cloud_buckets", False):
            return {}

        max_candidates = max(50, int(cfg.get("cloud_bucket_max", 2000)))
        threads = max(2, int(cfg.get("cloud_bucket_threads", 20)))
        timeout = max(2, int(cfg.get("cloud_bucket_timeout", 5)))

        seeds = self._cloud_bucket_seeds()
        extra_words = [str(w).strip().lower() for w in cfg.get("cloud_bucket_extra_words", []) if str(w).strip()]
        suffixes = tuple(dict.fromkeys(list(self.CLOUD_BUCKET_SUFFIXES) + [f"-{w}" for w in extra_words]))

        candidates: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            for suffix in suffixes:
                name = f"{seed}{suffix}".strip("-")
                if not (3 <= len(name) <= 63):
                    continue
                if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.\-]{1,61}[a-z0-9])?", name):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                candidates.append(name)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break

        if not candidates:
            return {}

        self.info(f"Cloud buckets: probing {len(candidates)} names across S3/GCS/Azure")
        self.save_text(candidates, "cloud/candidates.txt")

        findings: dict[str, list[dict]] = {"s3": [], "gcs": [], "azure": []}

        def classify_response(provider: str, name: str, url: str, resp) -> dict | None:
            if resp is None:
                return None
            sc = resp.status_code
            text = (resp.text or "")[:600]
            status = ""
            if provider == "s3":
                if sc == 200 and "ListBucketResult" in text:
                    status = "listable"
                elif sc == 200:
                    status = "exists"
                elif sc == 403 and "AccessDenied" in text:
                    status = "exists_denied"
                elif sc == 404 and "NoSuchBucket" in text:
                    status = ""
                elif sc in (301, 307) and "Endpoint" in text:
                    status = "exists_redirect"
            elif provider == "gcs":
                if sc == 200 and "<ListBucketResult" in text:
                    status = "listable"
                elif sc == 200:
                    status = "exists"
                elif sc == 401:
                    status = "exists_auth_required"
                elif sc == 403:
                    status = "exists_denied"
            elif provider == "azure":
                if sc == 200 and "<EnumerationResults" in text:
                    status = "listable"
                elif sc == 200:
                    status = "exists"
                elif sc in (400, 403, 409):
                    status = "exists_denied"
            if not status:
                return None
            return {
                "name": name,
                "url": url,
                "provider": provider,
                "status": status,
                "http_status": sc,
            }

        def probe(name: str) -> list[dict]:
            results: list[dict] = []
            attempts = [
                ("s3", f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1"),
                ("gcs", f"https://storage.googleapis.com/{name}/?max-keys=1"),
                ("azure", f"https://{name}.blob.core.windows.net/?comp=list&maxresults=1"),
            ]
            for provider, url in attempts:
                resp = self.http_get(
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    enforce_scope=False,
                    headers={"User-Agent": "ReconX/2.0"},
                )
                hit = classify_response(provider, name, url, resp)
                if hit:
                    results.append(hit)
            return results

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(probe, name): name for name in candidates}
            for fut in as_completed(futures):
                try:
                    for hit in fut.result():
                        findings[hit["provider"]].append(hit)
                except Exception:
                    continue

        for provider, hits in findings.items():
            hits.sort(key=lambda h: (h["status"] != "listable", h["name"]))

        total_hits = sum(len(v) for v in findings.values())
        result = {
            "candidates_probed": len(candidates),
            "total_hits": total_hits,
            "by_provider": findings,
        }
        self.save_json(result, "cloud/buckets.json")
        if total_hits:
            listable = sum(1 for v in findings.values() for h in v if h["status"] == "listable")
            self.success(f"Cloud buckets: {total_hits} hit(s); {listable} listable")
        else:
            self.info("  no cloud bucket hits")
        return result

    def _cloud_bucket_seeds(self) -> list[str]:
        """Pull seed names from domain root + sub labels + WHOIS org."""
        seeds: list[str] = []

        root = self.domain.split(".")[0] if "." in self.domain else self.domain
        if root:
            seeds.append(root)

        for sub in self.subdomains:
            if not sub.endswith(self.domain):
                continue
            prefix = sub[:-(len(self.domain) + 1)] if sub != self.domain else ""
            for label in (prefix.split(".") if prefix else []):
                if label and label not in seeds:
                    seeds.append(label)

        try:
            whois_path = self.module_dir / "passive" / "whois.txt"
            if whois_path.exists():
                text = whois_path.read_text(encoding="utf-8", errors="replace")
                for m in re.findall(r"(?:Organization|Registrant Org[^\n:]*):\s*([^\n]+)", text):
                    token = re.sub(r"[^a-z0-9]+", "", m.lower())
                    if token and 3 <= len(token) <= 30 and token not in seeds:
                        seeds.append(token)
        except Exception:
            pass

        # Bucket names must conform to dns-style charset; strip anything invalid.
        cleaned: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            cleaned_seed = re.sub(r"[^a-z0-9-]+", "", seed.lower()).strip("-")
            if cleaned_seed and cleaned_seed not in seen:
                seen.add(cleaned_seed)
                cleaned.append(cleaned_seed)
        return cleaned

    # ── API sources ───────────────────────────────────────────────────────────

    def _api_retry_config(self) -> dict:
        cfg = self.config.get("scan", {}).get("subdomains", {})
        return {
            "retries": max(0, int(cfg.get("api_retries", 1))),
            "delay": max(0.0, float(cfg.get("api_retry_delay", 1.0))),
            "backoff": max(1.0, float(cfg.get("api_retry_backoff", 2.0))),
            "max_delay": max(0.0, float(cfg.get("api_retry_max_delay", 10.0))),
        }

    @staticmethod
    def _retry_after_delay(response, fallback: float, max_delay: float) -> float:
        retry_after = str(response.headers.get("Retry-After", "")).strip() if response is not None else ""
        if retry_after.isdigit():
            return min(float(retry_after), max_delay)
        return min(fallback, max_delay)

    def _warn_api_status(self, source: str, status_code: int, auth_note: str = "") -> None:
        suffix = f" ({auth_note})" if auth_note else ""
        if status_code == 429:
            self.warn(f"  {source}: rate limited (HTTP 429)")
        elif status_code in (401, 403):
            self.warn(f"  {source}: authentication/access failed (HTTP {status_code}){suffix}")
        elif status_code in self.TRANSIENT_API_STATUSES:
            self.warn(f"  {source}: temporary API error (HTTP {status_code})")
        else:
            self.warn(f"  {source}: HTTP {status_code}")

    def _api_http_request(
        self,
        method: str,
        source: str,
        url: str,
        timeout: int = 20,
        headers: dict | None = None,
        params: dict | None = None,
        auth=None,
        payload: dict | None = None,
        auth_note: str = "",
    ):
        retry_cfg = self._api_retry_config()
        attempts = retry_cfg["retries"] + 1
        delay = retry_cfg["delay"]
        method = method.upper()

        for attempt in range(1, attempts + 1):
            if method == "POST":
                response = self.http_post(
                    url,
                    safe_readonly=True,
                    enforce_scope=False,
                    timeout=timeout,
                    headers=headers or {"User-Agent": "ReconX/2.0"},
                    params=params,
                    json=payload or {},
                )
            else:
                response = self.http_get(
                    url,
                    enforce_scope=False,
                    timeout=timeout,
                    headers=headers or {"User-Agent": "ReconX/2.0"},
                    params=params,
                    auth=auth,
                )

            if response is None:
                if attempt < attempts:
                    sleep_for = min(delay, retry_cfg["max_delay"])
                    self.warn(f"  {source}: request failed, retrying in {sleep_for:g}s")
                    if sleep_for:
                        time.sleep(sleep_for)
                    delay *= retry_cfg["backoff"]
                    continue
                self.warn(f"  {source}: request failed")
                return None

            if response.status_code == 200:
                return response

            if response.status_code in self.TRANSIENT_API_STATUSES and attempt < attempts:
                sleep_for = self._retry_after_delay(response, delay, retry_cfg["max_delay"])
                self.warn(f"  {source}: HTTP {response.status_code}, retrying in {sleep_for:g}s")
                if sleep_for:
                    time.sleep(sleep_for)
                delay *= retry_cfg["backoff"]
                continue

            self._warn_api_status(source, response.status_code, auth_note=auth_note)
            return None

        return None

    def _get_text(self, source: str, url: str, timeout: int = 20) -> str | None:
        r = self._api_http_request("GET", source, url, timeout=timeout)
        if r is None:
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
        auth_note: str = "",
    ):
        r = self._api_http_request(
            "GET",
            source,
            url,
            timeout=timeout,
            headers=headers,
            params=params,
            auth=auth,
            auth_note=auth_note,
        )
        if r is None:
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
        auth_note: str = "",
    ):
        r = self._api_http_request(
            "POST",
            source,
            url,
            timeout=timeout,
            headers=headers,
            params=params,
            payload=payload,
            auth_note=auth_note,
        )
        if r is None:
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
            auth_note = "using CENSYS_API_ID + CENSYS_API_SECRET legacy credentials"
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
                auth_note=auth_note,
            )
        else:
            auth_note = (
                "using CENSYS_API_SECRET as Platform PAT; if this is a legacy secret, "
                "set CENSYS_API_ID too"
            )
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
                auth_note=auth_note,
            )
        if not isinstance(data, dict):
            return []
        hosts = []
        for hit in data.get("result", {}).get("hits", []) or []:
            name = hit.get("name", "")
            if name:
                hosts.append(name)
            web_name = hit.get("web", {}).get("name", "") if isinstance(hit.get("web"), dict) else ""
            if web_name:
                hosts.append(web_name)
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

    # ── ICMP Ping check ───────────────────────────────────────────────────────

    def _ping_check(self) -> None:
        if not self.subdomains:
            return
        self.info(f"ICMP Ping check ({len(self.subdomains)} hosts)")
        
        def ping_host(host: str) -> str | None:
            try:
                # -c 1 (one packet), -W 1 (wait 1 second)
                r = self.exec(["ping", "-c", "1", "-W", "1", host], timeout=2)
                if r.returncode == 0:
                    return host
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(ping_host, host): host for host in self.subdomains}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self.pingable_hosts.append(result)

        self.save_text(sorted(self.pingable_hosts), "subdomains/pingable_hosts.txt")
        self.success(f"Pingable hosts: {len(self.pingable_hosts)}")

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
        urls = []
        for line in self.load_lines(out_file):
            match = re.search(r"https?://[^\s\[]+", line)
            if match:
                urls.append(match.group(0).strip())
        self.live_http = self.filter_in_scope_urls(urls)
        self.success(f"Live HTTP hosts: {len(self.live_http)}")

    # ── Live-subdomain aggregation ────────────────────────────────────────────

    def _classify_live_subdomains(self) -> None:
        """Combine DNS / ICMP / HTTP signals into a single per-subdomain verdict.

        A subdomain is considered 'live' if at least one signal fired. Each entry
        records which signals matched so consumers can prioritize follow-up.
        """
        if not self.subdomains:
            return

        resolved_set: set[str] = set()
        ips_by_host: dict[str, list[str]] = {}
        for entry in self.resolved_hosts:
            host = entry.split(" ", 1)[0].strip()
            if not host:
                continue
            resolved_set.add(host)
            ips = re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", entry)
            if ips:
                ips_by_host.setdefault(host, []).extend(ips)

        pingable_set = set(self.pingable_hosts)
        http_by_host: dict[str, list[str]] = {}
        for url in self.live_http:
            host = (urlparse(url).hostname or "").lower()
            if host:
                http_by_host.setdefault(host, []).append(url)

        records: list[dict] = []
        for sub in sorted(self.subdomains):
            host = sub.lower()
            reasons: list[str] = []
            if sub in resolved_set or host in resolved_set:
                reasons.append("dns")
            if sub in pingable_set or host in pingable_set:
                reasons.append("ping")
            urls = http_by_host.get(host, [])
            if urls:
                reasons.append("http")
            records.append({
                "subdomain": sub,
                "live": bool(reasons),
                "reasons": reasons,
                "ips": sorted(set(ips_by_host.get(sub, []) + ips_by_host.get(host, []))),
                "urls": sorted(set(urls)),
            })

        self.live_subdomains = records
        live_only = [r for r in records if r["live"]]
        self.save_json(records, "subdomains/live_subdomains.json")
        self.save_text([r["subdomain"] for r in live_only], "subdomains/live_subdomains.txt")
        self.success(
            f"Live subdomains: {len(live_only)} / {len(records)} "
            f"(dns={sum('dns' in r['reasons'] for r in live_only)}, "
            f"ping={sum('ping' in r['reasons'] for r in live_only)}, "
            f"http={sum('http' in r['reasons'] for r in live_only)})"
        )

    # ── URL collection ────────────────────────────────────────────────────────

    def _collect_urls(self) -> dict:
        all_urls: set[str] = set()
        cfg = self.config.get("scan", {}).get("subdomains", {})

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

        if cfg.get("use_katana", False) and self.live_http and self.has_tool("katana"):
            depth = max(1, int(cfg.get("katana_depth", 2)))
            kt_timeout = int(cfg.get("katana_timeout", 300))
            seeds_file = self.module_dir / "urls" / "katana_seeds.txt"
            out_file = self.module_dir / "urls" / "katana_urls.txt"
            self.save_text(self.live_http, "urls/katana_seeds.txt")
            self.info(f"katana (depth {depth})")
            self.exec(
                ["katana", "-list", str(seeds_file), "-d", str(depth),
                 "-jc", "-silent", "-no-color", "-o", str(out_file)],
                timeout=kt_timeout,
                label="katana crawl",
            )
            kt_urls = [u for u in self.load_lines(out_file) if u.startswith("http")]
            all_urls.update(kt_urls)
            self.success(f"katana → {len(kt_urls)} URLs")

        if cfg.get("use_well_known", True) and self.live_http:
            wk_urls = self._probe_well_known()
            all_urls.update(wk_urls)
            if wk_urls:
                self.success(f"well-known → {len(wk_urls)} URLs")

        lst = self.filter_in_scope_urls(all_urls)
        self.save_text(lst, "urls/all_urls.txt")
        return {"all_urls": lst, "total": len(lst)}

    WELL_KNOWN_PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/humans.txt",
        "/ads.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    )

    def _probe_well_known(self) -> set[str]:
        """Fetch well-known endpoints per live host and extract URLs from each."""
        from urllib.parse import urljoin

        cfg = self.config.get("scan", {}).get("subdomains", {})
        max_hosts = max(1, int(cfg.get("well_known_max_hosts", 50)))
        wk_timeout = int(cfg.get("well_known_timeout", 10))
        targets = list(self.live_http)[:max_hosts]
        if not targets:
            return set()

        self.info(f"well-known probe ({len(targets)} hosts)")

        def probe(base: str) -> tuple[str, dict, set]:
            findings: dict[str, dict] = {}
            urls: set[str] = set()
            root = base.rstrip("/") + "/"
            for path in self.WELL_KNOWN_PATHS:
                url = urljoin(root, path.lstrip("/"))
                r = self.http_get(
                    url,
                    timeout=wk_timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "ReconX/2.0"},
                )
                if r is None or r.status_code != 200:
                    continue
                text = r.text or ""
                if not text or len(text) > 1_500_000:
                    continue
                findings[path] = {
                    "status": r.status_code,
                    "content_type": r.headers.get("Content-Type", "")[:120],
                    "size": len(text),
                }
                for m in re.findall(r'https?://[^\s\'"<>]+', text):
                    urls.add(m.strip().rstrip(".,);"))
                if path.endswith("robots.txt"):
                    for line in text.splitlines():
                        if ":" not in line:
                            continue
                        directive, _, value = line.partition(":")
                        if directive.strip().lower() not in ("allow", "disallow", "sitemap"):
                            continue
                        value = value.strip()
                        if value.startswith("http"):
                            urls.add(value)
                        elif value.startswith("/"):
                            urls.add(urljoin(root, value.lstrip("/")))
                elif "sitemap" in path or path.endswith(".xml"):
                    for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text):
                        urls.add(loc.strip())
            return base, findings, urls

        collected: set[str] = set()
        host_summaries: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(probe, base): base for base in targets}
            for fut in as_completed(futures):
                try:
                    base, findings, urls = fut.result()
                except Exception:
                    continue
                if findings:
                    host_summaries[base] = findings
                collected.update(urls)

        if host_summaries:
            self.save_json(host_summaries, "urls/well_known.json")
        return collected

    def _asn_lookup(self) -> list[dict]:
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("use_asn_lookup", False) or not self.resolved_ips:
            return []

        max_lookups = int(cfg.get("max_asn_lookups", 40))
        by_net: dict[str, str] = {}
        for ip in sorted(self.resolved_ips):
            try:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                continue
            by_net.setdefault(net, ip)

        try:
            delay = float(cfg.get("asn_lookup_delay", 1.0))
        except (TypeError, ValueError):
            delay = 1.0
        lookup_targets = list(by_net.items())[:max_lookups]

        results: list[dict] = []
        for idx, (net, sample_ip) in enumerate(lookup_targets):
            if idx and delay > 0:
                time.sleep(delay)
            data = self._request_json(
                "ipinfo",
                f"https://ipinfo.io/{sample_ip}/json",
                timeout=10,
            )
            if not isinstance(data, dict):
                continue
            org = str(data.get("org", "")).strip()
            entry = {
                "network": net,
                "sample_ip": sample_ip,
                "asn": org.split()[0] if org.upper().startswith("AS") else "",
                "org": org,
                "country": data.get("country", ""),
                "cdn_or_cloud_hint": self._looks_like_cdn_or_cloud(org),
            }
            results.append(entry)

        self.save_json(results, "dns/asn_lookup.json")
        if results:
            self.success(f"ASN lookup: {len(results)} network(s)")
        return results

    def _scan_target_ips(self, asn_info: list[dict]) -> list[str]:
        cfg = self.config.get("scan", {}).get("subdomains", {})
        resolved = sorted(self.resolved_ips)
        if not resolved:
            return []
        if not asn_info or not cfg.get("exclude_cdn_ips", True):
            self.save_text(resolved, "dns/scan_ips.txt")
            return resolved

        cdn_networks = []
        for entry in asn_info:
            if not entry.get("cdn_or_cloud_hint"):
                continue
            try:
                cdn_networks.append(ipaddress.ip_network(str(entry.get("network", "")), strict=False))
            except ValueError:
                continue

        scan_ips: list[str] = []
        excluded: list[dict] = []
        for ip in resolved:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            matching_net = next((net for net in cdn_networks if ip_obj in net), None)
            if matching_net:
                excluded.append({"ip": ip, "reason": "cdn_or_cloud_asn", "network": str(matching_net)})
            else:
                scan_ips.append(ip)

        self.save_text(scan_ips, "dns/scan_ips.txt")
        if excluded:
            self.save_json(excluded, "dns/excluded_cdn_ips.json")
            self.warn(f"ASN filter excluded {len(excluded)} CDN/cloud IP(s) from active port scanning")
        return scan_ips

    # ── Origin-IP discovery (behind CDN/WAF) ──────────────────────────────────

    def _origin_discovery(self, asn_info: list[dict]) -> dict:
        """Surface origin-IP candidates for CDN-fronted subdomains.

        Combines two signals:
          1) shared-label heuristic — siblings that share a label with a fronted
             host but resolve directly are likely the origin or share its tier;
          2) historical A-records via SecurityTrails (when key is present),
             filtered to non-CDN networks.
        """
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("use_origin_discovery", False):
            return {}
        if not self.resolved_hosts:
            return {}

        self.info("Origin-IP discovery")

        cdn_nets: list = []
        for entry in asn_info or []:
            if not entry.get("cdn_or_cloud_hint"):
                continue
            try:
                cdn_nets.append(ipaddress.ip_network(str(entry.get("network", "")), strict=False))
            except ValueError:
                continue

        def is_cdn(ip: str) -> bool:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(ip_obj in net for net in cdn_nets)

        host_ips: dict[str, list[str]] = {}
        for entry in self.resolved_hosts:
            host = entry.split(" ", 1)[0].strip().lower()
            if not host:
                continue
            ips = re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", entry)
            if ips:
                host_ips.setdefault(host, []).extend(ips)

        cdn_fronted: list[str] = []
        directly_exposed: list[str] = []
        for host, ips in host_ips.items():
            uniq = sorted(set(ips))
            if uniq and all(is_cdn(ip) for ip in uniq):
                cdn_fronted.append(host)
            elif any(not is_cdn(ip) for ip in uniq):
                directly_exposed.append(host)

        candidates: list[dict] = []
        seen_pairs: set[tuple[str, str]] = set()
        max_lookups = max(1, int(cfg.get("origin_max_lookups", 50)))

        def host_labels(host: str) -> set[str]:
            stripped = host[:-(len(self.domain) + 1)] if host.endswith("." + self.domain) else host
            return {lab for lab in stripped.split(".") if lab}

        for host in sorted(cdn_fronted)[:max_lookups]:
            labels = host_labels(host)
            if not labels:
                continue
            for other in directly_exposed:
                if other == host:
                    continue
                if not (labels & host_labels(other)):
                    continue
                non_cdn = sorted({ip for ip in host_ips.get(other, []) if not is_cdn(ip)})
                if not non_cdn:
                    continue
                key = (host, other)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                candidates.append({
                    "cdn_fronted": host,
                    "candidate_origin_sub": other,
                    "candidate_ips": non_cdn,
                    "confidence": "low",
                    "method": "shared_label",
                })

        st_key = self.config.get("api_keys", {}).get("securitytrails", "")
        if st_key and cdn_fronted:
            for host in sorted(cdn_fronted)[:max_lookups]:
                data = self._request_json(
                    "securitytrails_history",
                    f"https://api.securitytrails.com/v1/history/{host}/dns/a",
                    headers={
                        "APIKEY": st_key,
                        "Accept": "application/json",
                        "User-Agent": "ReconX/2.0",
                    },
                    timeout=20,
                )
                if not isinstance(data, dict):
                    continue
                historical: list[str] = []
                for rec in data.get("records", []) or []:
                    for v in rec.get("values", []) or []:
                        ip = str(v.get("ip", "")).strip()
                        if ip and not is_cdn(ip):
                            historical.append(ip)
                uniq = sorted(set(historical))
                if uniq:
                    candidates.append({
                        "cdn_fronted": host,
                        "historical_non_cdn_ips": uniq,
                        "confidence": "medium",
                        "method": "securitytrails_history",
                    })

        result = {
            "cdn_fronted_hosts": sorted(cdn_fronted),
            "directly_exposed_hosts": sorted(directly_exposed),
            "origin_candidates": candidates,
        }
        self.save_json(result, "dns/origin_candidates.json")
        if candidates:
            self.success(f"Origin candidates: {len(candidates)}")
        elif cdn_fronted:
            self.info(f"  {len(cdn_fronted)} CDN-fronted host(s), no origin candidates")
        return result

    # ── Visual recon (screenshots) ───────────────────────────────────────────

    def _take_screenshots(self) -> dict:
        """Capture HTTP screenshots of live hosts via gowitness."""
        cfg = self.config.get("scan", {}).get("http", {})
        if not cfg.get("screenshots", False):
            return {}
        if not self.live_http:
            return {}
        if not self.has_tool("gowitness"):
            self.warn("Screenshots requested but gowitness is not installed")
            return {}

        targets = list(self.live_http)
        self.info(f"Screenshots ({len(targets)} hosts) via gowitness")
        shot_dir = self.module_dir / "screenshots"
        shot_dir.mkdir(exist_ok=True)
        targets_file = shot_dir / "targets.txt"
        self.save_text(targets, "screenshots/targets.txt")
        manifest = shot_dir / "gowitness.jsonl"

        threads = str(max(1, int(cfg.get("screenshot_threads", 5))))
        timeout = int(cfg.get("screenshot_timeout", 600))

        cmd_v3 = [
            "gowitness", "scan", "file",
            "-f", str(targets_file),
            "--screenshot-path", str(shot_dir),
            "--threads", threads,
            "--write-jsonl",
            "--write-jsonl-file", str(manifest),
        ]
        r = self.exec(cmd_v3, timeout=timeout, label="gowitness v3")
        if r.returncode != 0:
            cmd_v2 = [
                "gowitness", "file",
                "-f", str(targets_file),
                "-P", str(shot_dir),
                "--threads", threads,
            ]
            self.info("  gowitness v3 failed, retrying with v2 syntax")
            self.exec(cmd_v2, timeout=timeout, label="gowitness v2")

        shots = sorted(
            [p.name for p in shot_dir.iterdir()
             if p.is_file() and p.suffix.lower() in (".png", ".jpg", ".jpeg")]
        )
        self.success(f"Screenshots captured: {len(shots)}")
        return {
            "directory": str(shot_dir),
            "count": len(shots),
            "files": shots,
        }

    # ── TLS-cert SAN graph ────────────────────────────────────────────────────

    def _collect_cert_sans(self) -> dict:
        """Pull SANs from each live host's TLS cert and build a sharing graph.

        Same-domain SANs are merged back into self.subdomains so downstream
        modules see them. Sibling-domain SANs (different eTLD+1) are recorded
        separately.
        """
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("use_cert_san_graph", False):
            return {}
        if not self.live_http:
            return {}

        import socket
        import ssl
        import hashlib

        max_hosts = max(1, int(cfg.get("cert_san_max_hosts", 80)))
        timeout = max(2, int(cfg.get("cert_san_timeout", 5)))

        https_hosts: list[tuple[str, int]] = []
        seen_hp: set[tuple[str, int]] = set()
        for url in self.live_http:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                continue
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            port = parsed.port or 443
            hp = (host, port)
            if hp in seen_hp:
                continue
            seen_hp.add(hp)
            https_hosts.append(hp)
            if len(https_hosts) >= max_hosts:
                break

        if not https_hosts:
            return {}

        self.info(f"TLS cert SANs ({len(https_hosts)} hosts)")
        ctx = ssl._create_unverified_context()

        def fetch(host: str, port: int) -> tuple[str, dict | None]:
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        der = ssock.getpeercert(binary_form=True)
            except Exception:
                return host, None
            sans: list[str] = []
            for key, value in cert.get("subjectAltName", []) or []:
                if key == "DNS":
                    sans.append(str(value).strip(".").lower())
            subject_cn = ""
            for rdn in cert.get("subject", []) or []:
                for k, v in rdn:
                    if k == "commonName":
                        subject_cn = str(v).strip().lower()
            issuer_cn = ""
            for rdn in cert.get("issuer", []) or []:
                for k, v in rdn:
                    if k == "commonName":
                        issuer_cn = str(v).strip()
            fp = hashlib.sha256(der).hexdigest()[:32]
            return host, {
                "fingerprint": fp,
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "sans": sorted(set(sans)),
            }

        host_to_cert: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=min(20, len(https_hosts))) as pool:
            futures = {pool.submit(fetch, h, p): (h, p) for h, p in https_hosts}
            for fut in as_completed(futures):
                try:
                    host, info = fut.result()
                except Exception:
                    continue
                if info:
                    host_to_cert[host] = info

        try:
            import tldextract
            extractor = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            extractor = None

        def registered(name: str) -> str:
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if not name or "." not in name:
                return ""
            if extractor is not None:
                parts = extractor(name)
                if parts.domain and parts.suffix:
                    return f"{parts.domain}.{parts.suffix}"
            labels = name.split(".")
            return ".".join(labels[-2:]) if len(labels) >= 2 else name

        target_root = registered(self.domain)

        # Build the inverse: fingerprint -> {hosts, SANs}.
        fp_to_group: dict[str, dict] = {}
        for host, info in host_to_cert.items():
            grp = fp_to_group.setdefault(info["fingerprint"], {
                "fingerprint": info["fingerprint"],
                "subject_cn": info["subject_cn"],
                "issuer_cn": info["issuer_cn"],
                "not_before": info["not_before"],
                "not_after": info["not_after"],
                "hosts": [],
                "sans": set(),
            })
            grp["hosts"].append(host)
            grp["sans"].update(info["sans"])

        groups: list[dict] = []
        new_same_domain: set[str] = set()
        sibling_domains: set[str] = set()
        for grp in fp_to_group.values():
            sans_sorted = sorted(grp["sans"])
            for san in sans_sorted:
                clean = san.lstrip("*.")
                if not clean:
                    continue
                if clean == self.domain or clean.endswith("." + self.domain):
                    if clean not in self.subdomains:
                        new_same_domain.add(clean)
                else:
                    base = registered(clean)
                    if base and base != target_root:
                        sibling_domains.add(base)
            groups.append({
                "fingerprint": grp["fingerprint"],
                "subject_cn": grp["subject_cn"],
                "issuer_cn": grp["issuer_cn"],
                "not_before": grp["not_before"],
                "not_after": grp["not_after"],
                "hosts": sorted(grp["hosts"]),
                "sans": sans_sorted,
                "san_count": len(sans_sorted),
            })

        added = self._merge_subs(new_same_domain, "cert_san")
        if added:
            self.success(f"  cert SANs → +{added} new sub(s)")
            self.save_text(sorted(self.subdomains), "subdomains/all_subdomains.txt")

        result = {
            "groups": sorted(groups, key=lambda g: -g["san_count"]),
            "new_subdomains": sorted(new_same_domain),
            "sibling_domains": sorted(sibling_domains),
            "hosts_probed": len(host_to_cert),
        }
        self.save_json(result, "certs/cert_san_graph.json")
        if sibling_domains:
            self.success(f"  cert SANs → {len(sibling_domains)} sibling domain(s)")
        return result

    # ── Unified asset graph ──────────────────────────────────────────────────

    def _build_asset_graph(
        self,
        asn_info: list[dict],
        urls: dict,
        cert_sans: dict,
    ) -> dict:
        """Synthesise sub ↔ IP ↔ ASN ↔ cert ↔ tech ↔ endpoints into one graph."""
        cfg = self.config.get("scan", {}).get("subdomains", {})
        if not cfg.get("build_asset_graph", True):
            return {}
        if not self.subdomains and not self.resolved_hosts:
            return {}

        self.info("Building asset graph")

        # subdomain -> ips, ip -> network
        sub_to_ips: dict[str, list[str]] = {}
        for entry in self.resolved_hosts:
            host = entry.split(" ", 1)[0].strip().lower()
            if not host:
                continue
            ips = re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", entry)
            if ips:
                sub_to_ips.setdefault(host, []).extend(ips)

        ip_to_asn: dict[str, dict] = {}
        for entry in asn_info or []:
            net_str = str(entry.get("network", ""))
            try:
                net = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                continue
            for ip in sorted(self.resolved_ips):
                try:
                    if ipaddress.ip_address(ip) in net:
                        ip_to_asn[ip] = {
                            "asn": entry.get("asn", ""),
                            "org": entry.get("org", ""),
                            "network": net_str,
                            "country": entry.get("country", ""),
                            "cdn_or_cloud": entry.get("cdn_or_cloud_hint", False),
                        }
                except ValueError:
                    continue

        # subdomain -> cert fingerprints
        sub_to_certs: dict[str, list[str]] = {}
        cert_meta: dict[str, dict] = {}
        for grp in (cert_sans or {}).get("groups", []) or []:
            fp = grp.get("fingerprint", "")
            if not fp:
                continue
            cert_meta[fp] = {
                "subject_cn": grp.get("subject_cn", ""),
                "issuer_cn": grp.get("issuer_cn", ""),
                "san_count": grp.get("san_count", 0),
                "not_after": grp.get("not_after", ""),
            }
            for host in grp.get("hosts", []) or []:
                sub_to_certs.setdefault(host, []).append(fp)

        # subdomain -> tech (from sibling techstack module if present)
        sub_to_techs: dict[str, list[str]] = {}
        try:
            tech_path = self.session_path("techstack", "technologies.json")
            if tech_path.exists():
                tech_data = self.load_json(tech_path)
                if isinstance(tech_data, list):
                    for entry in tech_data:
                        url = str(entry.get("url", ""))
                        host = (urlparse(url).hostname or "").lower()
                        if not host:
                            continue
                        names = [str(t.get("name", "")).strip()
                                 for t in entry.get("technologies", []) or []
                                 if t.get("name")]
                        if names:
                            sub_to_techs.setdefault(host, []).extend(names)
        except Exception:
            pass

        # subdomain -> endpoints (bucket discovered URLs by host)
        sub_to_endpoints_count: dict[str, int] = {}
        for url in (urls or {}).get("all_urls", []) or []:
            host = (urlparse(url).hostname or "").lower()
            if host:
                sub_to_endpoints_count[host] = sub_to_endpoints_count.get(host, 0) + 1

        nodes: list[dict] = []
        for sub in sorted(self.subdomains):
            ips = sorted(set(sub_to_ips.get(sub, [])))
            asn_entries = [ip_to_asn[ip] for ip in ips if ip in ip_to_asn]
            certs = sorted(set(sub_to_certs.get(sub, [])))
            techs = sorted(set(sub_to_techs.get(sub, [])))
            nodes.append({
                "subdomain": sub,
                "ips": ips,
                "asn": asn_entries,
                "certs": [{"fingerprint": fp, **cert_meta.get(fp, {})} for fp in certs],
                "technologies": techs,
                "endpoint_count": sub_to_endpoints_count.get(sub, 0),
                "live_http": any(s["subdomain"] == sub and "http" in s.get("reasons", [])
                                 for s in self.live_subdomains),
            })

        graph = {
            "target": self.target,
            "domain": self.domain,
            "node_count": len(nodes),
            "nodes": nodes,
        }
        self.save_json(graph, "asset_graph.json")

        summary = {
            "node_count": len(nodes),
            "with_ips": sum(1 for n in nodes if n["ips"]),
            "with_asn": sum(1 for n in nodes if n["asn"]),
            "with_certs": sum(1 for n in nodes if n["certs"]),
            "with_techs": sum(1 for n in nodes if n["technologies"]),
            "with_endpoints": sum(1 for n in nodes if n["endpoint_count"]),
            "live_http": sum(1 for n in nodes if n["live_http"]),
            "graph_path": str(self.module_dir / "asset_graph.json"),
        }
        self.success(
            f"Asset graph: {summary['node_count']} nodes "
            f"(ips={summary['with_ips']} certs={summary['with_certs']} "
            f"techs={summary['with_techs']} endpoints={summary['with_endpoints']})"
        )
        return summary

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

    def _subdomain_wordlist(self, filename: str) -> str:
        from pathlib import Path

        direct = Path(str(filename)).expanduser()
        if direct.is_file():
            return str(direct)

        for base in self.config.get("wordlists", {}).get("search_paths", [
            "/opt/SecLists", "/usr/share/seclists", "/usr/share/wordlists",
        ]):
            candidates = []
            try:
                root_path = Path(base)
                if root_path.exists():
                    candidates = list(root_path.rglob(filename))
            except Exception:
                candidates = []
            for candidate in candidates:
                if candidate.is_file():
                    return str(candidate)
        return ""

    @staticmethod
    def _normalize_txt(value: str) -> str:
        return value.replace('" "', "").replace('"', "").strip()

    @staticmethod
    def _looks_like_cdn_or_cloud(org: str) -> bool:
        org_l = org.lower()
        markers = (
            "cloudflare", "akamai", "fastly", "cloudfront", "amazon", "aws",
            "google", "microsoft", "azure", "digitalocean", "linode", "ovh",
            "hetzner", "oracle", "gcore", "cdn77", "bunny",
        )
        return any(marker in org_l for marker in markers)

    @staticmethod
    def _clean_domain(t: str) -> str:
        return BaseModule._clean_domain(t)

    def _empty(self) -> dict:
        return {"target": self.target, "domain": self.domain,
                "subdomains_total": 0, "subdomains": [],
                "resolved_hosts": [], "resolved_ips": [],
                "scan_ips": [], "live_http": [], "urls": {},
                "email_security": {}, "asn": [],
                "origin_discovery": {}, "screenshots": {},
                "reverse_whois": {}, "cloud_buckets": {},
                "cert_sans": {}, "asset_graph_summary": {}}
