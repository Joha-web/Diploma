"""
ReconX — Module: Technology Fingerprinting
Tools: whatweb, httpx --tech-detect, wafw00f, nuclei (tech tags)
Fix:   whatweb parser handles nested brackets correctly.
"""

import re
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.base import BaseModule

TECH_CATEGORIES: dict[str, str] = {
    "Apache":"Web Server", "Nginx":"Web Server", "IIS":"Web Server",
    "LiteSpeed":"Web Server", "OpenResty":"Web Server", "Caddy":"Web Server",
    "Tomcat":"Web Server", "Gunicorn":"Web Server",
    "PHP":"Language", "Python":"Language", "Ruby":"Language",
    "Java":"Language", "Node.js":"Language", "Go":"Language", "Perl":"Language",
    "WordPress":"CMS", "Drupal":"CMS", "Joomla":"CMS",
    "Bitrix":"CMS", "1C-Bitrix":"CMS", "MODX":"CMS",
    "Ghost":"CMS", "Typo3":"CMS", "Moodle":"CMS",
    "jQuery":"JS Library", "Lodash":"JS Library",
    "React":"JS Framework", "Next.js":"JS Framework",
    "Vue.js":"JS Framework", "Angular":"JS Framework", "Nuxt.js":"JS Framework",
    "Bootstrap":"CSS Framework", "Tailwind CSS":"CSS Framework",
    "Laravel":"Web Framework", "Django":"Web Framework",
    "Flask":"Web Framework", "Rails":"Web Framework",
    "Spring":"Web Framework", "Express":"Web Framework",
    "MySQL":"Database", "PostgreSQL":"Database", "MongoDB":"Database",
    "Redis":"Database", "Elasticsearch":"Database", "MariaDB":"Database",
    "Google Analytics":"Analytics", "Google Tag Manager":"Analytics",
    "Yandex.Metrika":"Analytics",
    "Cloudflare":"CDN/WAF", "Varnish":"Cache", "Amazon CloudFront":"CDN",
    "Let's Encrypt":"SSL", "OpenSSL":"SSL",
    "Kubernetes":"Infrastructure", "Docker":"Infrastructure",
    "GitLab":"DevTools", "Jenkins":"DevTools",
    "Grafana":"Monitoring", "Prometheus":"Monitoring",
}

CMS_SET = {"WordPress", "Drupal", "Joomla", "Bitrix", "1C-Bitrix",
           "MODX", "Ghost", "Typo3", "Moodle"}

SKIP_PLUGINS = {
    "Country", "IP", "RedirectLocation", "UncommonHeaders",
    "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security",
    "Content-Security-Policy", "X-Content-Type-Options", "Script",
    "HTML5", "Email", "Cookies", "Frame", "HTML", "CSS", "Meta-Refresh",
    "Open-Graph-Protocol", "PasswordField", "FormAction",
}


class TechStackModule(BaseModule):
    name = "techstack"
    description = "Technology Fingerprinting"
    required_tools = ["whatweb", "httpx", "wafw00f"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        urls = self._urls()
        if not urls:
            self.warn("No URLs to fingerprint")
            return {"hosts": [], "technologies_summary": {}, "cms_detected": []}

        self.save_text(urls, "urls.txt")
        url_file = self.module_dir / "urls.txt"
        hosts: dict[str, dict] = {
            u: {"url": u, "status": "?", "technologies": [], "waf": [], "server": ""}
            for u in urls
        }

        # Run tools in parallel threads
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = {
                pool.submit(self._run_whatweb, url_file): "whatweb",
                pool.submit(self._run_wafw00f,  url_file): "wafw00f",
                pool.submit(self._run_nuclei,   url_file): "nuclei",
            }
            tool_results: dict[str, dict] = {}
            for f in as_completed(futs):
                tool_results[futs[f]] = f.result() or {}

        # Merge into hosts dict
        for url in urls:
            u = url.rstrip("/")
            ww = tool_results["whatweb"].get(u, {})
            nc = tool_results["nuclei"].get(u, {})
            wf = tool_results["wafw00f"].get(u, [])

            existing: set[str] = set()
            for t in ww.get("technologies", []):
                if t["name"].lower() not in existing:
                    hosts[url]["technologies"].append(t)
                    existing.add(t["name"].lower())
            if ww.get("server"):
                hosts[url]["server"] = ww["server"]
            if ww.get("status"):
                hosts[url]["status"] = ww["status"]
            for t in nc.get("technologies", []):
                if t["name"].lower() not in existing:
                    hosts[url]["technologies"].append(t)
                    existing.add(t["name"].lower())
            hosts[url]["waf"] = wf

        # Ensure category is set
        for h in hosts.values():
            for t in h["technologies"]:
                if not t.get("category"):
                    t["category"] = TECH_CATEGORIES.get(t["name"], "Other")

        host_list = list(hosts.values())

        # Build summary stats
        tech_counter: dict[str, int] = {}
        cms_detected: list[dict] = []
        for h in host_list:
            for t in h["technologies"]:
                tech_counter[t["name"]] = tech_counter.get(t["name"], 0) + 1
                if t["name"] in CMS_SET:
                    cms_detected.append({"name": t["name"], "url": h["url"],
                                         "version": t.get("version", "")})

        top_techs = dict(sorted(tech_counter.items(), key=lambda x: -x[1])[:40])

        self.save_json(host_list, "technologies.json")
        self.success(f"{len(host_list)} hosts | {len(tech_counter)} unique technologies")
        if cms_detected:
            self.warn(f"CMS detected: {[c['name'] for c in cms_detected]}")

        return {
            "hosts":                host_list,
            "technologies_summary": top_techs,
            "cms_detected":         cms_detected,
        }

    # ── whatweb ───────────────────────────────────────────────────────────────

    def _run_whatweb(self, url_file: Path) -> dict:
        if not self.has_tool("whatweb"):
            return {}
        raw = self.module_dir / "whatweb_raw.txt"
        self.exec(
            ["whatweb", "-i", str(url_file),
             "--log-brief", str(raw),
             "-a", "3", "--no-errors", "--colour=never"],
            timeout=600,
        )
        return self._parse_whatweb(raw)

    def _parse_whatweb(self, path: Path) -> dict[str, dict]:
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        result: dict[str, dict] = {}
        if not path.exists():
            return result

        for line in path.read_text(errors="replace").splitlines():
            line = ansi.sub("", line).strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"(https?://\S+?)\s+\[(\d+)[^\]]*\]\s*(.*)", line)
            if not m:
                continue
            url, status, rest = m.group(1).rstrip("/"), m.group(2), m.group(3)

            techs:  list[dict] = []
            server: str = ""

            for name, val in self._parse_plugins(rest).items():
                if name in SKIP_PLUGINS:
                    continue
                if name == "HTTPServer" and val:
                    server = val.split("/")[0].strip()
                    ver    = val.split("/")[1].strip() if "/" in val else ""
                    techs.append({"name": server, "version": ver,
                                  "category": "Web Server", "source": "whatweb"})
                    continue
                if name == "X-Powered-By" and val:
                    nm  = val.split("/")[0].strip()
                    ver = val.split("/")[1].strip() if "/" in val else ""
                    techs.append({"name": nm, "version": ver,
                                  "category": TECH_CATEGORIES.get(nm, "Other"),
                                  "source": "whatweb"})
                    continue
                ver = ""
                if val:
                    vm = re.search(r"\d+\.\d+[\d.]*", val)
                    if vm:
                        ver = vm.group(0)
                techs.append({"name": name, "version": ver,
                               "category": TECH_CATEGORIES.get(name, "Other"),
                               "source": "whatweb"})

            result[url] = {"technologies": techs, "server": server, "status": status}
        return result

    @staticmethod
    def _parse_plugins(s: str) -> dict[str, str]:
        """Parse whatweb plugin string handling nested brackets via depth counter."""
        plugins: dict[str, str] = {}
        i, name_buf = 0, ""
        while i < len(s):
            ch = s[i]
            if ch == "[":
                depth, j = 1, i + 1
                while j < len(s) and depth:
                    if s[j] == "[": depth += 1
                    elif s[j] == "]": depth -= 1
                    j += 1
                val = s[i + 1 : j - 1]
                key = name_buf.strip()
                if key:
                    plugins[key] = val
                name_buf = ""
                i = j
                if i < len(s) and s[i] == ",": i += 1
                if i < len(s) and s[i] == " ": i += 1
            elif s[i:i+2] == ", ":
                key = name_buf.strip()
                if key:
                    plugins[key] = ""
                name_buf = ""
                i += 2
            else:
                name_buf += ch
                i += 1
        if name_buf.strip():
            plugins[name_buf.strip()] = ""
        return plugins

    # ── wafw00f ───────────────────────────────────────────────────────────────

    def _run_wafw00f(self, url_file: Path) -> dict:
        if not self.has_tool("wafw00f"):
            return {}
        raw = self.module_dir / "wafw00f_raw.txt"
        self.exec(["wafw00f", "-i", str(url_file), "-o", str(raw)], timeout=300)
        return self._parse_wafw00f(raw)

    def _parse_wafw00f(self, path: Path) -> dict[str, list[str]]:
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        result: dict[str, list[str]] = {}
        if not path.exists():
            return result
        for line in path.read_text(errors="replace").splitlines():
            line = ansi.sub("", line).strip()
            m = re.search(r"(https?://\S+).*?behind\s+(.+?)(?:\s+WAF)?$", line, re.I)
            if m:
                result.setdefault(m.group(1).rstrip("/"), []).append(m.group(2).strip())
        return result

    # ── nuclei tech tags ──────────────────────────────────────────────────────

    def _run_nuclei(self, url_file: Path) -> dict:
        if not self.has_tool("nuclei"):
            return {}
        raw = self.module_dir / "nuclei_tech.jsonl"
        rate = str(self.config.get("scan", {}).get("nuclei", {}).get("rate_limit", 100))
        self.exec(
            ["nuclei", "-l", str(url_file), "-tags", "tech",
             "-silent", "-no-color", "-jsonl", "-o", str(raw), "-rl", rate],
            timeout=600,
        )
        return self._parse_nuclei(raw)

    def _parse_nuclei(self, path: Path) -> dict[str, dict]:
        result: dict[str, dict] = {}
        if not path.exists():
            return result
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                obj  = json.loads(line)
                url  = obj.get("host", "").rstrip("/")
                name = obj.get("info", {}).get("name", "")
                ver  = ""
                ext  = obj.get("extracted-results", [])
                if ext:
                    ver = ext[0]
                result.setdefault(url, {"technologies": []})["technologies"].append({
                    "name":     name,
                    "version":  ver,
                    "category": TECH_CATEGORIES.get(name, "Other"),
                    "source":   "nuclei",
                })
            except Exception:
                continue
        return result

    # ── helpers ───────────────────────────────────────────────────────────────

    def _urls(self) -> list[str]:
        urls: set[str] = set()
        for line in self.live_hosts:
            m = re.search(r"https?://[^\s]+", line)
            if m:
                urls.add(m.group(0))
        return sorted(urls)
