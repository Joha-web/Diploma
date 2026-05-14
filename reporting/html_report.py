"""
ReconX — HTML Report Generator
Renders templates/report.html via Jinja2 with full scan results.
AI analysis is rendered from Markdown to HTML for proper formatting.
"""

import json
import html
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False

ALLOWED_TAGS = [
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li",
    "code", "pre", "strong", "em", "table", "thead", "tbody", "tr",
    "td", "th", "br", "blockquote", "a",
]
ALLOWED_ATTRS = {"a": ["href", "title", "rel", "target"]}


class HTMLReportGenerator:
    def __init__(self, output_dir: str, target: str, duration: str = ""):
        self.output_dir  = Path(output_dir)
        self.target      = target
        self.duration    = duration
        self.template_dir = Path(__file__).parent.parent / "templates"

    def generate(self, all_results: dict, ai_analysis: str = "") -> str:
        """Render report.html and return path to the generated file."""
        env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html"]),
        )
        # Custom filters
        env.filters["jsonpretty"] = lambda x: json.dumps(
            x, indent=2, ensure_ascii=False, default=str
        )
        env.filters["default_val"] = lambda x, d="": x if x is not None else d

        template = env.get_template("report.html")

        ctx = self._build_context(all_results, ai_analysis)
        html = template.render(**ctx)

        out_path = self.output_dir / "report.html"
        out_path.write_text(html, encoding="utf-8")
        return str(out_path)

    # ── Context builder ───────────────────────────────────────────────────────

    def _build_context(self, r: dict, ai_analysis: str) -> dict:
        recon = r.get("recon", {})
        secret = r.get("secret_scanner", {})
        web   = r.get("webdetect", {})
        ports = r.get("portscan", {})
        tech  = r.get("techstack", {})
        fuzz  = r.get("fuzzer", {})
        cms   = r.get("cmscan", {})
        vuln  = r.get("vulnscan", {})
        cve   = r.get("cve_check", {})
        ssl   = r.get("ssl_checker", {})
        cors  = r.get("cors_checker", {})
        auth  = r.get("auth_probe", {})
        sourcemap = r.get("sourcemap_analyzer", {})
        vhost = r.get("vhost_enum", {})
        takeover = r.get("takeover_checker", {})
        openapi = r.get("openapi_parser", {})
        params = r.get("parameter_discovery", {})
        injection = r.get("injection_probe", {})
        corr = r.get("correlator", {})
        email_security = recon.get("email_security", {}) or {}
        active_probe_sections = [
            ("injection-probe", "Injection Probe Findings", r.get("injection_probe", {})),
            ("http-smuggling", "HTTP Smuggling Findings", r.get("http_smuggling", {})),
            ("oauth-probe", "OAuth / OIDC Findings", r.get("oauth_probe", {})),
            ("cache-poison", "Cache Poisoning Findings", r.get("cache_poison", {})),
            ("host-header-injection", "Host Header Findings", r.get("host_header_injection", {})),
            ("prototype-pollution", "Prototype Pollution Findings", r.get("prototype_pollution", {})),
            ("xxe-probe", "XXE Findings", r.get("xxe_probe", {})),
            ("deserialization-probe", "Deserialization Findings", r.get("deserialization_probe", {})),
            ("graphql-audit", "GraphQL Audit Findings", r.get("graphql_audit", {})),
            ("race-condition", "Race Condition Findings", r.get("race_condition", {})),
            ("open-redirect-probe", "Open Redirect Findings", r.get("open_redirect_probe", {})),
            ("api-key-validator", "API Key Validation Findings", r.get("api_key_validator", {})),
            ("idor-probe", "IDOR / BOLA Findings", r.get("idor_probe", {})),
            ("jwt-audit", "JWT Audit Findings", r.get("jwt_audit", {})),
            ("websocket-probe", "WebSocket Findings", r.get("websocket_probe", {})),
            ("api-schema-audit", "OpenAPI Schema Audit Findings", r.get("api_schema_audit", {})),
            ("js-security-audit", "JavaScript Security Findings", r.get("js_security_audit", {})),
        ]
        active_probe_total = sum(
            module.get("total", len(module.get("findings", [])))
            for _, _, module in active_probe_sections
        )
        extra_finding_sections = [
            ("secret-scanner", "Git Secret Findings", secret.get("findings", [])),
            ("fuzzer-findings", "Fuzzer Findings", fuzz.get("findings", [])),
            ("email-security", "Email DNS Security", email_security.get("findings", [])),
            ("cors", "CORS Findings", cors.get("findings", [])),
            ("auth", "Auth Findings", auth.get("findings", [])),
            ("sourcemaps", "Source Map Findings", sourcemap.get("findings", [])),
            ("takeover", "Subdomain Takeover Candidates", takeover.get("findings", [])),
            ("correlator", "Cross-Finding Correlation", corr.get("findings", [])),
        ]
        finding_filter_modules = []
        if vuln.get("findings"):
            finding_filter_modules.append(("vulnscan", "Nuclei"))
        finding_filter_modules.extend(
            (section_id, title)
            for section_id, title, findings in extra_finding_sections
            if findings
        )
        finding_filter_modules.extend(
            (section_id, title)
            for section_id, title, module in active_probe_sections
            if module.get("findings")
        )
        all_findings_count = len(vuln.get("findings", [])) + sum(
            len(findings) for _, _, findings in extra_finding_sections
        ) + sum(
            len(module.get("findings", [])) for _, _, module in active_probe_sections
        )

        # Ensure by_severity exists
        if "by_severity" not in vuln:
            by_sev: dict[str, int] = {}
            for f in vuln.get("findings", []):
                sev = f.get("severity", "INFO").upper()
                by_sev[sev] = by_sev.get(sev, 0) + 1
            vuln["by_severity"] = by_sev

        # Ensure total exists
        if "total" not in vuln:
            vuln["total"] = len(vuln.get("findings", []))

        cve.setdefault("summary", {})
        cve.setdefault("cves", [])
        cve.setdefault("technology_matches", [])

        summary = {
            "subdomains":      recon.get("subdomains_total", 0),
            "live_hosts":      len(web.get("live_urls") or recon.get("live_http", [])),
            "resolved_ips":    len(recon.get("resolved_ips", [])),
            "open_ports":      ports.get("summary", {}).get("total_open_ports", 0),
            "technologies":    len(tech.get("technologies_summary", {})),
            "endpoints":       fuzz.get("total_endpoints", 0),
            "vulnerabilities": vuln.get("total", 0),
            "cves":            cve.get("summary", {}).get("total_cves", 0),
            "exploitdb":        cve.get("summary", {}).get("with_exploitdb", 0),
            "js_secrets":      fuzz.get("js_secrets_count", 0),
            "cors_findings":   cors.get("total", len(cors.get("findings", []))),
            "auth_findings":   auth.get("total", len(auth.get("findings", []))),
            "email_findings":  len(email_security.get("findings", [])),
            "secret_findings": secret.get("total", len(secret.get("findings", []))),
            "injection_findings": injection.get("total", len(injection.get("findings", []))),
            "active_probe_findings": active_probe_total,
            "takeover_findings": takeover.get("total", len(takeover.get("findings", []))),
            "parameters":      params.get("total", 0),
            "correlated":      corr.get("total", 0),
            "screenshots":     len(web.get("screenshots", [])),
        }

        # Render AI analysis from Markdown to HTML
        ai_html = ""
        if ai_analysis:
            ai_html = self._render_markdown(ai_analysis)

        return {
            "target":      self.target,
            "date":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration":    self.duration,
            "recon":       recon,
            "secret":      secret,
            "web":         web,
            "ports":       ports,
            "tech":        tech,
            "fuzz":        fuzz,
            "cms":         cms,
            "vuln":        vuln,
            "cve":         cve,
            "ssl":         ssl,
            "cors":        cors,
            "auth":        auth,
            "sourcemap":   sourcemap,
            "vhost":       vhost,
            "takeover":    takeover,
            "openapi":     openapi,
            "params":      params,
            "injection":   injection,
            "corr":        corr,
            "email_security": email_security,
            "extra_finding_sections": extra_finding_sections,
            "active_probe_sections": active_probe_sections,
            "finding_filter_modules": finding_filter_modules,
            "all_findings_count": all_findings_count,
            "diff":        r.get("diff", {}),
            "ai_analysis": ai_html,
            "summary":     summary,
        }

    @staticmethod
    def _render_markdown(text: str) -> str:
        """Convert markdown text to HTML. Falls back to <pre> if markdown lib is missing."""
        if HAS_MARKDOWN:
            rendered = markdown.markdown(
                text,
                extensions=["tables", "fenced_code", "nl2br", "sane_lists"],
            )
        else:
            rendered = f"<pre>{html.escape(text)}</pre>"

        if HAS_BLEACH:
            return bleach.clean(
                rendered,
                tags=ALLOWED_TAGS,
                attributes=ALLOWED_ATTRS,
                protocols=["http", "https", "mailto"],
                strip=True,
            )
        return html.escape(rendered)
