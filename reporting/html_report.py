"""
ReconX — HTML Report Generator
Renders templates/report.html via Jinja2 with full scan results.
AI analysis is rendered from Markdown to HTML for proper formatting.
"""

import base64
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
        html_content = template.render(**ctx)

        out_path = self.output_dir / "report.html"
        out_path.write_text(html_content, encoding="utf-8")
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
        asset_risk = r.get("asset_risk", {})
        email_security = recon.get("email_security", {}) or {}
        active_probe_sections = [
            ("injection-probe", "Injection Probe Findings", r.get("injection_probe", {})),
            ("xss", "XSS Findings", r.get("xss", {})),
            ("sql-injection", "SQL Injection Findings", r.get("sql_injection", {})),
            ("http-smuggling", "HTTP Smuggling Findings", r.get("http_smuggling", {})),
            ("oauth-probe", "OAuth / OIDC Findings", r.get("oauth_probe", {})),
            ("cache-poison", "Cache Poisoning Findings", r.get("cache_poison", {})),
            ("host-header-injection", "Host Header Findings", r.get("host_header_injection", {})),
            ("prototype-pollution", "Prototype Pollution Findings", r.get("prototype_pollution", {})),
            ("xxe-probe", "XXE Findings", r.get("xxe_probe", {})),
            ("deserialization-probe", "Deserialization Findings", r.get("deserialization_probe", {})),
            ("race-condition", "Race Condition Findings", r.get("race_condition", {})),
            ("open-redirect-probe", "Open Redirect Findings", r.get("open_redirect_probe", {})),
            ("api-key-validator", "API Key Validation Findings", r.get("api_key_validator", {})),
            ("idor-probe", "IDOR / BOLA Findings", r.get("idor_probe", {})),
            ("jwt-audit", "JWT Audit Findings", r.get("jwt_audit", {})),
            ("websocket-probe", "WebSocket Findings", r.get("websocket_probe", {})),
            ("api-schema-audit", "OpenAPI Schema Audit Findings", r.get("api_schema_audit", {})),
            ("js-security-audit", "JavaScript Security Findings", r.get("js_security_audit", {})),
        ]
        extra_finding_sections = [
            ("secret-scanner", "Git Secret Findings", secret.get("findings", [])),
            ("fuzzer-findings", "Fuzzer Findings", fuzz.get("findings", [])),
            ("endpoint-harvester", "Endpoint Harvester Findings",
             r.get("endpoint_harvester", {}).get("findings", [])),
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
        all_findings = self._collect_all_findings(
            vuln,
            cms,
            cve,
            extra_finding_sections,
            active_probe_sections,
        )
        severity_counts = self._all_finding_severity_counts(
            vuln,
            cms,
            cve,
            extra_finding_sections,
            active_probe_sections,
        )
        verdict_counts = self._all_finding_verdict_counts(
            vuln,
            cms,
            cve,
            extra_finding_sections,
            active_probe_sections,
        )
        active_probe_total = sum(
            module.get("total", len(module.get("findings", [])))
            for _, _, module in active_probe_sections
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

        recon_coverage = self._build_recon_coverage(recon)

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
            "screenshots":     len(web.get("screenshots", [])) + recon_coverage["screenshots"],
            "finding_severity": severity_counts,
            "verdict_counts":  verdict_counts,
            "risk_level":      self._risk_level(severity_counts),
            "sibling_domains":   recon_coverage["sibling_domains"],
            "cloud_bucket_hits": recon_coverage["cloud_bucket_hits"],
            "cloud_bucket_listable": recon_coverage["cloud_bucket_listable"],
            "origin_candidates": recon_coverage["origin_candidates"],
            "cert_san_groups":   recon_coverage["cert_san_groups"],
            "cert_san_new_subs": recon_coverage["cert_san_new_subs"],
            "well_known_urls":   recon_coverage["well_known_urls"],
            "asset_graph_nodes": recon_coverage["asset_graph_nodes"],
        }

        # Render AI analysis from Markdown to HTML
        ai_html = ""
        if ai_analysis:
            ai_html = self._render_markdown(ai_analysis)

        # Embed screenshots as base64 for portable HTML
        screenshots_b64 = self._embed_screenshots(web.get("screenshots", []))
        recon_shots = recon.get("screenshots", {}) or {}
        if recon_shots.get("files"):
            shot_dir = Path(recon_shots.get("directory", "")) if recon_shots.get("directory") else None
            if shot_dir and shot_dir.exists():
                recon_paths = [str(shot_dir / name) for name in recon_shots["files"]]
                screenshots_b64 = screenshots_b64 + self._embed_screenshots(recon_paths)
        interesting_screenshots_b64 = self._embed_screenshots(
            fuzz.get("interesting_screenshots", [])
        )

        # Build finding descriptions from registry
        finding_descriptions = self._build_finding_descriptions(r)

        # Generate static AI fallback if AI analysis is empty
        static_analysis = ""
        if not ai_html:
            static_analysis = self._build_static_analysis(r, summary)

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
            "asset_risk":  asset_risk,
            "email_security": email_security,
            "recon_coverage": recon_coverage,
            "extra_finding_sections": extra_finding_sections,
            "active_probe_sections": active_probe_sections,
            "finding_filter_modules": finding_filter_modules,
            "all_findings_count": all_findings_count,
            "all_findings": all_findings,
            "diff":        r.get("diff", {}),
            "ai_analysis": ai_html,
            "static_analysis": static_analysis,
            "summary":     summary,
            "screenshots_b64": screenshots_b64,
            "interesting_screenshots_b64": interesting_screenshots_b64,
            "finding_descriptions": finding_descriptions,
        }

    # Severity order for sorting (higher number = more important)
    _SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    @classmethod
    def _collect_all_findings(
        cls,
        vuln: dict,
        cms: dict,
        cve: dict,
        extra_finding_sections: list,
        active_probe_sections: list,
    ) -> list:
        """Flatten every finding across modules into a single list sorted by severity
        (CRITICAL → INFO) then by confidence descending.

        Each entry has a stable shape consumed by the All Findings section in the
        HTML template:
            {module, module_label, anchor, title, severity, severity_rank,
             url, confidence, verdict, evidence_excerpt, raw}
        """
        flat: list[dict] = []

        def push(module_id: str, module_label: str, anchor: str, finding: dict) -> None:
            if not isinstance(finding, dict):
                return
            sev = str(finding.get("severity", "INFO") or "INFO").upper()
            if sev not in cls._SEVERITY_RANK:
                sev = "INFO"
            title = (
                finding.get("title")
                or finding.get("name")
                or finding.get("id")
                or finding.get("rule")
                or "Untitled finding"
            )
            url = finding.get("url") or finding.get("matched_url") or ""
            confidence = finding.get("confidence")
            try:
                confidence_num = float(confidence) if confidence is not None else None
            except (TypeError, ValueError):
                confidence_num = None
            verdict = finding.get("verdict") or ""
            flat.append({
                "module": module_id,
                "module_label": module_label,
                "anchor": anchor,
                "id": str(finding.get("id", "") or ""),
                "title": str(title)[:240],
                "severity": sev,
                "severity_rank": cls._SEVERITY_RANK[sev],
                "url": str(url)[:300],
                "confidence": confidence_num,
                "verdict": str(verdict),
                "evidence_excerpt": cls._evidence_excerpt(finding.get("evidence")),
                "tags": finding.get("tags") or [],
            })

        # Vulnscan
        for finding in vuln.get("findings", []) or []:
            push("vulnscan", "Nuclei", "vulns", finding)

        # Extra sections (already paired with their anchor + label)
        for anchor, label, findings in extra_finding_sections:
            for finding in findings or []:
                push(anchor, label, anchor, finding)

        # Active probe sections (module dicts)
        for anchor, label, module in active_probe_sections:
            for finding in module.get("findings", []) or []:
                push(anchor, label, anchor, finding)

        # CMS scans
        for scan in cms.get("scans", []) or []:
            cms_name = scan.get("cms", "cmscan")
            for finding in scan.get("findings", []) or []:
                push("cmscan", f"CMS ({cms_name})", "cms", finding)

        # CVE / ExploitDB correlation
        for finding in cve.get("cves", []) or []:
            push("cve_check", "CVE / ExploitDB", "cve", finding)

        flat.sort(
            key=lambda item: (
                -item["severity_rank"],
                -(item["confidence"] if item["confidence"] is not None else -1),
                item["module"],
                item["title"],
            )
        )
        return flat

    @staticmethod
    def _evidence_excerpt(evidence) -> str:
        """Short single-line evidence summary for the All Findings table."""
        if not evidence:
            return ""
        if isinstance(evidence, str):
            text = evidence
        elif isinstance(evidence, dict):
            # Prefer the most informative field if present
            for key in (
                "excerpt", "body_excerpt", "snippet", "match", "description",
                "payload", "header", "param", "rule", "file",
            ):
                value = evidence.get(key)
                if value:
                    text = f"{key}={value}"
                    break
            else:
                try:
                    text = json.dumps(evidence, default=str, ensure_ascii=False)
                except Exception:
                    text = str(evidence)
        else:
            text = str(evidence)
        text = " ".join(str(text).split())
        return text[:200]

    @staticmethod
    def _all_finding_severity_counts(
        vuln: dict,
        cms: dict,
        cve: dict,
        extra_finding_sections: list,
        active_probe_sections: list,
    ) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        def add_finding(finding: dict) -> None:
            sev = str(finding.get("severity", "INFO") or "INFO").upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1

        for finding in vuln.get("findings", []) or []:
            add_finding(finding)
        if not vuln.get("findings"):
            for sev, count in (vuln.get("by_severity", {}) or {}).items():
                sev = str(sev or "INFO").upper()
                if sev in counts:
                    counts[sev] += int(count or 0)

        for _, _, findings in extra_finding_sections:
            for finding in findings or []:
                add_finding(finding)

        for _, _, module in active_probe_sections:
            for finding in module.get("findings", []) or []:
                add_finding(finding)

        for scan in cms.get("scans", []) or []:
            for finding in scan.get("findings", []) or []:
                add_finding(finding)

        for finding in cve.get("cves", []) or []:
            add_finding(finding)

        return counts

    @staticmethod
    def _all_finding_verdict_counts(
        vuln: dict,
        cms: dict,
        cve: dict,
        extra_finding_sections: list,
        active_probe_sections: list,
    ) -> dict:
        from modules.finding_registry import (
            VERDICT_CONFIRMED, VERDICT_CANDIDATE, VERDICT_REVIEW, verdict_for,
        )

        counts = {VERDICT_CONFIRMED: 0, VERDICT_CANDIDATE: 0, VERDICT_REVIEW: 0}

        def add(finding: dict) -> None:
            v = finding.get("verdict")
            if v not in counts:
                v = verdict_for(
                    finding.get("exploitability", "candidate"),
                    finding.get("evidence", {}),
                    finding.get("confidence", 0.75),
                )
            counts[v] = counts.get(v, 0) + 1

        for finding in vuln.get("findings", []) or []:
            add(finding)
        for _, _, findings in extra_finding_sections:
            for f in findings or []:
                add(f)
        for _, _, module in active_probe_sections:
            for f in module.get("findings", []) or []:
                add(f)
        for scan in cms.get("scans", []) or []:
            for f in scan.get("findings", []) or []:
                add(f)
        for f in cve.get("cves", []) or []:
            add(f)
        return counts

    @staticmethod
    def _build_recon_coverage(recon: dict) -> dict:
        """Extract compact stats + lists from new recon fields for the template."""
        siblings = (recon.get("reverse_whois") or {}).get("sibling_domains") or {}
        cloud = recon.get("cloud_buckets") or {}
        cloud_by_provider = (cloud.get("by_provider") or {}) if isinstance(cloud, dict) else {}
        cloud_flat: list[dict] = []
        for provider, hits in cloud_by_provider.items():
            for hit in (hits or []):
                cloud_flat.append({**hit, "provider": provider})
        cloud_listable = sum(1 for h in cloud_flat if h.get("status") == "listable")

        origin = recon.get("origin_discovery") or {}
        origin_candidates = origin.get("origin_candidates") or []

        cert_sans = recon.get("cert_sans") or {}
        cert_groups = cert_sans.get("groups") or []
        cert_new_subs = cert_sans.get("new_subdomains") or []
        cert_sibling_doms = cert_sans.get("sibling_domains") or []

        well_known_urls = (recon.get("urls") or {}).get("all_urls") or []

        asset_summary = recon.get("asset_graph_summary") or {}

        recon_shots = recon.get("screenshots") or {}
        recon_shot_count = int(recon_shots.get("count", 0)) if isinstance(recon_shots, dict) else 0

        sibling_items_list = (
            sorted(siblings.items())[:60] if isinstance(siblings, dict) else []
        )

        return {
            "sibling_domains": len(siblings),
            "sibling_domain_items": sibling_items_list,
            "cloud_bucket_hits": int(cloud.get("total_hits", len(cloud_flat))),
            "cloud_bucket_listable": cloud_listable,
            "cloud_bucket_items": cloud_flat[:80],
            "origin_candidates": len(origin_candidates),
            "origin_items": origin_candidates[:60],
            "origin_cdn_fronted": len(origin.get("cdn_fronted_hosts") or []),
            "cert_san_groups": len(cert_groups),
            "cert_san_items": cert_groups[:30],
            "cert_san_new_subs": len(cert_new_subs),
            "cert_san_siblings": cert_sibling_doms[:30],
            "well_known_urls": len(well_known_urls),
            "asset_graph_nodes": int(asset_summary.get("node_count", 0)),
            "asset_graph_summary": asset_summary,
            "screenshots": recon_shot_count,
        }

    @staticmethod
    def _risk_level(severity_counts: dict) -> str:
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if severity_counts.get("HIGH", 0) > 0:
            return "HIGH"
        if severity_counts.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        return "LOW"

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
        # Return rendered HTML directly — do NOT call html.escape() here because
        # `rendered` already contains HTML tags produced by the markdown library
        # (or the <pre>…</pre> fallback). Escaping would double-encode all tags.
        return rendered

    def _embed_screenshots(self, screenshots: list) -> list:
        """Convert screenshot file paths to base64 data URIs."""
        result = []
        for shot in (screenshots or [])[:80]:
            path_str = shot.get("path", "")
            if not path_str:
                rel = shot.get("relative_path", "")
                if rel:
                    path_str = str(self.output_dir / rel)
            from pathlib import Path as P
            path = P(path_str)
            if path.exists() and path.stat().st_size > 0:
                try:
                    data = base64.b64encode(path.read_bytes()).decode("ascii")
                    ext = path.suffix.lower().lstrip(".")
                    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                            "webp": "image/webp", "gif": "image/gif"}.get(ext, "image/png")
                    entry = {
                        "data_uri": f"data:{mime};base64,{data}",
                        "url": shot.get("url", shot.get("filename", "")),
                        "filename": shot.get("filename", path.name),
                    }
                    if shot.get("categories"):
                        entry["categories"] = shot["categories"]
                    result.append(entry)
                except Exception:
                    continue
        return result

    @staticmethod
    def _build_finding_descriptions(r: dict) -> dict:
        """Build human-readable descriptions for common finding types.

        Each entry has four fields:
          * title       — human label
          * impact      — what an attacker can do with the issue
          * detection   — how ReconX evaluates / detects the issue and how
                          confidence and severity are assigned
          * remediation — what to do about it
        """
        return {
            "xss": {"title": "Cross-Site Scripting (XSS)", "impact": "Attackers can inject malicious scripts into web pages viewed by other users, potentially stealing session cookies, credentials, or performing actions on behalf of the victim.", "detection": "Reflection probes inject context-aware markers into each discovered parameter and re-render the response. When dalfox confirms an executable payload the finding is upgraded to HIGH with confidence 0.90; pure reflections without a working sink stay LOW.", "remediation": "Encode all user-controlled output. Use Content-Security-Policy headers. Validate and sanitize input."},
            "sql_injection": {"title": "SQL Injection", "impact": "Attackers can manipulate database queries to read, modify, or delete data. May lead to full database compromise, authentication bypass, or remote code execution.", "detection": "sqlmap is run in --batch mode against parameters surfaced by parameter_discovery and fuzzer. A finding is emitted only when sqlmap prints an explicit injection point, so severity is fixed at HIGH with confidence 0.9.", "remediation": "Use parameterized queries/prepared statements. Apply input validation. Use least-privilege database accounts."},
            "injection_probe": {"title": "Server-Side Injection (SSTI/SSRF)", "impact": "Attackers can execute arbitrary code on the server (SSTI) or make the server send requests to internal services (SSRF), potentially accessing internal networks.", "detection": "Out-of-band markers and template tokens are sent through each parameter. SSTI is confirmed when an arithmetic payload renders the computed value; SSRF requires either an OOB callback or a known-private IP echo before being raised above LOW.", "remediation": "Sanitize template inputs. Restrict outbound network access. Use allowlists for URL parameters."},
            "cors_checker": {"title": "CORS Misconfiguration", "impact": "Overly permissive CORS policies can allow malicious websites to make authenticated requests to the application, stealing sensitive data.", "detection": "Each live URL is probed with five untrusted Origin headers. Reflection of the attacker origin with Access-Control-Allow-Credentials: true is CRITICAL; plain reflections or null-origin acceptance are HIGH; wildcard ACAO without credentials is MEDIUM.", "remediation": "Restrict Access-Control-Allow-Origin to trusted domains. Avoid wildcard origins with credentials."},
            "auth_probe": {"title": "Authentication/Authorization Issues", "impact": "Weak authentication configurations can allow unauthorized access, session hijacking, or privilege escalation.", "detection": "Session cookies are inspected for HttpOnly / Secure / SameSite flags and login forms are checked for CSRF token presence. Severity scales with how directly the flag relates to session theft (missing HttpOnly + Secure on a session cookie → HIGH).", "remediation": "Implement secure session management. Use HttpOnly and Secure cookie flags. Enforce strong password policies."},
            "ssl_checker": {"title": "SSL/TLS & Security Headers", "impact": "Weak SSL configurations or missing security headers can expose users to man-in-the-middle attacks, clickjacking, and XSS.", "detection": "testssl.sh (or its built-in fallback) is parsed for protocol/cipher weaknesses and HSTS/CSP/X-Frame-Options presence. Severity follows the canonical mapping (e.g. SSLv3/weak ciphers → HIGH, missing HSTS → MEDIUM).", "remediation": "Use TLS 1.2+. Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers."},
            "prototype_pollution": {"title": "Prototype Pollution", "impact": "Attackers can modify JavaScript object prototypes, potentially leading to property injection, denial of service, or remote code execution.", "detection": "Query and JSON payloads add __proto__/constructor.prototype keys; the response is then inspected for the injected marker on the global Object. A confirmed reflection promotes the finding to HIGH; otherwise it stays an INFO candidate.", "remediation": "Use Object.create(null) for maps. Validate and sanitize user input. Use __proto__ pollution prevention libraries."},
            "http_smuggling": {"title": "HTTP Request Smuggling", "impact": "Attackers can bypass security controls, access unauthorized content, or poison web caches by exploiting discrepancies in HTTP request parsing.", "detection": "Raw sockets send CL.TE / TE.CL / TE.TE payloads and compare response times against a configured threshold. A measurable timing delta on a smuggling variant raises a HIGH finding with timing evidence attached.", "remediation": "Use HTTP/2 end-to-end. Normalize Transfer-Encoding handling. Ensure consistent parsing across proxy layers."},
            "open_redirect_probe": {"title": "Open Redirect", "impact": "Attackers can redirect users to malicious websites for phishing or malware delivery while the URL appears legitimate.", "detection": "Redirect parameters are replaced with attacker-controlled URLs; a 30x Location header pointing to the attacker origin is required before a finding is emitted (MEDIUM by default).", "remediation": "Validate redirect URLs against an allowlist. Avoid using user input directly in redirects."},
            "jwt_audit": {"title": "JWT Security Issues", "impact": "Weak JWT configurations can allow token forgery, authentication bypass, or privilege escalation.", "detection": "Discovered JWTs are decoded; a wordlist-based HMAC crack is attempted and `alg: none`/`alg: HS256` confusion is checked. A successful crack or none-algorithm acceptance is CRITICAL; missing exp/aud claims are MEDIUM.", "remediation": "Use strong signing algorithms (RS256/ES256). Validate all claims. Set appropriate expiration times."},
            "idor_probe": {"title": "Insecure Direct Object Reference (IDOR)", "impact": "Attackers can access or modify resources belonging to other users by manipulating object identifiers in API requests.", "detection": "Numeric/UUID identifiers in endpoints are swapped between configured auth profiles. A 200 response with different content for the other tenant's ID confirms IDOR and produces a HIGH finding.", "remediation": "Implement proper authorization checks. Use indirect references. Validate user permissions server-side."},
            "secret_scanner": {"title": "Exposed Secrets in Git Repositories", "impact": "API keys, passwords, and tokens leaked in source code can provide direct access to backend services and cloud infrastructure.", "detection": "trufflehog/gitleaks scan the repository plus dependency manifests; high-entropy strings matching well-known token shapes (AWS, GitHub, Stripe, …) are flagged. Confidence inherits from the upstream tool's verifier (verified secrets → HIGH).", "remediation": "Rotate all exposed credentials immediately. Use environment variables or secret managers. Add .gitignore rules."},
            "takeover_checker": {"title": "Subdomain Takeover", "impact": "Unclaimed subdomains pointing to expired services can be taken over by attackers to host malicious content under the organization's domain.", "detection": "CNAMEs are matched against a provider fingerprint list; the target page body is compared to the provider's 'not configured' banner. CNAME + body fingerprint match → HIGH; CNAME-only is LOW.", "remediation": "Remove stale DNS records. Monitor subdomain health. Claim or decommission unused services."},
        }

    @staticmethod
    def _build_static_analysis(r: dict, summary: dict) -> str:
        """Generate a deterministic analysis when AI is unavailable."""
        lines = []
        risk = summary.get("risk_level", "LOW")
        sev = summary.get("finding_severity", {})
        total_findings = sum(sev.values())

        # Executive Summary
        lines.append("<h2>Executive Summary</h2>")
        if risk == "CRITICAL":
            lines.append(f"<p>The automated scan identified <strong>{total_findings} findings</strong> including <strong style='color:var(--red)'>{sev.get('CRITICAL',0)} critical</strong> issues. Immediate remediation is required. Security grade: <strong>F</strong>.</p>")
        elif risk == "HIGH":
            lines.append(f"<p>The scan found <strong>{total_findings} findings</strong> with <strong style='color:var(--amber)'>{sev.get('HIGH',0)} high-severity</strong> issues requiring prompt attention. Security grade: <strong>D</strong>.</p>")
        elif risk == "MEDIUM":
            lines.append(f"<p>The scan found <strong>{total_findings} findings</strong> with <strong>{sev.get('MEDIUM',0)} medium-severity</strong> issues. Security grade: <strong>C</strong>.</p>")
        else:
            lines.append(f"<p>The scan found <strong>{total_findings} findings</strong>. No critical or high-risk issues were confirmed. Security grade: <strong>B</strong>.</p>")

        # Key Metrics
        lines.append("<h2>Attack Surface Overview</h2><ul>")
        lines.append(f"<li><strong>{summary.get('subdomains',0)}</strong> subdomains discovered</li>")
        lines.append(f"<li><strong>{summary.get('live_hosts',0)}</strong> live HTTP hosts</li>")
        lines.append(f"<li><strong>{summary.get('open_ports',0)}</strong> open ports</li>")
        lines.append(f"<li><strong>{summary.get('technologies',0)}</strong> technologies detected</li>")
        lines.append(f"<li><strong>{summary.get('endpoints',0)}</strong> endpoints discovered</li>")
        lines.append("</ul>")

        # Findings by severity
        if total_findings > 0:
            lines.append("<h2>Findings Breakdown</h2><ul>")
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = sev.get(s, 0)
                if count > 0:
                    lines.append(f"<li><strong>{s}</strong>: {count} finding(s)</li>")
            lines.append("</ul>")

        # Remediation priorities
        lines.append("<h2>Recommended Actions</h2><ol>")
        if sev.get("CRITICAL", 0) > 0:
            lines.append("<li><strong>Critical:</strong> Address all critical findings immediately — these represent actively exploitable vulnerabilities.</li>")
        if sev.get("HIGH", 0) > 0:
            lines.append("<li><strong>High:</strong> Remediate high-severity findings within the current sprint.</li>")
        if sev.get("MEDIUM", 0) > 0:
            lines.append("<li><strong>Medium:</strong> Plan remediation for medium findings in upcoming releases.</li>")
        lines.append("<li>Review and validate all automated findings manually before tracking for remediation.</li>")
        lines.append("<li>Implement missing security headers (CSP, HSTS, X-Frame-Options) across all hosts.</li>")
        lines.append("<li>Conduct periodic re-scans to track remediation progress.</li>")
        lines.append("</ol>")
        lines.append("<p><em>All automated findings should be manually verified before remediation tracking or risk acceptance.</em></p>")

        return "\n".join(lines)
