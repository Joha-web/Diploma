"""
ReconX — HTML Report Generator
Renders templates/report.html via Jinja2 with full scan results.
AI analysis is rendered from Markdown to HTML for proper formatting.
"""

import json
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False


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
        ports = r.get("portscan", {})
        tech  = r.get("techstack", {})
        fuzz  = r.get("fuzzer", {})
        cms   = r.get("cmscan", {})
        vuln  = r.get("vulnscan", {})
        ssl   = r.get("ssl_checker", {})

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

        summary = {
            "subdomains":      recon.get("subdomains_total", 0),
            "live_hosts":      len(recon.get("live_http", [])),
            "resolved_ips":    len(recon.get("resolved_ips", [])),
            "open_ports":      ports.get("summary", {}).get("total_open_ports", 0),
            "technologies":    len(tech.get("technologies_summary", {})),
            "endpoints":       fuzz.get("total_endpoints", 0),
            "vulnerabilities": vuln.get("total", 0),
            "js_secrets":      fuzz.get("js_secrets_count", 0),
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
            "ports":       ports,
            "tech":        tech,
            "fuzz":        fuzz,
            "cms":         cms,
            "vuln":        vuln,
            "ssl":         ssl,
            "ai_analysis": ai_html,
            "summary":     summary,
        }

    @staticmethod
    def _render_markdown(text: str) -> str:
        """Convert markdown text to HTML. Falls back to <pre> if markdown lib is missing."""
        if HAS_MARKDOWN:
            return markdown.markdown(
                text,
                extensions=["tables", "fenced_code", "nl2br", "sane_lists"],
            )
        # Fallback: wrap in <pre> for basic readability
        return f"<pre>{text}</pre>"
