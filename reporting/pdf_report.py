"""
pdf_report.py — PDF Generation from HTML report via WeasyPrint
"""
from pathlib import Path


def generate_pdf(html_path: str) -> str:
    """
    Convert HTML report to PDF.
    Returns path to generated PDF, or empty string on failure.
    """
    pdf_path = str(html_path).replace(".html", ".pdf")
    try:
        from weasyprint import HTML, CSS
        HTML(filename=html_path).write_pdf(
            pdf_path,
            stylesheets=[CSS(string="@page { margin: 1cm; }")]
        )
        return pdf_path
    except ImportError:
        print("[!] weasyprint not installed — PDF skipped")
        print("    pip install weasyprint")
        return ""
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        return ""
