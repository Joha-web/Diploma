"""
pdf_report.py — PDF Generation from HTML report via WeasyPrint
"""
import subprocess
import shutil
from pathlib import Path


def generate_pdf(html_path: str) -> str:
    """
    Convert HTML report to PDF.
    Returns path to generated PDF, or empty string on failure.
    """
    pdf_path = str(html_path).replace(".html", ".pdf")
    html_file = Path(html_path).resolve()
    weasy_error = ""
    try:
        from weasyprint import HTML, CSS
        HTML(filename=html_path).write_pdf(
            pdf_path,
            stylesheets=[CSS(string="@page { margin: 1cm; }")]
        )
        return pdf_path
    except ImportError:
        weasy_error = "weasyprint not installed"
    except Exception as e:
        weasy_error = str(e)

    fallback = _generate_with_project_venv(html_file, Path(pdf_path))
    if fallback:
        return fallback

    fallback = _generate_with_chromium(html_file, Path(pdf_path))
    if fallback:
        return fallback

    print(f"[!] PDF generation failed: {weasy_error}")
    return ""


def _generate_with_project_venv(html_path: Path, pdf_path: Path) -> str:
    """Try the project's virtualenv when the system WeasyPrint stack is broken."""
    python_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python"
    if not python_bin.exists():
        return ""

    code = (
        "import sys; "
        "from weasyprint import HTML, CSS; "
        "HTML(filename=sys.argv[1]).write_pdf("
        "sys.argv[2], stylesheets=[CSS(string='@page { margin: 1cm; }')])"
    )
    try:
        result = subprocess.run(
            [str(python_bin), "-c", code, str(html_path), str(pdf_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return ""

    if result.returncode == 0 and pdf_path.exists() and pdf_path.stat().st_size > 0:
        return str(pdf_path)
    return ""


def _generate_with_chromium(html_path: Path, pdf_path: Path) -> str:
    """Fallback PDF renderer for environments with broken WeasyPrint deps."""
    chromium = (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
    )
    if not chromium:
        print("[!] Chromium fallback not available — PDF skipped")
        return ""

    try:
        result = subprocess.run(
            [
                chromium,
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-crash-reporter",
                "--disable-crashpad",
                "--no-first-run",
                "--user-data-dir=/tmp/reconx-chromium-pdf",
                f"--print-to-pdf={pdf_path}",
                html_path.as_uri(),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as e:
        print(f"[!] Chromium PDF fallback failed: {e}")
        return ""

    if result.returncode == 0 and pdf_path.exists() and pdf_path.stat().st_size > 0:
        return str(pdf_path)

    print(f"[!] Chromium PDF fallback failed: {result.stderr[:200]}")
    return ""
