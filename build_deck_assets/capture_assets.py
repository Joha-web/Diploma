"""Capture screenshots and mock-ups used in the diploma defense deck.

Outputs:
  build_deck_assets/screenshots/
      01_top_risk_assets.png       - Top Risk Assets table from report.html
      02_all_findings.png          - All Findings section
      03_live_subdomains.png       - Live Subdomains section
      04_telegram_summary.png      - Mock Telegram bot notify_complete card
      05_ai_analysis.png           - Rendered AI analysis (cropped)
      06_html_overview.png         - Full report overview header + KPIs
"""

from pathlib import Path
import subprocess
import shutil
import re

ROOT = Path("/home/kali/Desktop/Diploma-pre-defend/reconx")
RUN  = ROOT / "output/20-05-2026_miras.app"
OUT  = ROOT / "build_deck_assets/screenshots"
OUT.mkdir(parents=True, exist_ok=True)


def chromium_shot(url: str, out_path: Path, width: int = 1400, height: int = 900,
                  wait_ms: int = 800):
    """Take a viewport screenshot of a URL using headless Chromium."""
    subprocess.run(
        [
            "chromium",
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--hide-scrollbars",
            f"--window-size={width},{height}",
            f"--virtual-time-budget={wait_ms}",
            f"--screenshot={out_path}",
            url,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ── Cropped section captures via temp HTML wrappers ──────────────────────────
def render_section(html_text: str, section_id: str, out_path: Path,
                   width: int = 1400, height: int = 900,
                   extra_css: str = ""):
    """Extract a section by id from the full report.html, wrap it in its own
    HTML doc that reuses the inline <style>, and screenshot only that page."""
    # 1. extract the <style> block
    style_m = re.search(r"<style[^>]*>(.*?)</style>", html_text, re.S | re.I)
    style = style_m.group(0) if style_m else ""

    # 2. extract the section — slice from this section to the next HTML comment
    # marker. Falls back to slicing to the next <div class="section".
    sec_re = re.compile(
        rf'<div class="section[^"]*"\s+id="{section_id}".*?(?=<!--\s*[A-Z])',
        re.S,
    )
    m = sec_re.search(html_text)
    if not m:
        sec_re = re.compile(
            rf'<div class="section[^"]*"\s+id="{section_id}".*?(?=<div class="section)',
            re.S,
        )
        m = sec_re.search(html_text)
    if not m:
        print(f"  ✗ section {section_id} not found")
        return False
    block = m.group(0)

    page = f"""<!doctype html><html><head><meta charset="utf-8">
{style}
<style>
body {{ background: #06091b; margin: 24px; }}
.main {{ margin: 0; padding: 0; }}
.section {{ margin: 0 !important; }}
{extra_css}
</style></head>
<body><div class="main">{block}</div></body></html>"""
    tmp = out_path.with_suffix(".tmp.html")
    tmp.write_text(page, encoding="utf-8")
    chromium_shot(f"file://{tmp.absolute()}", out_path, width, height)
    tmp.unlink(missing_ok=True)
    return out_path.exists() and out_path.stat().st_size > 1000


def render_html_string(html: str, out_path: Path, width: int = 900, height: int = 800):
    tmp = out_path.with_suffix(".tmp.html")
    tmp.write_text(html, encoding="utf-8")
    chromium_shot(f"file://{tmp.absolute()}", out_path, width, height)
    tmp.unlink(missing_ok=True)
    return out_path.exists() and out_path.stat().st_size > 1000


# ── Sections of report.html ──────────────────────────────────────────────────
report_html = (RUN / "report.html").read_text(encoding="utf-8")

print("→ Top Risk Assets")
render_section(report_html, "asset-risk", OUT / "01_top_risk_assets.png",
               width=1400, height=820)

print("→ All Findings (filter bar + first rows)")
render_section(report_html, "all-findings", OUT / "02_all_findings.png",
               width=1400, height=900)

print("→ Live Subdomains")
render_section(report_html, "live-subdomains", OUT / "03_live_subdomains.png",
               width=1400, height=820)

print("→ Report overview (header + KPI strip)")
# capture the top of the page
overview_doc = f"""<!doctype html><html><head><meta charset="utf-8">
{re.search(r'<style.*?</style>', report_html, re.S).group(0)}
</style></head><body>"""
header_m = re.search(r'<div class="header"[^>]*>.*?</div>\s*</div>', report_html, re.S)
stats_m = re.search(r'<div class="stats">.*?</div>\s*</div>(?=\s*<!--)', report_html, re.S)
overview_doc += '<div class="main">'
if header_m:
    overview_doc += header_m.group(0)
if stats_m:
    overview_doc += stats_m.group(0)
overview_doc += "</div></body></html>"
render_html_string(overview_doc, OUT / "06_html_overview.png",
                   width=1400, height=900)


# ── AI analysis — pick the most recent successful run ────────────────────────
print("→ AI analysis (rendered Markdown)")
ai_candidates = sorted(ROOT.glob("output/*/ai_report/ai_analysis.md"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
ai_text = ""
ai_source = ""
for cand in ai_candidates:
    txt = cand.read_text(encoding="utf-8", errors="replace")
    if len(txt) > 800 and ("Executive Summary" in txt or "Резюме" in txt or "##" in txt):
        ai_text = txt
        ai_source = str(cand)
        break

if ai_text:
    try:
        import markdown as mdlib
        ai_html_body = mdlib.markdown(ai_text, extensions=["tables", "fenced_code", "nl2br"])
    except Exception:
        ai_html_body = "<pre>" + ai_text.replace("<", "&lt;") + "</pre>"

    ai_page = f"""<!doctype html><html><head><meta charset="utf-8">
<style>
body {{
  background:#0b1024; color:#e2e8f0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
  padding: 26px; margin:0;
}}
.card {{
  background:#111a3a; border:1px solid #1f2c5a; border-radius:12px;
  padding: 22px 26px; max-width: 1280px; margin: 0 auto;
  box-shadow: 0 8px 32px rgba(37,99,235,.18);
}}
.card h1, .card h2, .card h3 {{ color:#93c5fd; margin: 18px 0 8px; }}
.card h2 {{ font-size: 18px; border-bottom: 1px solid #1f2c5a; padding-bottom:6px; }}
.card h3 {{ font-size: 14px; }}
.card p, .card li {{ color:#cbd5e1; font-size: 13.5px; line-height:1.55; }}
.card code {{ background:#04070e; color:#67e8f9; padding:1px 6px; border-radius:4px; font-size:12px; }}
.card strong {{ color:#fff; }}
.banner {{
  background: linear-gradient(135deg, #2563eb, #1e3a8a);
  color:#fff; font-weight:700; padding:8px 14px; border-radius: 8px;
  display:inline-block; margin-bottom:14px; font-size:13px;
}}
</style></head>
<body><div class="card">
  <div class="banner">🤖 AI Security Analysis — Ollama / deepseek-r1:7b</div>
  {ai_html_body}
</div></body></html>"""
    render_html_string(ai_page, OUT / "05_ai_analysis.png", width=1400, height=900)
    print(f"   source: {ai_source}")
else:
    print("   no AI analysis found — skipping")


# ── Telegram mock (notify_complete card) ─────────────────────────────────────
print("→ Telegram summary mock-up")
tg_html = """<!doctype html><html><head><meta charset="utf-8">
<style>
body { background:#0e1621; color:#fff; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
       margin:0; padding:40px; }
.chat { max-width:520px; margin: 0 auto; }
.bubble {
  background: #182533; color:#fff; padding:14px 18px; border-radius:14px;
  box-shadow: 0 4px 18px rgba(0,0,0,.4); margin-bottom:14px; font-size:14px;
  line-height:1.55;
}
.bubble .title { color:#5eb9ff; font-weight:700; margin-bottom:6px; }
.bubble code { background:#0e1621; color:#ffb454; padding:1px 6px;
               border-radius:4px; font-size:12.5px; }
.bubble .meta { color:#8aa1bc; font-size:11.5px; margin-top:8px; }
.b-list { margin: 4px 0; padding-left:16px; }
.b-list li { margin: 2px 0; }
.bot-row { display:flex; align-items:center; gap:10px; margin-bottom:8px; color:#5eb9ff; font-weight:700; }
.bot-row .avatar { width:28px; height:28px; border-radius:14px;
                   background:linear-gradient(135deg,#3b82f6,#1e3a8a); display:flex;
                   align-items:center; justify-content:center; font-size:14px; }
.grade { background:linear-gradient(135deg,#16a34a,#0e7c33); padding:8px 12px;
         border-radius:8px; font-weight:700; display:inline-block; margin-top:6px; }
</style></head><body><div class="chat">

<div class="bot-row"><div class="avatar">R</div><span>ReconX Bot</span></div>

<div class="bubble">
  <div class="title">🚀 Сканирование запущено</div>
  Цель: <code>miras.app</code><br>
  Модулей: 40<br>
  Запущено: 22.05.2026 14:02
</div>

<div class="bubble">
  <div class="title">✅ ReconX — Сканирование завершено</div>
  🎯 Цель: <code>miras.app</code><br><br>
  📊 <b>Результаты:</b>
  <ul class="b-list">
    <li>Субдоменов: 49</li>
    <li>Живых хостов: 39</li>
    <li>Открытых портов: 42</li>
    <li>Технологий: 27</li>
    <li>Уязвимостей: 18</li>
    <li>CVE: 4</li>
    <li>Endpoints: 89,673</li>
    <li>JS Secrets: 6</li>
    <li>Время: 1h 14m</li>
  </ul>
  <div class="grade">🛡️ Оценка безопасности: C</div>
  <div class="meta">📎 report.html · report.json · ai_analysis.md</div>
</div>

</div></body></html>"""
render_html_string(tg_html, OUT / "04_telegram_summary.png",
                   width=720, height=900)


# ── Done ──────────────────────────────────────────────────────────────────────
for p in sorted(OUT.glob("*.png")):
    print(f"  ✓ {p.name}  ({p.stat().st_size//1024} KB)")
