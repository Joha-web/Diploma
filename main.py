#!/usr/bin/env python3
"""
ReconX — Automated Web Application Reconnaissance Framework
Usage:
    python3 main.py -t example.com
    python3 main.py -t example.com --modules recon,portscan,vulnscan
    python3 main.py -t example.com --skip cmscan --resume
"""

import argparse
import json
import sys
import time
import importlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule

console = Console()

BANNER = r"""
[bold magenta]
    ____                       _  __
   / __ \___  _________  ____  | |/ /
  / /_/ / _ \/ ___/ __ \/ __ \ |   /
 / _, _/  __/ /__/ /_/ / / / //   |
/_/ |_|\___/\___/\____/_/ /_//_/|_|
                              v1.0.0
[/bold magenta][dim]Red Team · AppSec · Reconnaissance Framework[/dim]
"""

# Pipeline — parallel_group determines execution order.
# Modules in the same group run in parallel threads.
PIPELINE: list[dict] = [
    {"name": "recon",       "group": 1},
    {"name": "portscan",    "group": 2},   # parallel with webdetect
    {"name": "webdetect",   "group": 2},   # parallel with portscan
    {"name": "techstack",   "group": 3},
    {"name": "fuzzer",      "group": 4},   # parallel with ssl_checker
    {"name": "ssl_checker", "group": 4},   # parallel with fuzzer
    {"name": "cmscan",      "group": 5},
    {"name": "vulnscan",    "group": 6},
    {"name": "ai_report",   "group": 7},
]

CLASS_MAP = {
    "recon":       ("modules.recon",        "ReconModule"),
    "portscan":    ("modules.portscan",     "PortScanModule"),
    "webdetect":   ("modules.webdetect",    "WebdetectModule"),
    "techstack":   ("modules.techstack",    "TechStackModule"),
    "fuzzer":      ("modules.fuzzer",       "FuzzerModule"),
    "ssl_checker": ("modules.ssl_checker",  "SSLCheckerModule"),
    "cmscan":      ("modules.cmscan",       "CMSScanModule"),
    "vulnscan":    ("modules.vulnscan",     "VulnScanModule"),
    "ai_report":   ("modules.ai_report",    "AIReportModule"),
}


def _load_cls(name: str):
    mod_path, cls_name = CLASS_MAP[name]
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def _build_kwargs(name: str, all_results: dict) -> dict:
    """Build extra constructor kwargs for each module based on prior results."""
    recon  = all_results.get("recon", {})
    live   = recon.get("live_http", [])
    kwargs: dict = {}
    if name == "portscan":
        kwargs["resolved_ips"] = recon.get("resolved_ips", [])
    elif name in ("webdetect", "techstack", "fuzzer", "ssl_checker", "vulnscan"):
        kwargs["live_hosts"] = live
    elif name == "cmscan":
        kwargs["tech_results"] = all_results.get("techstack", {})
    elif name == "ai_report":
        kwargs["all_results"] = all_results
    return kwargs


# ─── Module runner ────────────────────────────────────────────────────────────

def run_one(
    name: str,
    target: str,
    session_dir: Path,
    config: dict,
    all_results: dict,
    resume: bool,
) -> tuple[str, dict]:
    try:
        Cls = _load_cls(name)
        kwargs = _build_kwargs(name, all_results)
        mod = Cls(target=target, output_dir=str(session_dir), config=config, **kwargs)
        result = mod.execute(resume=resume)
        return name, result
    except Exception as exc:
        import traceback
        console.print(f"[red]✗ Module '{name}' crashed: {exc}[/red]")
        return name, {"status": "crashed", "error": str(exc),
                      "traceback": traceback.format_exc()}


# ─── Pipeline orchestrator ────────────────────────────────────────────────────

def run_pipeline(
    target: str,
    config: dict,
    session_dir: Path,
    active: list[str],
    resume: bool,
) -> dict:
    t0 = time.time()
    all_results: dict = {}
    master_json = session_dir / "all_results.json"

    # On resume — pre-load all cached module results
    if resume and master_json.exists():
        try:
            all_results = json.loads(master_json.read_text(encoding="utf-8"))
            console.print(f"[cyan]Resume: {len(all_results)} cached module(s) loaded[/cyan]\n")
        except Exception:
            pass

    # Build execution groups (preserving PIPELINE order)
    groups: dict[int, list[str]] = {}
    for step in PIPELINE:
        if step["name"] in active:
            groups.setdefault(step["group"], []).append(step["name"])

    for gid in sorted(groups):
        names = groups[gid]

        if len(names) == 1:
            # Sequential
            name, result = run_one(names[0], target, session_dir, config, all_results, resume)
            all_results[name] = result
        else:
            # Parallel — snapshot all_results so threads don't race
            console.print(f"\n[bold cyan]⚡ Running in parallel: {', '.join(names)}[/bold cyan]")
            snapshot = dict(all_results)
            with ThreadPoolExecutor(max_workers=len(names)) as pool:
                futures = {
                    pool.submit(run_one, n, target, session_dir, config, snapshot, resume): n
                    for n in names
                }
                for future in as_completed(futures):
                    n, result = future.result()
                    all_results[n] = result

        # Persist after every group — enables resume on crash
        master_json.write_text(
            json.dumps(all_results, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    # ── Reports ───────────────────────────────────────────────────────────────
    elapsed = _fmt_elapsed(time.time() - t0)
    console.print(Rule("[bold magenta]Generating reports[/bold magenta]"))

    ai_text = all_results.get("ai_report", {}).get("analysis", "")
    formats = config.get("reporting", {}).get("formats", ["html", "md"])

    report_path = ""
    if "html" in formats:
        try:
            from reporting.html_report import HTMLReportGenerator
            gen = HTMLReportGenerator(str(session_dir), target, elapsed)
            report_path = gen.generate(all_results, ai_text)
            console.print(f"  [green]✓[/green]  HTML → {report_path}")
        except Exception as e:
            console.print(f"  [red]✗[/red]  HTML report: {e}")

        # PDF (WeasyPrint)
        if report_path:
            try:
                from reporting.pdf_report import generate_pdf
                pdf = generate_pdf(report_path)
                if pdf:
                    console.print(f"  [green]✓[/green]  PDF  → {pdf}")
            except Exception as e:
                console.print(f"  [yellow]![/yellow]  PDF skipped: {e}")

    if "md" in formats:
        md = _md_report(session_dir, target, all_results, ai_text, elapsed)
        console.print(f"  [green]✓[/green]  MD   → {md}")

    _print_summary(target, session_dir, all_results, elapsed)
    return all_results


# ─── Markdown report ──────────────────────────────────────────────────────────

def _md_report(
    session_dir: Path, target: str, results: dict, ai: str, elapsed: str
) -> str:
    recon = results.get("recon", {})
    ports = results.get("portscan", {}).get("summary", {})
    tech  = results.get("techstack", {})
    fuzz  = results.get("fuzzer", {})
    vuln  = results.get("vulnscan", {})

    lines = [
        f"# 🔬 ReconX: `{target}`",
        f"\n> **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  **Duration:** {elapsed}\n",
        "---\n## 📊 Summary\n",
        "| Metric | Value |", "|--------|-------|",
        f"| Subdomains | {recon.get('subdomains_total', 0)} |",
        f"| Live HTTP hosts | {len(recon.get('live_http', []))} |",
        f"| Unique IPs | {len(recon.get('resolved_ips', []))} |",
        f"| Open ports | {ports.get('total_open_ports', 0)} |",
        f"| Technologies | {len(tech.get('technologies_summary', {}))} |",
        f"| Endpoints | {fuzz.get('total_endpoints', 0)} |",
        f"| Vulnerabilities | {vuln.get('total', 0)} |",
        f"| JS Secrets | {fuzz.get('js_secrets_count', 0)} |",
        "",
    ]
    if ai:
        lines += ["---\n## 🤖 AI Analysis\n", ai, ""]

    for f in vuln.get("findings", [])[:50]:
        sev = f.get("severity", "").upper()
        lines.append(f"| {sev} | {f.get('name','')} | {f.get('matched_url','')} |")

    path = session_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


# ─── Console summary ──────────────────────────────────────────────────────────

def _print_summary(target: str, session_dir: Path, results: dict, elapsed: str):
    recon = results.get("recon", {})
    ports = results.get("portscan", {}).get("summary", {})
    tech  = results.get("techstack", {})
    fuzz  = results.get("fuzzer", {})
    vuln  = results.get("vulnscan", {})
    n_vuln = vuln.get("total", 0)

    t = Table(show_header=False, border_style="dim", box=None, padding=(0, 1))
    t.add_column("k", style="bold"); t.add_column("v", style="cyan")
    t.add_row("🎯 Target",           target)
    t.add_row("📁 Output dir",       str(session_dir))
    t.add_row("⏱  Duration",         elapsed)
    t.add_row("🌐 Subdomains",       str(recon.get("subdomains_total", 0)))
    t.add_row("✅ Live HTTP",        str(len(recon.get("live_http", []))))
    t.add_row("🖥  Unique IPs",       str(len(recon.get("resolved_ips", []))))
    t.add_row("🔌 Open ports",       str(ports.get("total_open_ports", 0)))
    t.add_row("🧰 Technologies",     str(len(tech.get("technologies_summary", {}))))
    t.add_row("🔎 Endpoints",        str(fuzz.get("total_endpoints", 0)))
    t.add_row("🚨 Vulnerabilities",  f"[{'red' if n_vuln else 'green'}]{n_vuln}[/{'red' if n_vuln else 'green'}]")
    t.add_row("🔑 JS Secrets",       str(fuzz.get("js_secrets_count", 0)))

    console.print(Panel(t, title="[bold magenta]ReconX — Complete[/bold magenta]",
                        border_style="magenta", padding=(1, 2)))


def _fmt_elapsed(seconds: float) -> str:
    m, s = int(seconds // 60), int(seconds % 60)
    return f"{m}m {s}s"


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="ReconX — Automated Web Application Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t example.com
  python3 main.py -t example.com -m recon,portscan,vulnscan
  python3 main.py -t example.com --skip cmscan
  python3 main.py -t example.com --resume
        """,
    )
    p.add_argument("-t", "--target",  required=True, help="Domain or IP")
    p.add_argument("-c", "--config",  default="config.yaml")
    p.add_argument("-o", "--output",  default=".", help="Base output directory")
    p.add_argument("-m", "--modules", help="Comma-separated modules (default: all)")
    p.add_argument("-s", "--skip",    help="Comma-separated modules to skip")
    p.add_argument("-r", "--resume",  action="store_true",
                   help="Reuse cached module results from a previous run")
    p.add_argument("--list-modules",  action="store_true")

    args = p.parse_args()
    console.print(BANNER)

    if args.list_modules:
        console.print("[bold]Modules (execution order):[/bold]")
        for step in PIPELINE:
            console.print(f"  • {step['name']:<15} [dim]group {step['group']}[/dim]")
        sys.exit(0)

    all_names = [s["name"] for s in PIPELINE]
    active = [m.strip() for m in args.modules.split(",")] if args.modules else list(all_names)
    active = [m for m in active if m in all_names]
    if args.skip:
        skip = {m.strip() for m in args.skip.split(",")}
        active = [m for m in active if m not in skip]

    console.print(f"[bold]Target:[/bold]  [cyan]{args.target}[/cyan]")
    console.print(f"[bold]Modules:[/bold] {', '.join(active)}")
    console.print(f"[bold]Resume:[/bold]  {'yes' if args.resume else 'no'}\n")

    cfg = load_config(args.config)
    session_dir = create_session_dir(args.target, args.output)
    console.print(f"[bold]Output:[/bold]  {session_dir}\n")

    try:
        run_pipeline(args.target, cfg, session_dir, active, args.resume)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — partial results saved.[/yellow]")
        sys.exit(1)


def create_session_dir(target: str, base: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_").replace(".", "_")
    d = Path(base) / "output" / f"reconx_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    d.mkdir(parents=True, exist_ok=True)
    return d


if __name__ == "__main__":
    main()
