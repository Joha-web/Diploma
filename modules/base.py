"""
base.py — Base class for all ReconX scan modules.

Every module inherits from BaseModule and implements run().
Provides shared utilities: subprocess execution, tool checking,
file I/O, logging, and result collection.
"""

import subprocess
import shutil
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console

console = Console()


class BaseModule:
    """Base class for all reconnaissance modules."""

    name: str = "base"
    description: str = ""
    required_tools: list = []

    def __init__(self, target: str, output_dir: str, config: dict):
        self.target = target
        self.output_dir = Path(output_dir)
        self.config = config
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.module_dir = self.output_dir / self.name
        self.module_dir.mkdir(parents=True, exist_ok=True)

    # ── Tool availability ────────────────────────────────────────
    @staticmethod
    def has_tool(name: str) -> bool:
        return shutil.which(name) is not None

    def check_tools(self) -> dict:
        status = {}
        for tool in self.required_tools:
            available = self.has_tool(tool)
            status[tool] = available
            if available:
                console.print(f"  [green]✓[/green] {tool}")
            else:
                console.print(f"  [yellow]✗[/yellow] {tool} — not found")
        return status

    def any_tool_available(self) -> bool:
        if not self.required_tools:
            return True
        return any(self.has_tool(t) for t in self.required_tools)

    # ── Subprocess execution ─────────────────────────────────────
    def exec(self, cmd: list | str, timeout: int = 300,
             capture: bool = True, shell: bool = False) -> subprocess.CompletedProcess:
        """Run command, never raises on failure."""
        try:
            if isinstance(cmd, str):
                shell = True
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
                shell=shell,
            )
            return result
        except subprocess.TimeoutExpired:
            self.warn(f"Timeout ({timeout}s): {cmd if isinstance(cmd, str) else ' '.join(str(c) for c in cmd[:3])}")
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="timeout")
        except Exception as e:
            self.warn(f"Command error: {e}")
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr=str(e))

    def exec_json(self, cmd: list | str, timeout: int = 300) -> list | dict:
        r = self.exec(cmd, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        return {}

    # ── Cross-module file access ─────────────────────────────────
    def session_path(self, module: str, *path_parts: str) -> Path:
        """Return path to a file in another module's output directory.

        Usage:
            self.session_path("recon", "subdomains", "all_subdomains.txt")
            self.session_path("portscan", "ports_by_host.json")
        """
        return self.output_dir / module / Path(*path_parts)

    # ── Resume support ───────────────────────────────────────────
    def is_cached(self) -> bool:
        """Return True if this module already ran (results exist)."""
        results_file = self.module_dir / f"{self.name}_results.json"
        return results_file.exists() and results_file.stat().st_size > 10

    def load_cached(self) -> dict:
        results_file = self.module_dir / f"{self.name}_results.json"
        try:
            data = json.loads(results_file.read_text(encoding="utf-8"))
            self.success(f"Loaded cached results ({results_file.stat().st_size} bytes)")
            return data
        except Exception:
            return {}

    # ── File I/O ─────────────────────────────────────────────────
    def save_json(self, data, filename: str) -> Path:
        path = self.module_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path

    def save_text(self, lines: list | str, filename: str) -> Path:
        path = self.module_dir / filename
        if isinstance(lines, list):
            lines = "\n".join(str(l) for l in lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(lines)
        return path

    def load_lines(self, filepath: str | Path) -> list:
        path = Path(filepath)
        if not path.exists() or path.stat().st_size == 0:
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.strip() for line in f if line.strip()]

    def load_json(self, filepath: str | Path) -> list | dict:
        path = Path(filepath)
        if not path.exists() or path.stat().st_size == 0:
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    # ── Logging ──────────────────────────────────────────────────
    def banner(self, text: str):
        console.print(f"\n[bold magenta]{'═' * 56}[/bold magenta]")
        console.print(f"[bold magenta]  {text}[/bold magenta]")
        console.print(f"[bold magenta]{'═' * 56}[/bold magenta]\n")

    def info(self, msg: str):
        console.print(f"  [cyan]ℹ[/cyan]  {msg}")

    def success(self, msg: str):
        console.print(f"  [green]✓[/green]  {msg}")

    def warn(self, msg: str):
        console.print(f"  [yellow]![/yellow]  {msg}")

    def error(self, msg: str):
        console.print(f"  [red]✗[/red]  {msg}")

    # ── Lifecycle ────────────────────────────────────────────────
    def run(self) -> dict:
        raise NotImplementedError

    def execute(self, resume: bool = False) -> dict:
        """Wrapper around run() with timing, caching, and error handling."""
        self.banner(f"{self.name.upper()} — {self.description}")

        # Resume: skip if already done
        if resume and self.is_cached():
            self.info("Resume mode — loading cached results")
            self.results = self.load_cached()
            return self.results

        self.start_time = datetime.now()
        self.check_tools()

        if self.required_tools and not self.any_tool_available():
            self.warn("No required tools available — module skipped")
            self.results = {"status": "skipped", "reason": "no_tools"}
            return self.results

        try:
            self.results = self.run()
            self.results["status"] = "completed"
        except Exception as e:
            self.error(f"Module failed: {e}")
            import traceback
            self.results = {"status": "error", "error": str(e),
                            "traceback": traceback.format_exc()}

        self.end_time = datetime.now()
        elapsed = (self.end_time - self.start_time).total_seconds()
        self.results["elapsed_seconds"] = round(elapsed, 1)
        self.success(f"Completed in {elapsed:.1f}s")

        self.save_json(self.results, f"{self.name}_results.json")
        return self.results

    # ── Utility ──────────────────────────────────────────────────
    @staticmethod
    def extract_urls(text: str) -> list:
        return re.findall(r'https?://[^\s\'"<>]+', text)

    @staticmethod
    def extract_ips(text: str) -> list:
        return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    @staticmethod
    def unique(items: list) -> list:
        seen, result = set(), []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result
