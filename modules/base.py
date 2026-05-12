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
import signal
import sys
import threading
import time
import ipaddress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from rich.console import Console

from modules.audit import AuditLogger
from modules.rate_limiter import TokenBucket

console = Console()

_CTRL_C_SKIP_WINDOW = 2.0
_COMMAND_POLL_INTERVAL = 0.2
_INTERRUPT_LOCK = threading.RLock()
_ACTIVE_PROCESSES: set[subprocess.Popen] = set()
_INTERRUPT_GENERATION = 0
_LAST_SIGINT_AT = 0.0
_ABORT_REQUESTED = threading.Event()
_SIGINT_HANDLER_INSTALLED = False


def install_ctrl_c_skip_handler() -> None:
    """Make Ctrl+C skip the current external tool; quick second Ctrl+C aborts."""
    global _SIGINT_HANDLER_INSTALLED
    if _SIGINT_HANDLER_INSTALLED:
        return
    if threading.current_thread() is not threading.main_thread():
        return
    signal.signal(signal.SIGINT, _handle_sigint)
    _SIGINT_HANDLER_INSTALLED = True


def scan_abort_requested() -> bool:
    return _ABORT_REQUESTED.is_set()


def _handle_sigint(signum, frame) -> None:
    global _INTERRUPT_GENERATION, _LAST_SIGINT_AT

    with _INTERRUPT_LOCK:
        now = time.monotonic()
        active = [proc for proc in _ACTIVE_PROCESSES if proc.poll() is None]
        abort = not active or (now - _LAST_SIGINT_AT <= _CTRL_C_SKIP_WINDOW)
        _LAST_SIGINT_AT = now

        if abort:
            _ABORT_REQUESTED.set()
        else:
            _INTERRUPT_GENERATION += 1

    for proc in active:
        _signal_process(proc, signal.SIGINT)

    if abort:
        raise KeyboardInterrupt

    sys.stderr.write(
        "\n[!] Ctrl+C: skipping current external command(s). "
        "Press Ctrl+C again to abort.\n"
    )
    sys.stderr.flush()


def _current_interrupt_generation() -> int:
    with _INTERRUPT_LOCK:
        return _INTERRUPT_GENERATION


def _register_process(proc: subprocess.Popen) -> None:
    with _INTERRUPT_LOCK:
        _ACTIVE_PROCESSES.add(proc)


def _unregister_process(proc: subprocess.Popen) -> None:
    with _INTERRUPT_LOCK:
        _ACTIVE_PROCESSES.discard(proc)


def _signal_process(proc: subprocess.Popen, sig: int) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(proc.pid, sig)
        else:
            proc.send_signal(sig)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _is_interrupt_returncode(returncode: int | None) -> bool:
    return returncode in (130, -int(signal.SIGINT))


class BaseModule:
    """Base class for all reconnaissance modules."""

    name: str = "base"
    description: str = ""
    required_tools: list = []

    def __init__(self, target: str, output_dir: str, config: dict):
        self.target = target
        self.output_dir = Path(output_dir)
        self.config = config
        self.domain = self._clean_domain(target)
        rate = (
            self.config.get("scan", {}).get("global_rate_limit")
            or self.config.get("scan", {}).get("rate_limit")
            or 100
        )
        self.rate_limiter = TokenBucket(rate=rate)
        self.audit = AuditLogger(self.output_dir)
        self.results = {}
        self.interrupted_commands: list[str] = []
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
             capture: bool = True, shell: bool = False,
             label: str | None = None) -> subprocess.CompletedProcess:
        """Run command, never raises on failure."""
        command_label = label or self._command_label(cmd)
        stdout_target = subprocess.PIPE if capture else None
        stderr_target = subprocess.PIPE if capture else None
        started_generation = _current_interrupt_generation()

        try:
            if isinstance(cmd, str):
                shell = True

            popen_kwargs = {
                "stdout": stdout_target,
                "stderr": stderr_target,
                "text": True,
                "shell": shell,
                "env": self._subprocess_env(),
            }
            if os.name != "nt":
                popen_kwargs["start_new_session"] = True

            proc = subprocess.Popen(cmd, **popen_kwargs)
            _register_process(proc)
            interrupted_by_ctrl_c = False

            try:
                stdout, stderr, interrupted_by_ctrl_c = self._communicate(
                    proc, timeout, started_generation
                )
            finally:
                _unregister_process(proc)

            stdout = stdout or ""
            stderr = stderr or ""
            if interrupted_by_ctrl_c or _is_interrupt_returncode(proc.returncode):
                self.interrupted_commands.append(command_label)
                self.warn(f"Interrupted — skipped: {command_label}")
                return subprocess.CompletedProcess(
                    cmd, returncode=130, stdout=stdout, stderr=stderr or "interrupted"
                )

            return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            self.warn(f"Timeout ({timeout}s): {command_label}")
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="timeout")
        except KeyboardInterrupt:
            if "proc" in locals():
                _signal_process(proc, signal.SIGINT)
            raise
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

    def _communicate(
        self,
        proc: subprocess.Popen,
        timeout: int | float | None,
        started_generation: int,
    ) -> tuple[str | None, str | None, bool]:
        deadline = time.monotonic() + timeout if timeout is not None else None
        interrupted = False
        interrupted_at = 0.0
        kill_sent = False

        while True:
            wait_for = _COMMAND_POLL_INTERVAL
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _signal_process(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                    proc.communicate()
                    raise subprocess.TimeoutExpired(proc.args, timeout)
                wait_for = min(wait_for, remaining)

            try:
                stdout, stderr = proc.communicate(timeout=wait_for)
                return stdout, stderr, interrupted
            except subprocess.TimeoutExpired:
                if _current_interrupt_generation() != started_generation:
                    if not interrupted:
                        interrupted = True
                        interrupted_at = time.monotonic()
                        _signal_process(proc, signal.SIGINT)
                    elif not kill_sent and time.monotonic() - interrupted_at > 2.0:
                        kill_sent = True
                        _signal_process(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                    continue

                if deadline is not None and time.monotonic() >= deadline:
                    _signal_process(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                    proc.communicate()
                    raise

    @staticmethod
    def _command_label(cmd: list | str) -> str:
        if isinstance(cmd, str):
            return cmd
        return " ".join(str(c) for c in cmd[:3])

    def _subprocess_env(self) -> dict:
        """Pass configured API tokens to external tools without printing them."""
        env = os.environ.copy()
        keys = self.config.get("api_keys", {})
        mapping = {
            "pdcp": "PDCP_API_KEY",
            "github": "GITHUB_TOKEN",
            "shodan": "SHODAN_API_KEY",
            "virustotal": "VIRUSTOTAL_API_KEY",
            "wpscan": "WPSCAN_API_TOKEN",
            "censys_api_id": "CENSYS_API_ID",
            "censys_api_secret": "CENSYS_API_SECRET",
        }
        for config_key, env_key in mapping.items():
            value = str(keys.get(config_key, "")).strip()
            if value and not env.get(env_key):
                env[env_key] = value
        return env

    # ── HTTP helpers: scope, rate limiting, audit ─────────────────────────
    def http_request(
        self,
        method: str,
        url: str,
        session: requests.Session | None = None,
        enforce_scope: bool = True,
        safe_readonly: bool = False,
        **kwargs,
    ) -> requests.Response | None:
        """Run one HTTP request with scope enforcement, global rate limit, and audit."""
        method = method.upper()
        in_scope = self.is_in_scope(url) if enforce_scope else True

        if enforce_scope and not in_scope:
            self.warn(f"Blocked out-of-scope request: {url}")
            self.audit.log_request(self.name, url, method, None, 0.0, in_scope=False,
                                   error="out_of_scope")
            return None

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            allow_write = self.config.get("scan", {}).get("allow_write", False)
            if not allow_write and not safe_readonly:
                self.warn(f"Blocked write-like HTTP method without allow_write: {method} {url}")
                self.audit.log_request(self.name, url, method, None, 0.0, in_scope=in_scope,
                                       error="write_method_blocked")
                return None

        self.rate_limiter.acquire()
        start = time.monotonic()
        requester = session if session is not None else requests
        try:
            response = requester.request(method, url, **kwargs)
            elapsed = time.monotonic() - start
            self.audit.log_request(
                self.name, url, method, response.status_code, elapsed, in_scope=in_scope
            )
            return response
        except requests.RequestException as exc:
            elapsed = time.monotonic() - start
            self.audit.log_request(
                self.name, url, method, None, elapsed, in_scope=in_scope, error=str(exc)
            )
            return None

    def http_get(self, url: str, **kwargs) -> requests.Response | None:
        return self.http_request("GET", url, **kwargs)

    def http_post(self, url: str, safe_readonly: bool = False, **kwargs) -> requests.Response | None:
        return self.http_request("POST", url, safe_readonly=safe_readonly, **kwargs)

    def is_in_scope(self, value: str) -> bool:
        """Return True when a URL/host belongs to configured scan scope."""
        scope_cfg = self.config.get("scope", {})
        if scope_cfg.get("enforce", True) is False:
            return True

        host = self._hostname(value)
        if not host:
            return False

        excluded = scope_cfg.get("excluded", []) or []
        if any(self._host_matches(host, self._hostname_or_domain(item)) for item in excluded):
            return False

        if self._is_ip(host):
            allowed_ips = set(scope_cfg.get("allowed_ips", []) or [])
            if self._is_ip(self.domain) and scope_cfg.get("allow_target_ip", True):
                allowed_ips.add(self.domain)
            return host in allowed_ips

        allowed_domains = scope_cfg.get("allowed_domains", []) or []
        if not allowed_domains and self.domain and not self._is_ip(self.domain):
            allowed_domains = [self.domain]

        return any(
            self._host_matches(host, self._hostname_or_domain(domain))
            for domain in allowed_domains
        )

    def filter_in_scope_urls(self, items: list[str] | set[str]) -> list[str]:
        filtered: list[str] = []
        blocked = 0
        for item in items:
            if self.is_in_scope(str(item)):
                filtered.append(str(item))
            else:
                blocked += 1
        if blocked:
            self.warn(f"Scope filter removed {blocked} out-of-scope URL(s)")
        return sorted(self.unique(filtered))

    @classmethod
    def _hostname(cls, value: str) -> str:
        value = str(value or "").strip()
        match = re.search(r"https?://[^\s'\"<>]+", value)
        if match:
            value = match.group(0)

        try:
            parsed = urlparse(value if "://" in value else f"//{value}")
            host = parsed.hostname or ""
        except Exception:
            host = value.split("/", 1)[0].split(":", 1)[0]
        return host.strip(".").lower()

    @classmethod
    def _hostname_or_domain(cls, value: str) -> str:
        host = cls._hostname(value)
        return host.lstrip("*.").strip(".").lower()

    @staticmethod
    def _host_matches(host: str, allowed: str) -> bool:
        if not allowed:
            return False
        allowed = allowed.lstrip("*.").strip(".").lower()
        return host == allowed or host.endswith(f".{allowed}")

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _clean_domain(target: str) -> str:
        host = BaseModule._hostname(target)
        return host or str(target).strip().lower()

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
            if self.interrupted_commands:
                self.results["interrupted_commands"] = self.interrupted_commands
            self.results["status"] = "completed"
        except KeyboardInterrupt:
            if scan_abort_requested():
                raise
            self.warn("Interrupted — module skipped")
            self.results = {"status": "skipped", "reason": "interrupted"}
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
