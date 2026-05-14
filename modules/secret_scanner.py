"""
ReconX - Module: public Git repository secret scanning with Gitleaks.
"""

import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import quote_plus

from modules.base import BaseModule


class SecretScannerModule(BaseModule):
    name = "secret_scanner"
    description = "Git Secret Scanning (Gitleaks)"
    required_tools = ["gitleaks", "git"]

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("secret_scanner", {})
        if not cfg.get("enabled", True):
            return {"findings": [], "repos": [], "total": 0, "status": "disabled"}

        missing = [tool for tool in self.required_tools if not self.has_tool(tool)]
        if missing:
            self.warn(f"Secret scanning skipped; missing tools: {', '.join(missing)}")
            return {
                "findings": [],
                "repos": [],
                "total": 0,
                "missing_tools": missing,
                "status": "dependency_missing",
            }

        repos = self._find_repos()
        max_repos = int(cfg.get("max_repos", 20))
        findings: list[dict] = []
        scanned: list[str] = []
        for repo_url in repos[:max_repos]:
            tmpdir = self._clone(repo_url)
            if not tmpdir:
                continue
            try:
                scanned.append(repo_url)
                findings.extend(self._scan(tmpdir, repo_url=repo_url))
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        self.save_json(repos, "github_repositories.json")
        self.save_json(findings, "secret_findings.json")
        return {
            "findings": findings,
            "repos": repos,
            "scanned_repos": scanned,
            "total": len(findings),
        }

    def _find_repos(self) -> list[str]:
        cfg = self.config.get("scan", {}).get("secret_scanner", {})
        token = self.config.get("api_keys", {}).get("github", "")
        per_page = min(int(cfg.get("github_per_page", cfg.get("max_repos", 20))), 100)
        query = quote_plus(str(cfg.get("query", self.domain)))
        url = f"https://api.github.com/search/repositories?q={query}&per_page={per_page}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = self.http_get(
            url,
            enforce_scope=False,
            timeout=float(cfg.get("github_timeout", 15)),
            headers=headers,
        )
        if resp is None:
            return []
        try:
            data = resp.json()
        except Exception:
            try:
                data = json.loads(resp.text or "{}")
            except json.JSONDecodeError:
                return []
        items = data.get("items", []) if isinstance(data, dict) else []
        repos = [
            str(item.get("clone_url", "")).strip()
            for item in items
            if isinstance(item, dict) and item.get("clone_url")
        ]
        return sorted(dict.fromkeys(repos))

    def _clone(self, repo_url: str) -> str:
        cfg = self.config.get("scan", {}).get("secret_scanner", {})
        tmpdir = tempfile.mkdtemp(prefix="reconx_repo_")
        result = self.exec(
            ["git", "clone", "--depth", "1", repo_url, tmpdir],
            timeout=int(cfg.get("clone_timeout", 120)),
        )
        if result.returncode != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return ""
        return tmpdir

    def _scan(self, path: str, repo_url: str = "") -> list[dict]:
        cfg = self.config.get("scan", {}).get("secret_scanner", {})
        out = self.module_dir / f"gitleaks_{self._safe_name(repo_url or path)}.json"
        self.exec(
            [
                "gitleaks", "detect",
                "--source", path,
                "--report-format", "json",
                "--report-path", str(out),
                "--no-git",
            ],
            timeout=int(cfg.get("scan_timeout", 120)),
        )
        raw = self.load_json(out) or []
        if isinstance(raw, dict):
            raw_items = raw.get("findings", []) or raw.get("Results", []) or []
        else:
            raw_items = raw
        findings = []
        for item in raw_items:
            if isinstance(item, dict):
                findings.append(self._normalize_secret(item, repo_url))
        return findings

    def _normalize_secret(self, item: dict, repo_url: str) -> dict:
        rule = item.get("RuleID") or item.get("rule_id") or item.get("Description") or "secret"
        file_path = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("Line") or item.get("line") or ""
        title = f"Potential secret detected: {rule}"
        return {
            "source": self.name,
            "id": str(rule),
            "type": "git_secret",
            "name": title,
            "title": title,
            "severity": "HIGH",
            "url": repo_url,
            "matched_url": repo_url,
            "description": "Gitleaks detected a potential secret in a public Git repository.",
            "evidence": {
                "repo": repo_url,
                "file": file_path,
                "line": line,
                "rule": rule,
                "fingerprint": item.get("Fingerprint", ""),
                "raw": item,
            },
            "confidence": 0.9,
        }

    @staticmethod
    def _safe_name(value: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip())
        return safe.strip("._")[:120] or "repo"
