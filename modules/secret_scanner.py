"""
ReconX - Module: public Git repository secret scanning with Gitleaks.
"""

import json
import hashlib
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
        skipped_unrelated: list[dict] = []
        for repo in repos[:max_repos]:
            repo_url = repo["clone_url"] if isinstance(repo, dict) else str(repo)
            repo_meta = repo if isinstance(repo, dict) else {"clone_url": repo_url}
            relevance = self._repo_relevance(repo_meta, cfg)
            repo_meta["relevance"] = relevance
            # If the repo is clearly unrelated and the user has not opted into scanning
            # those, skip it entirely. Otherwise we still clone & scan but tag findings
            # with the relevance score so severity can be downgraded.
            if relevance["score"] == "unrelated" and not cfg.get("scan_unrelated_repos", False):
                skipped_unrelated.append({
                    "clone_url": repo_url,
                    "owner": repo_meta.get("owner", ""),
                    "name": repo_meta.get("name", ""),
                    "reason": relevance.get("reason", "no_match"),
                })
                continue
            tmpdir = self._clone(repo_url)
            if not tmpdir:
                continue
            try:
                scanned.append(repo_url)
                findings.extend(self._scan(tmpdir, repo_url=repo_url, repo_meta=repo_meta))
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        if skipped_unrelated:
            self.info(
                f"Skipped {len(skipped_unrelated)} GitHub repos with no clear "
                f"relevance to {self.domain} (set scan.secret_scanner.scan_unrelated_repos=true to include)"
            )
        self.save_json(repos, "github_repositories.json")
        self.save_json(skipped_unrelated, "github_repositories_skipped.json")
        self.save_json(findings, "secret_findings.json")
        return {
            "findings": findings,
            "repos": repos,
            "scanned_repos": scanned,
            "skipped_unrelated": skipped_unrelated,
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
        repos: list[dict] = []
        seen_clones: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            clone_url = str(item.get("clone_url", "")).strip()
            if not clone_url or clone_url in seen_clones:
                continue
            seen_clones.add(clone_url)
            owner_info = item.get("owner", {}) or {}
            repos.append({
                "clone_url": clone_url,
                "owner": str(owner_info.get("login", "")),
                "owner_type": str(owner_info.get("type", "")),
                "name": str(item.get("name", "")),
                "full_name": str(item.get("full_name", "")),
                "description": str(item.get("description", "") or ""),
                "html_url": str(item.get("html_url", "")),
                "stargazers_count": int(item.get("stargazers_count", 0) or 0),
                "fork": bool(item.get("fork", False)),
                "archived": bool(item.get("archived", False)),
            })
        return sorted(repos, key=lambda r: r["clone_url"])

    def _repo_relevance(self, repo: dict, cfg: dict) -> dict:
        """Score the relevance of a repo to the scan target.

        Returns a dict with:
          - score: "trusted" | "related" | "weak" | "unrelated"
          - reason: short explanation
          - matched: list of tokens that matched
        """
        owner = (repo.get("owner") or "").lower()
        name = (repo.get("name") or "").lower()
        full = (repo.get("full_name") or "").lower()
        description = (repo.get("description") or "").lower()

        trusted_owners = {str(o).strip().lower() for o in (cfg.get("trusted_owners") or []) if str(o).strip()}
        if owner and owner in trusted_owners:
            return {"score": "trusted", "reason": "owner_in_trusted_list", "matched": [owner]}

        # Build a set of meaningful tokens from the target domain (root label and any
        # second-level chunks longer than 3 chars).
        target_tokens: set[str] = set()
        domain_parts = [p for p in (self.domain or "").lower().split(".") if p]
        for part in domain_parts:
            if len(part) >= 4 and part not in {"com", "org", "net", "info", "io", "co", "app", "dev"}:
                target_tokens.add(part)
        # Allow extra tokens from config (e.g. company name when not in domain).
        for extra in cfg.get("relevance_tokens", []) or []:
            extra_l = str(extra).strip().lower()
            if extra_l:
                target_tokens.add(extra_l)

        if not target_tokens:
            # No tokens to match against — default to weak relevance (don't be aggressive).
            return {"score": "weak", "reason": "no_target_tokens", "matched": []}

        matched_in_owner = [t for t in target_tokens if t in owner]
        matched_in_name = [t for t in target_tokens if t in name]
        matched_in_full = [t for t in target_tokens if t in full]
        matched_in_desc = [t for t in target_tokens if t in description]

        if matched_in_owner:
            return {"score": "trusted", "reason": "target_token_in_owner", "matched": matched_in_owner}
        if matched_in_name or matched_in_full:
            return {"score": "related", "reason": "target_token_in_repo_name", "matched": (matched_in_name or matched_in_full)}
        if matched_in_desc:
            return {"score": "weak", "reason": "target_token_in_description_only", "matched": matched_in_desc}
        return {"score": "unrelated", "reason": "no_token_match", "matched": []}

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

    def _scan(self, path: str, repo_url: str = "", repo_meta: dict | None = None) -> list[dict]:
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
                findings.append(self._normalize_secret(item, repo_url, repo_meta or {}))
        return findings

    def _normalize_secret(self, item: dict, repo_url: str, repo_meta: dict | None = None) -> dict:
        repo_meta = repo_meta or {}
        cfg = self.config.get("scan", {}).get("secret_scanner", {})
        rule = item.get("RuleID") or item.get("rule_id") or item.get("Description") or "secret"
        file_path = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("Line") or item.get("line") or ""
        raw = item if cfg.get("retain_raw_secrets", False) else self._sanitize_raw_item(item)
        relevance = repo_meta.get("relevance", {}) or {}
        score = str(relevance.get("score", "weak"))
        severity_map = {
            "trusted": "HIGH",
            "related": "MEDIUM",
            "weak": "LOW",
            "unrelated": "INFO",
        }
        severity = severity_map.get(score, "MEDIUM")
        confidence_map = {"trusted": 0.9, "related": 0.65, "weak": 0.45, "unrelated": 0.25}
        confidence = confidence_map.get(score, 0.6)
        title_suffix = "" if score == "trusted" else f" (repo relevance: {score})"
        title = f"Potential secret detected: {rule}{title_suffix}"
        description = (
            "Gitleaks detected a potential secret in a public Git repository."
            if score in ("trusted", "related")
            else "Gitleaks detected a potential secret in a public Git repository that does "
                 "not appear to belong to the target organization. Manually verify ownership."
        )
        return {
            "source": self.name,
            "id": str(rule),
            "type": "git_secret",
            "name": title,
            "title": title,
            "severity": severity,
            "url": repo_url,
            "matched_url": repo_url,
            "description": description,
            "evidence": {
                "repo": repo_url,
                "repo_owner": repo_meta.get("owner", ""),
                "repo_name": repo_meta.get("name", ""),
                "repo_full_name": repo_meta.get("full_name", ""),
                "repo_description": repo_meta.get("description", ""),
                "repo_stars": repo_meta.get("stargazers_count", 0),
                "repo_fork": repo_meta.get("fork", False),
                "repo_archived": repo_meta.get("archived", False),
                "relevance": relevance,
                "file": file_path,
                "line": line,
                "rule": rule,
                "fingerprint": item.get("Fingerprint", ""),
                "raw": raw,
            },
            "confidence": confidence,
        }

    @classmethod
    def _sanitize_raw_item(cls, item: dict) -> dict:
        sanitized: dict = {}
        for key, value in item.items():
            if str(key).lower() in {"secret", "match"}:
                sanitized[key] = cls._redact_secret(str(value))
                sanitized[f"{key}_sha256"] = cls._fingerprint_secret(str(value))
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def _safe_name(value: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip())
        return safe.strip("._")[:120] or "repo"

    @staticmethod
    def _redact_secret(value: str) -> str:
        if len(value) <= 10:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    @staticmethod
    def _fingerprint_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
