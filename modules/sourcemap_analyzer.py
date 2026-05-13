"""
ReconX - Module: JavaScript source map analysis.
"""

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from modules.base import BaseModule
from modules.fuzzer import SECRET_PATTERNS


INTERESTING_PATH = re.compile(r"(\.env|config|credential|secret|internal|private)", re.I)


class SourceMapAnalyzerModule(BaseModule):
    name = "sourcemap_analyzer"
    description = "JavaScript Source Map Analysis"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 fuzzer_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        (self.module_dir / "reconstructed").mkdir(exist_ok=True)

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("sourcemap_analyzer", {})
        if not cfg.get("enabled", True):
            return {"maps": [], "findings": [], "total": 0, "status": "disabled"}

        js_urls = self._js_urls()[: int(cfg.get("max_js", 150))]
        if not js_urls:
            self.info("No JavaScript URLs found for source map analysis")
            return {"maps": [], "findings": [], "total": 0}

        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "ReconX/2.0"

        maps: list[dict] = []
        findings: list[dict] = []
        for js_url in js_urls:
            source_map = self._fetch_sourcemap(js_url, sess)
            if not source_map:
                continue
            map_info, map_findings = self._analyse_map(js_url, source_map)
            maps.append(map_info)
            findings.extend(map_findings)

        self.save_json(maps, "sourcemaps.json")
        self.save_json(findings, "sourcemap_findings.json")
        return {"maps": maps, "findings": findings, "total": len(findings)}

    def _fetch_sourcemap(self, js_url: str, sess: requests.Session) -> dict | None:
        resp = self.http_get(js_url, session=sess, timeout=10, verify=False)
        if resp is None:
            return None

        map_url = resp.headers.get("SourceMap") or resp.headers.get("X-SourceMap")
        if not map_url:
            tail = (resp.text or "")[-800:]
            match = re.search(r"sourceMappingURL=([^\s]+)", tail)
            map_url = match.group(1).strip() if match else f"{js_url}.map"
        map_url = urljoin(js_url, map_url)
        if not self.is_in_scope(map_url):
            return None

        map_resp = self.http_get(map_url, session=sess, timeout=10, verify=False)
        if map_resp is None or map_resp.status_code != 200:
            return None
        try:
            data = map_resp.json()
            data["_map_url"] = map_url
            return data
        except ValueError:
            return None

    def _analyse_map(self, js_url: str, source_map: dict) -> tuple[dict, list[dict]]:
        sources = source_map.get("sources", []) or []
        contents = source_map.get("sourcesContent", []) or []
        map_url = source_map.get("_map_url", "")
        findings = [{
            "source": self.name,
            "id": "sourcemap_exposed",
            "type": "sourcemap_exposed",
            "name": "JavaScript source map exposed",
            "title": "JavaScript source map exposed",
            "severity": "LOW",
            "url": map_url,
            "matched_url": js_url,
            "description": "A public source map can expose original client-side source paths and code.",
            "evidence": {"sources": len(sources), "sources_content": len(contents)},
            "confidence": 0.9,
        }]

        for idx, src in enumerate(sources):
            if INTERESTING_PATH.search(str(src)):
                findings.append(self._finding(
                    "sourcemap_interesting_path", "LOW", js_url,
                    "Source map contains sensitive-looking source path",
                    {"source_path": src},
                ))

            if idx < len(contents) and contents[idx]:
                self._write_reconstructed(js_url, src, contents[idx])
                for pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(contents[idx]):
                        findings.append(self._finding(
                            "sourcemap_secret", "HIGH", js_url,
                            "Potential secret found in source map content",
                            {"source_path": src, "match": match.group(0)[:200]},
                        ))

        return {
            "js_url": js_url,
            "map_url": map_url,
            "sources": sources[:500],
            "sources_count": len(sources),
            "sources_content_count": len(contents),
        }, findings

    def _write_reconstructed(self, js_url: str, source_path: str, content: str) -> None:
        host = urlparse(js_url).hostname or "unknown"
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", f"{host}/{source_path}").strip("_")
        out = self.module_dir / "reconstructed" / safe[:180]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8", errors="replace")

    def _finding(self, finding_type: str, severity: str, url: str,
                 title: str, evidence: dict) -> dict:
        return {
            "source": self.name,
            "id": finding_type,
            "type": finding_type,
            "name": title,
            "title": title,
            "severity": severity,
            "url": url,
            "matched_url": url,
            "description": title,
            "evidence": evidence,
            "confidence": 0.8,
        }

    def _js_urls(self) -> list[str]:
        candidates: set[str] = set(self.fuzzer_results.get("js_urls", []) or [])
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            candidates.add(str(url))
        classified = self.fuzzer_results.get("classified", {}) or {}
        for value in classified.values():
            if isinstance(value, list):
                candidates.update(str(item) for item in value)
        return self.filter_in_scope_urls({
            url for url in candidates
            if re.search(r"\.js(?:\?.*)?$", str(url), re.I)
        })
