"""
ReconX - Module: Swagger/OpenAPI discovery and path extraction.
"""

import json
from urllib.parse import urljoin

import requests
import yaml

from modules.base import BaseModule


OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api/docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/openapi.yaml", "/openapi.yml",
]


class OpenAPIParserModule(BaseModule):
    name = "openapi_parser"
    description = "Swagger / OpenAPI Discovery"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 live_hosts: list | None = None):
        super().__init__(target, output_dir, config)
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("openapi_parser", {})
        if not cfg.get("enabled", True):
            return {"specs": [], "endpoints": [], "parameters": [], "status": "disabled"}

        urls = self._extract_urls()[: int(cfg.get("max_hosts", 100))]
        sess = requests.Session()
        sess.verify = False
        specs: list[dict] = []
        endpoints: list[dict] = []
        parameters: list[dict] = []

        for base in urls:
            for path in OPENAPI_PATHS:
                spec_url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                data = self._fetch_spec(spec_url, sess)
                if not data:
                    continue
                specs.append({"url": spec_url, "title": self._title(data)})
                eps, params = self._extract(data, base)
                endpoints.extend(eps)
                parameters.extend(params)
                break

        endpoints = self._dedupe(endpoints, ("method", "url"))
        parameters = self._dedupe(parameters, ("url", "name", "in"))
        self.save_json(specs, "openapi_specs.json")
        self.save_json(endpoints, "openapi_endpoints.json")
        self.save_json(parameters, "openapi_parameters.json")
        return {
            "specs": specs,
            "endpoints": endpoints,
            "parameters": parameters,
            "total_specs": len(specs),
            "total_endpoints": len(endpoints),
            "total_parameters": len(parameters),
        }

    def _fetch_spec(self, url: str, sess: requests.Session) -> dict | None:
        if not self.is_in_scope(url):
            return None
        resp = self.http_get(url, session=sess, timeout=10, verify=False)
        if resp is None or resp.status_code != 200:
            return None
        text = resp.text or ""
        if "openapi" not in text.lower() and "swagger" not in text.lower():
            return None
        try:
            return json.loads(text)
        except ValueError:
            try:
                data = yaml.safe_load(text)
                return data if isinstance(data, dict) else None
            except Exception:
                return None

    def _extract(self, spec: dict, base_url: str) -> tuple[list[dict], list[dict]]:
        endpoints: list[dict] = []
        parameters: list[dict] = []
        for path, methods in (spec.get("paths", {}) or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, info in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "url": full_url,
                    "summary": (info or {}).get("summary", "") if isinstance(info, dict) else "",
                })
                for param in (info or {}).get("parameters", []) if isinstance(info, dict) else []:
                    if isinstance(param, dict) and param.get("name"):
                        parameters.append({
                            "url": full_url,
                            "path": path,
                            "method": method.upper(),
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": param.get("required", False),
                        })
        return endpoints, parameters

    @staticmethod
    def _title(spec: dict) -> str:
        return (spec.get("info", {}) or {}).get("title", "")

    @staticmethod
    def _dedupe(items: list[dict], keys: tuple[str, ...]) -> list[dict]:
        seen = set()
        result = []
        for item in items:
            key = tuple(item.get(k, "") for k in keys)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def _extract_urls(self) -> list[str]:
        urls: set[str] = set()
        for item in self.live_hosts:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            if url.startswith(("http://", "https://")):
                urls.add(url)
        return self.filter_in_scope_urls(urls)
