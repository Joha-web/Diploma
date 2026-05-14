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
                specs.append({
                    "url": spec_url,
                    "title": self._title(data),
                    "security_defined": self._security_defined(data),
                    "security_schemes": sorted(self._security_schemes(data)),
                })
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
        global_security = spec.get("security", [])
        security_defined = self._security_defined(spec)
        for path, methods in (spec.get("paths", {}) or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, info in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                info = info if isinstance(info, dict) else {}
                full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                operation_security = info.get("security") if "security" in info else None
                effective_security = operation_security if operation_security is not None else global_security
                responses = info.get("responses", {}) or {}
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "url": full_url,
                    "summary": info.get("summary", ""),
                    "operation_id": info.get("operationId", ""),
                    "tags": info.get("tags", []) or [],
                    "security": operation_security,
                    "effective_security": effective_security,
                    "security_defined": security_defined,
                    "request_schema": self._request_schema(info),
                    "responses": responses,
                    "response_headers": self._response_headers(responses),
                })
                for param in info.get("parameters", []) or []:
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
    def _security_defined(spec: dict) -> bool:
        return bool(spec.get("security") or OpenAPIParserModule._security_schemes(spec))

    @staticmethod
    def _security_schemes(spec: dict) -> set[str]:
        components = spec.get("components", {}) or {}
        schemes = components.get("securitySchemes", {}) or {}
        if isinstance(schemes, dict):
            return set(schemes.keys())
        return set()

    @staticmethod
    def _request_schema(info: dict) -> dict:
        body = info.get("requestBody", {}) or {}
        if not isinstance(body, dict):
            return {}
        content = body.get("content", {}) or {}
        if not isinstance(content, dict):
            return {}
        preferred = (
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        )
        for content_type in preferred:
            schema = (content.get(content_type, {}) or {}).get("schema")
            if isinstance(schema, dict):
                return schema
        for details in content.values():
            if isinstance(details, dict) and isinstance(details.get("schema"), dict):
                return details["schema"]
        return {}

    @staticmethod
    def _response_headers(responses: dict) -> dict:
        headers: dict[str, list[str]] = {}
        if not isinstance(responses, dict):
            return headers
        for status, details in responses.items():
            if not isinstance(details, dict):
                continue
            response_headers = details.get("headers", {}) or {}
            if isinstance(response_headers, dict) and response_headers:
                headers[str(status)] = sorted(response_headers.keys())
        return headers

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
