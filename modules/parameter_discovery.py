"""
ReconX - Module: hidden parameter discovery with Arjun.
"""

import importlib.util
import sys
from urllib.parse import urlencode, urlparse, urlunparse

from modules.base import BaseModule


class ParameterDiscoveryModule(BaseModule):
    name = "parameter_discovery"
    description = "Hidden Parameter Discovery"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 fuzzer_results: dict | None = None,
                 openapi_results: dict | None = None,
                 endpoint_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}
        self.endpoint_results = endpoint_results or {}

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("parameter_discovery", {})
        if not cfg.get("enabled", True):
            return {"parameters": [], "parameterized_targets": [], "total": 0, "status": "disabled"}

        openapi_params = self._openapi_parameters()
        targets = self._select_targets()[: int(cfg.get("max_targets", 150))]
        if not targets and not openapi_params:
            self.warn("No URLs for parameter discovery")
            return {"parameters": [], "parameterized_targets": [], "total": 0}

        params: list[dict] = []
        arjun_cmd = self._arjun_command()
        if not arjun_cmd and targets:
            self.warn("Arjun not available in PATH or current Python environment")
        elif arjun_cmd and targets:
            url_file = self.module_dir / "arjun_targets.txt"
            out_file = self.module_dir / "arjun_results.json"
            self.save_text(targets, "arjun_targets.txt")
            self.exec(
                [*arjun_cmd, "-i", str(url_file), "-oJ", str(out_file),
                 "-t", str(cfg.get("threads", 10)), "-d", str(cfg.get("delay", 1)),
                 "--stable"],
                timeout=int(cfg.get("timeout", 600)),
            )
            params = self._parse_arjun(self.load_json(out_file))

        params.extend(openapi_params)
        params = self._dedupe_params(params)
        parameterized_targets = [self._with_param(p["url"], p["param"]) for p in params]

        self.save_json(params, "parameters.json")
        self.save_text(parameterized_targets, "parameterized_targets.txt")
        return {
            "parameters": params,
            "parameterized_targets": parameterized_targets,
            "total": len(params),
            "missing_tools": [] if arjun_cmd else ["arjun"],
        }

    def _select_targets(self) -> list[str]:
        candidates: set[str] = set()
        # fuzzer and endpoint_harvester both expose a same-shaped `classified` dict
        for results in (self.fuzzer_results, self.endpoint_results):
            classified = results.get("classified", {}) or {}
            for category in ("auth", "api", "with_params"):
                candidates.update(str(url) for url in classified.get(category, []) or [])
        # harvested request parameters point at directly parameterised URLs
        for item in self.endpoint_results.get("parameters", []) or []:
            if item.get("url"):
                candidates.add(str(item["url"]))
        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if endpoint.get("url"):
                candidates.add(endpoint["url"])
        return self.filter_in_scope_urls(candidates)

    @staticmethod
    def _parse_arjun(data) -> list[dict]:
        params: list[dict] = []
        if not isinstance(data, dict):
            return params
        for url, found in data.items():
            if isinstance(found, dict):
                values = found.get("params") or found.get("parameters") or []
            else:
                values = found or []
            for param in values:
                if isinstance(param, str):
                    params.append({"url": url, "param": param, "source": "arjun"})
        return params

    def _openapi_parameters(self) -> list[dict]:
        params: list[dict] = []
        for item in self.openapi_results.get("parameters", []) or []:
            if item.get("url") and item.get("name"):
                params.append({"url": item["url"], "param": item["name"], "source": "openapi"})
        return params

    @staticmethod
    def _dedupe_params(params: list[dict]) -> list[dict]:
        seen: set[tuple[str, str]] = set()
        result: list[dict] = []
        for item in params:
            key = (item.get("url", ""), item.get("param", ""))
            if key[0] and key[1] and key not in seen:
                seen.add(key)
                result.append(item)
        return result

    @staticmethod
    def _with_param(url: str, param: str) -> str:
        parsed = urlparse(url)
        query = urlencode({param: "reconx"})
        if parsed.query:
            query = f"{parsed.query}&{query}"
        return urlunparse(parsed._replace(query=query))

    def _arjun_command(self) -> list[str]:
        if importlib.util.find_spec("arjun") is not None:
            return [sys.executable, "-m", "arjun"]
        if self.has_tool("arjun"):
            return ["arjun"]
        return []
