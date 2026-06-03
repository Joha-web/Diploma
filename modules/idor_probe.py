"""
ReconX - Module: IDOR / BOLA candidate discovery and profile comparison.
"""

from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules.active_probe_base import ActiveProbeBase


ID_PARAM_RE = re.compile(
    r"(^|_|\b)(id|uuid|user|user_id|account|account_id|org|org_id|organization|"
    r"tenant|tenant_id|team|team_id|company|customer|owner|profile|project|order|"
    r"invoice|payment|subscription|workspace|member|role)(_id|id)?($|\b)",
    re.I,
)
HIGH_VALUE_PARAM_RE = re.compile(
    r"(user_id|account_id|org_id|organization_id|tenant_id|owner_id|customer_id|"
    r"company_id|workspace_id|member_id|role_id)",
    re.I,
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
# Recognise integer IDs including 0 and negatives (e.g. id=0, id=-1) so they are
# not silently ignored as IDOR candidates.
INTEGER_ID_RE = re.compile(r"^-?[0-9]{1,12}$")
PATH_ID_RE = re.compile(r"/([a-z0-9_-]{2,40})/([0-9]{1,12}|[0-9a-f-]{24,36})(?=/|$|\?)", re.I)
OPENAPI_PARAM_RE = re.compile(r"\{([^}]+)\}")
SENSITIVE_RESOURCE_RE = re.compile(
    r"(users?|accounts?|orgs?|organizations?|tenants?|teams?|customers?|profiles?|"
    r"projects?|orders?|invoices?|payments?|subscriptions?|workspaces?|members?|roles?)",
    re.I,
)

# Cache-busting / asset-versioning query params that look like IDs but never are.
CACHE_BUSTER_PARAMS = {
    "v", "_", "t", "ts", "time", "timestamp", "cb", "rev", "rnd", "rand",
    "build", "buildid", "build_id", "version", "ver", "hash", "h", "nonce",
    "cache", "nocache", "no-cache", "bust", "_bust", "r",
}

# URL path prefixes that point to static assets — never useful IDOR candidates.
STATIC_ASSET_PATH_RE = re.compile(
    r"/(?:_debugbar|debugbar|"
    r"assets?|static|public|build|dist|out|"
    r"node_modules|vendor|bower_components|"
    r"admin_assets|lte_assets|app_assets|"
    r"css|js|fonts?|images?|img|media|video|audio|svg|icons?|"
    r"\.well-known)(?:/|$)",
    re.I,
)

# File extensions that mark a URL as a static asset
STATIC_ASSET_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|bmp|tiff|"
    r"woff2?|ttf|otf|eot|"
    r"mp[34]|webm|ogg|wav|"
    r"pdf|zip|tar|gz|bz2|7z|"
    r"json|xml)(?:\?|$)",
    re.I,
)


class IDORProbeModule(ActiveProbeBase):
    name = "idor_probe"
    description = "IDOR / BOLA Candidate Analysis"
    required_tools: list[str] = []

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        parameter_results: dict | None = None,
        fuzzer_results: dict | None = None,
        openapi_results: dict | None = None,
        live_hosts: list | None = None,
    ):
        super().__init__(target, output_dir, config)
        self.parameter_results = parameter_results or {}
        self.fuzzer_results = fuzzer_results or {}
        self.openapi_results = openapi_results or {}
        self.live_hosts = live_hosts or []

    def run(self) -> dict:
        if not self.active_enabled():
            return {"findings": [], "candidates": [], "total": 0, "status": "disabled"}

        candidates = self.limit(self._candidates(), "max_candidates", 200)
        findings = self._classify_candidates(candidates)
        profile_findings: list[dict] = []
        if self.module_config().get("compare_profiles", False):
            profile_findings = self._compare_profiles(candidates)
            findings.extend(profile_findings)
        if self.module_config().get("check_anonymous", False):
            anon_findings = self._check_anonymous_access(candidates)
            findings.extend(anon_findings)
        if self.module_config().get("enumerate_ids", False):
            findings.extend(self._enumerate_ids(candidates, self.module_config()))

        findings = self.dedup_findings(findings)
        self.save_json(candidates, "idor_candidates.json")
        self.save_json(findings, "idor_findings.json")
        return {
            "findings": findings,
            "candidates": candidates,
            "total": len(findings),
            "candidate_count": len(candidates),
            "profile_comparisons": len(profile_findings),
            "profiles_available": self.profile_names_with_auth(),
        }

    def _candidates(self) -> list[dict]:
        candidates: dict[tuple[str, str, str], dict] = {}

        def add(item: dict) -> None:
            url = str(item.get("url", "") or "").strip()
            if not url.startswith(("http://", "https://")) or not self.is_in_scope(url):
                return
            kind = str(item.get("kind", "url"))
            subject = str(item.get("param") or item.get("path_param") or item.get("resource") or "")
            key = (url, kind, subject)
            existing = candidates.setdefault(key, dict(item, sources=[]))
            source = item.get("source")
            if source and source not in existing["sources"]:
                existing["sources"].append(source)
            for field in ("method", "path", "summary", "security", "effective_security"):
                if item.get(field) and not existing.get(field):
                    existing[field] = item[field]

        for item in self.parameter_results.get("parameters", []) or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            param = item.get("param") or item.get("name", "")
            if self._interesting_param(param):
                add({"url": url, "kind": "query", "param": param, "source": item.get("source", "parameter_discovery")})

        for url in self.parameter_results.get("parameterized_targets", []) or []:
            self._add_url_candidates(str(url), "parameterized_target", add)

        classified = self.fuzzer_results.get("classified", {}) or {}
        for bucket in ("with_params", "api", "auth"):
            for url in classified.get(bucket, []) or []:
                self._add_url_candidates(str(url), f"fuzzer:{bucket}", add)
        for url in self.fuzzer_results.get("all_endpoints", []) or []:
            self._add_url_candidates(str(url), "fuzzer", add)

        for endpoint in self.openapi_results.get("endpoints", []) or []:
            if not isinstance(endpoint, dict):
                continue
            url = endpoint.get("url", "")
            path = endpoint.get("path", urlparse(url).path)
            method = str(endpoint.get("method", "GET")).upper()
            path_params = OPENAPI_PARAM_RE.findall(str(path))
            for param in path_params:
                if self._interesting_param(param) or SENSITIVE_RESOURCE_RE.search(str(path)):
                    add({
                        "url": url,
                        "kind": "openapi_path_param",
                        "path_param": param,
                        "source": "openapi",
                        "method": method,
                        "path": path,
                        "summary": endpoint.get("summary", ""),
                        "security": endpoint.get("security"),
                        "effective_security": endpoint.get("effective_security"),
                    })
            self._add_url_candidates(url, "openapi", add, method=method)

        result = []
        for item in candidates.values():
            item["sources"] = sorted(set(item.get("sources", [])))
            result.append(item)
        return sorted(result, key=lambda value: (value.get("url", ""), value.get("kind", "")))

    def _add_url_candidates(self, url: str, source: str, add, method: str = "GET") -> None:
        if not url.startswith(("http://", "https://")):
            return
        if self._looks_like_static_asset(url):
            return
        for param, value in self.query_pairs(url):
            if self._is_cache_buster(param):
                continue
            # Require the param NAME to look ID-like — high-entropy values alone on
            # ordinary params produce too many FPs (e.g. tokens, version stamps, hashes).
            if self._interesting_param(param):
                add({
                    "url": url,
                    "kind": "query",
                    "param": param,
                    "value": value,
                    "value_shape": self._value_shape(value),
                    "source": source,
                    "method": method,
                })

        path = urlparse(url).path
        for resource, value in PATH_ID_RE.findall(path):
            # Skip when the matched resource is itself a static-asset folder.
            if STATIC_ASSET_PATH_RE.match(f"/{resource}/") or resource.lower() in {
                "assets", "static", "public", "build", "dist", "img", "images",
                "css", "js", "fonts", "media", "video", "audio", "svg", "icons",
            }:
                continue
            # Require a recognisable sensitive resource name OR a UUID/hex (high-entropy)
            # value. A bare integer on an unknown resource is too weak to flag.
            shape = self._value_shape(value)
            if SENSITIVE_RESOURCE_RE.search(resource) or shape in {"uuid", "hex_identifier"}:
                add({
                    "url": url,
                    "kind": "path",
                    "resource": resource,
                    "value": value,
                    "value_shape": shape,
                    "source": source,
                    "method": method,
                })

    def _classify_candidates(self, candidates: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for item in candidates:
            kind = item.get("kind")
            evidence = {
                "kind": kind,
                "param": item.get("param") or item.get("path_param"),
                "resource": item.get("resource"),
                "value_shape": item.get("value_shape"),
                "method": item.get("method", "GET"),
                "path": item.get("path"),
                "sources": item.get("sources", []),
                "effective_security": item.get("effective_security"),
            }
            if kind == "query":
                severity = "HIGH" if HIGH_VALUE_PARAM_RE.search(str(item.get("param", ""))) else "MEDIUM"
                findings.append(self.make_finding(
                    "idor_query_identifier_candidate",
                    item["url"],
                    evidence=evidence,
                    severity=severity,
                    confidence=0.76 if severity == "HIGH" else 0.70,
                ))
            elif kind == "path":
                findings.append(self.make_finding("idor_path_identifier_candidate", item["url"], evidence=evidence))
            elif kind == "openapi_path_param":
                findings.append(self.make_finding("idor_openapi_object_endpoint", item["url"], evidence=evidence))
        return findings

    def _compare_profiles(self, candidates: list[dict]) -> list[dict]:
        profiles = self.profile_names_with_auth()
        profile_a = self.module_config().get("profile_a", "user_a")
        profile_b = self.module_config().get("profile_b", "user_b")
        if profile_a not in profiles or profile_b not in profiles:
            self.warn("IDOR profile comparison needs auth_profiles.user_a and auth_profiles.user_b")
            return []

        findings: list[dict] = []
        timeout = self.request_timeout()
        max_requests = int(self.module_config().get("max_compare_requests", 40))
        sent = 0
        for item in candidates:
            method = str(item.get("method", "GET")).upper()
            if method not in ("GET", "HEAD") or sent + 2 > max_requests:
                continue
            url = item["url"]
            resp_a = self.get_with_profile(url, profile_a, timeout=timeout, verify=False)
            self.jitter_sleep()
            resp_b = self.get_with_profile(url, profile_b, timeout=timeout, verify=False)
            sent += 2
            if resp_a is None or resp_b is None:
                continue
            if not self._successful(resp_a) or not self._successful(resp_b):
                continue
            similarity = self._response_similarity(resp_a, resp_b)
            if similarity < float(self.module_config().get("similarity_threshold", 0.92)):
                continue
            findings.append(self.make_finding(
                "idor_profile_response_overlap",
                url,
                evidence={
                    "profile_a": profile_a,
                    "profile_b": profile_b,
                    "status_a": resp_a.status_code,
                    "status_b": resp_b.status_code,
                    "length_a": len(resp_a.text or ""),
                    "length_b": len(resp_b.text or ""),
                    "similarity": similarity,
                    "body_sha256": self._body_hash(resp_a.text or ""),
                    "candidate": item,
                },
                confidence=min(0.90, 0.60 + (similarity * 0.30)),
            ))
        return findings

    def _check_anonymous_access(self, candidates: list[dict]) -> list[dict]:
        findings: list[dict] = []
        timeout = self.request_timeout()
        max_requests = int(self.module_config().get("max_anonymous_requests", 20))
        sent = 0
        for item in candidates:
            method = str(item.get("method", "GET")).upper()
            if method not in ("GET", "HEAD") or sent >= max_requests:
                continue
            resp = self.get_with_profile(item["url"], "anonymous", timeout=timeout, verify=False)
            sent += 1
            if resp is None or not self._successful(resp):
                continue
            findings.append(self.make_finding(
                "idor_anonymous_object_access",
                item["url"],
                evidence={
                    "status": resp.status_code,
                    "length": len(resp.text or ""),
                    "candidate": item,
                    "body_sha256": self._body_hash(resp.text or ""),
                },
            ))
        return findings

    # ── Numeric ID enumeration (the IDOR "wordlist") ────────────────────────────
    @staticmethod
    def _id_value_set(baseline: int | None, cfg: dict) -> list[str]:
        """The set of integer IDs to substitute. ALWAYS includes 0 and negatives.

        "Try all numbers" is unbounded, so this is a configurable but exhaustive
        sweep: zero, a run of negatives, a low run from 1, the baseline's mirror
        (-baseline), and a window around the observed baseline. Order puts the
        interesting edge cases (0, negatives) first.
        """
        low = max(0, int(cfg.get("enum_low_range", 25)))
        window = max(0, int(cfg.get("enum_window", 5)))
        neg = max(0, int(cfg.get("enum_negative_count", 10)))
        cap = max(1, int(cfg.get("max_ids_per_candidate", 60)))

        ordered: list[int] = [0]
        ordered += [-i for i in range(1, neg + 1)]          # -1 .. -neg
        ordered += list(range(1, low + 1))                  # 1 .. low
        if baseline is not None:
            ordered.append(-baseline)                       # mirror of the real id
            ordered += list(range(max(0, baseline - window), baseline + window + 1))

        seen: set[int] = set()
        uniq: list[int] = []
        for value in ordered:
            if value not in seen:
                seen.add(value)
                uniq.append(value)
        return [str(value) for value in uniq[:cap]]

    @staticmethod
    def _sub_query_value(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        names = {key for key, _ in pairs}
        updated = [(key, value if key == param else existing) for key, existing in pairs]
        if param not in names:
            updated.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    @staticmethod
    def _sub_path_value(url: str, old_value: str, value: str) -> str:
        parsed = urlparse(url)
        new_path = re.sub(rf"/{re.escape(str(old_value))}(?=/|$)",
                          f"/{value}", parsed.path, count=1)
        return urlunparse(parsed._replace(path=new_path))

    def _enumerate_ids(self, candidates: list[dict], cfg: dict) -> list[dict]:
        """Substitute a full integer sweep (0, negatives, ...) into integer-ID
        candidates and flag endpoints whose object space is walkable."""
        profile = (self.profile_names_with_auth() or ["anonymous"])[0]
        max_candidates = int(cfg.get("max_enum_candidates", 10))
        max_requests = int(cfg.get("max_enum_requests", 200))
        min_distinct = int(cfg.get("enum_min_distinct", 2))
        guard_id = str(cfg.get("enum_guard_id", 988776655))
        timeout = self.request_timeout()

        enum_targets = [
            item for item in candidates
            if item.get("value_shape") == "integer"
            and re.fullmatch(r"-?\d{1,12}", str(item.get("value", "")))
            and str(item.get("method", "GET")).upper() in ("GET", "HEAD")
            and item.get("kind") in ("query", "path")
        ]
        if not enum_targets:
            return []
        self.info(f"ID enumeration over {min(len(enum_targets), max_candidates)} "
                  "integer candidate(s) (0, negatives, range)")

        findings: list[dict] = []
        sent = 0
        for item in enum_targets[:max_candidates]:
            if sent >= max_requests:
                break
            baseline = int(item["value"])

            def make_url(value: str) -> str:
                if item["kind"] == "query":
                    return self._sub_query_value(item["url"], item["param"], value)
                return self._sub_path_value(item["url"], item["value"], value)

            # Guard: a near-certainly-nonexistent ID to learn the not-found page.
            guard_resp = self.get_with_profile(make_url(guard_id), profile, timeout=timeout, verify=False)
            sent += 1
            guard_ok = guard_resp is not None and self._successful(guard_resp)
            guard_hash = self._body_hash(guard_resp.text or "") if guard_resp is not None else ""

            accessible: list[dict] = []
            body_hashes: set[str] = set()
            for value in self._id_value_set(baseline, cfg):
                if sent >= max_requests:
                    break
                resp = self.get_with_profile(make_url(value), profile, timeout=timeout, verify=False)
                self.jitter_sleep()
                sent += 1
                if resp is None or not self._successful(resp):
                    continue
                body_hash = self._body_hash(resp.text or "")
                # A 2xx that's byte-identical to the nonexistent-ID page is the
                # generic not-found/SPA shell, not a real object — skip it.
                if guard_ok and body_hash == guard_hash:
                    continue
                accessible.append({
                    "id": value, "status": resp.status_code,
                    "length": len(resp.text or ""), "body_sha256": body_hash,
                })
                body_hashes.add(body_hash)

            # Enumerable when distinct objects appear across the sweep, or any
            # object is reachable while the nonexistent guard ID is not.
            if accessible and (len(body_hashes) >= min_distinct or not guard_ok):
                negatives_hit = [a["id"] for a in accessible if a["id"].startswith("-")]
                subject = str(item.get("param") or item.get("resource") or "")
                high_value = bool(HIGH_VALUE_PARAM_RE.search(subject)
                                  or SENSITIVE_RESOURCE_RE.search(subject))
                findings.append(self.make_finding(
                    "idor_enumerable_object",
                    make_url(str(baseline)),
                    evidence={
                        "kind": item.get("kind"),
                        "param": item.get("param"),
                        "resource": item.get("resource"),
                        "baseline_id": baseline,
                        "profile": profile,
                        "ids_tried": len(self._id_value_set(baseline, cfg)) + 1,
                        "accessible_count": len(accessible),
                        "distinct_objects": len(body_hashes),
                        "zero_accessible": any(a["id"] == "0" for a in accessible),
                        "negative_ids_accessible": negatives_hit[:10],
                        "accessible_sample": accessible[:15],
                        "guard_id": guard_id,
                        "guard_successful": guard_ok,
                    },
                    severity="HIGH" if high_value else "MEDIUM",
                    confidence=min(0.88, 0.55 + 0.05 * len(body_hashes)),
                    exploitability="active",
                ))
        return findings

    @staticmethod
    def _interesting_param(param: str) -> bool:
        return bool(ID_PARAM_RE.search(str(param or "")))

    @staticmethod
    def _is_cache_buster(param: str) -> bool:
        return str(param or "").strip().lower() in CACHE_BUSTER_PARAMS

    @staticmethod
    def _looks_like_static_asset(url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        path = parsed.path or ""
        if STATIC_ASSET_PATH_RE.search(path):
            return True
        if STATIC_ASSET_EXT_RE.search(path):
            return True
        return False

    @staticmethod
    def _interesting_value(value: str) -> bool:
        value = str(value or "").strip()
        return bool(UUID_RE.match(value) or INTEGER_ID_RE.match(value))

    @staticmethod
    def _value_shape(value: str) -> str:
        value = str(value or "").strip()
        if UUID_RE.match(value):
            return "uuid"
        if INTEGER_ID_RE.match(value):
            return "integer"
        if re.match(r"^[0-9a-f]{24,36}$", value, re.I):
            return "hex_identifier"
        return "unknown"

    @staticmethod
    def _successful(resp) -> bool:
        return 200 <= int(getattr(resp, "status_code", 0)) < 300

    @staticmethod
    def _response_similarity(resp_a, resp_b) -> float:
        body_a = resp_a.text or ""
        body_b = resp_b.text or ""
        json_similarity = IDORProbeModule._json_response_similarity(resp_a, resp_b)
        if json_similarity is not None:
            return json_similarity
        if not body_a and not body_b:
            return 1.0
        if IDORProbeModule._body_hash(body_a) == IDORProbeModule._body_hash(body_b):
            return 1.0
        larger = max(len(body_a), len(body_b), 1)
        smaller = min(len(body_a), len(body_b))
        return smaller / larger

    @staticmethod
    def _json_response_similarity(resp_a, resp_b) -> float | None:
        try:
            data_a = resp_a.json()
            data_b = resp_b.json()
        except Exception:
            return None

        scalars_a = IDORProbeModule._flatten_scalar_values(data_a)
        scalars_b = IDORProbeModule._flatten_scalar_values(data_b)
        if not scalars_a and not scalars_b:
            return 1.0
        if not scalars_a or not scalars_b:
            return 0.0

        exact_overlap = len(scalars_a & scalars_b) / max(len(scalars_a | scalars_b), 1)
        canonical_a = IDORProbeModule._canonical_json(data_a)
        canonical_b = IDORProbeModule._canonical_json(data_b)
        text_similarity = SequenceMatcher(None, canonical_a, canonical_b).ratio()
        return (exact_overlap * 0.70) + (text_similarity * 0.30)

    @staticmethod
    def _flatten_scalar_values(value, prefix: str = "") -> set[str]:
        values: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                values.update(IDORProbeModule._flatten_scalar_values(child, name))
        elif isinstance(value, list):
            for idx, child in enumerate(value[:5]):
                name = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                values.update(IDORProbeModule._flatten_scalar_values(child, name))
        else:
            values.add(f"{prefix}={json.dumps(value, sort_keys=True, default=str)}")
        return values

    @staticmethod
    def _canonical_json(value) -> str:
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except TypeError:
            return str(value)

    @staticmethod
    def _body_hash(body: str) -> str:
        return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
