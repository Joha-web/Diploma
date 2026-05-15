import threading
import time

from modules.fuzzer import FuzzerModule


def test_classify_patterns(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])

    classified = module._classify([
        "https://example.com/api/users",
        "https://example.com/login",
        "https://example.com/.env",
        "https://example.com/admin",
        "https://example.com/items?id=1",
    ])

    assert classified["api"]
    assert classified["auth"]
    assert classified["sensitive_files"]
    assert classified["admin_panels"]
    assert classified["with_params"]


def test_extract_urls_filters_out_of_scope(tmp_path):
    live_hosts = [
        {"url": "https://example.com"},
        {"url": "https://evil-example.com"},
        "https://api.example.com",
    ]
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=live_hosts)

    assert module._extract_urls() == ["https://api.example.com", "https://example.com"]


def test_fuzzer_execute_runs_without_external_tools_for_builtin_checks(tmp_path, monkeypatch):
    module = FuzzerModule(
        "example.com",
        str(tmp_path),
        {"scan": {"fuzzing": {"graphql_probe": False, "cloud_assets": False}}},
        live_hosts=["https://example.com"],
    )
    monkeypatch.setattr(module, "has_tool", lambda name: False)
    monkeypatch.setattr(module, "_robots_sitemap", lambda urls: ["https://example.com/robots-only"])

    result = module.execute()

    assert result["status"] == "completed"
    assert "https://example.com/robots-only" in result["all_endpoints"]


def test_extract_js_routes_handles_framework_manifests(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    content = """
    <Route path="/admin" element={Admin} />
    const routes = [{ path: "/vue/:id", component: User }];
    self.__BUILD_MANIFEST = {"__rewrites": {}, "/next/[slug]": ["x.js"]};
    self.__SSG_MANIFEST = new Set(["/pricing", "/blog/[slug]"]);
    """

    routes = module._extract_js_routes(content)

    assert "/admin" in routes
    assert "/vue/:id" in routes
    assert "/next/[slug]" in routes
    assert "/pricing" in routes
    assert "/blog/[slug]" in routes


def test_extract_js_routes_handles_nextjs_build_manifest_shape(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    content = """
    self.__BUILD_MANIFEST=function(s,c){return{
      __rewrites:{beforeFiles:[],afterFiles:[],fallback:[]},
      "/":["static/chunks/pages/index-a1b2c3.js"],
      "/account/settings":["static/chunks/pages/account/settings-d4e5f6.js"],
      "/blog/[slug]":["static/chunks/pages/blog/[slug]-abc123.js"],
      sortedPages:["/","/account/settings","/blog/[slug]"]
    }}();
    """

    routes = module._extract_js_routes(content)

    assert "/account/settings" in routes
    assert "/blog/[slug]" in routes


def test_graphql_mutation_fields_ignores_internal_fields():
    schema = {
        "types": [{
            "name": "Mutation",
            "fields": [
                {"name": "createUser"},
                {"name": "__typename"},
                {"name": "__schema"},
            ],
        }]
    }

    assert FuzzerModule._graphql_mutation_fields(schema, "Mutation") == ["createUser"]


def test_cloud_listing_checks_run_in_parallel(tmp_path, monkeypatch):
    module = FuzzerModule(
        "example.com",
        str(tmp_path),
        {"scan": {"fuzzing": {"cloud_listing_threads": 4}}},
        live_hosts=[],
    )
    active = 0
    max_active = 0
    lock = threading.Lock()

    def fake_check(asset):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return {"checked": True, "public": False}

    monkeypatch.setattr(module, "_check_cloud_listing", fake_check)
    seeded = [
        {
            "provider": "aws_s3",
            "kind": "aws_s3_virtual",
            "bucket": f"assets-{idx}",
            "container": "",
            "url": f"https://assets-{idx}.s3.amazonaws.com/",
            "source": "unit",
        }
        for idx in range(6)
    ]

    result = module._analyze_cloud_assets([], seeded)

    assert len(result) == 6
    assert max_active > 1


def test_check_cloud_listing_detects_public_s3_listing(tmp_path, monkeypatch):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    captured = {}

    class Response:
        status_code = 200
        text = "<ListBucketResult><Name>assets-example</Name></ListBucketResult>"

    def fake_http_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return Response()

    monkeypatch.setattr(module, "http_get", fake_http_get)

    result = module._check_cloud_listing({
        "provider": "aws_s3",
        "bucket": "assets-example",
        "container": "",
    })

    assert result["public"] is True
    assert captured["url"] == "https://assets-example.s3.amazonaws.com/?list-type=2&max-keys=5"
    assert captured["kwargs"]["enforce_scope"] is False


def test_public_cloud_listing_becomes_critical_finding(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])

    findings = module._build_findings([
        {
            "provider": "aws_s3",
            "bucket": "assets-example",
            "container": "",
            "url": "https://assets-example.s3.amazonaws.com/",
            "source": "unit",
            "listing": {"public": True, "url": "https://assets-example.s3.amazonaws.com/?list-type=2"},
        }
    ], [])

    assert findings[0]["id"] == "public_cloud_storage_listing"
    assert findings[0]["severity"] == "CRITICAL"


def test_js_secret_match_is_redacted_by_default(tmp_path):
    raw = 'api_key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'

    redacted = FuzzerModule._redact_js_secret_match(raw)

    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in redacted
    assert "ghp_..." in redacted
