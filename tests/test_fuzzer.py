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
    assert classified["with_params"]
    # admin_panels and sensitive_files are now HTTP-verified;
    # unreachable test URLs correctly return empty verified lists
    # but unverified candidate counts are tracked
    assert classified.get("admin_panels_unverified", 0) >= 1
    assert classified.get("sensitive_files_unverified", 0) >= 1


def test_classify_recognises_modern_api_and_auth_surfaces(tmp_path):
    """New patterns must catch WP REST, JSON:API, OData, OIDC OAuth flows,
    Salesforce-style /services/data, Rails Devise /users/sign_in, and SAML ACS,
    while NOT collateral-matching unrelated paths like /register_steps.
    """
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])

    classified = module._classify([
        # api family
        "https://example.com/wp-json/wp/v2/posts",
        "https://example.com/odata/Customers",
        "https://example.com/services/data/v40.0/sobjects",
        "https://example.com/jsonrpc",
        "https://example.com/swagger/index.html",
        "https://example.com/openapi.json",
        # auth family
        "https://example.com/oauth/authorize",
        "https://example.com/oauth/token",
        "https://example.com/users/sign_in",
        "https://example.com/saml/acs",
        "https://example.com/connect/authorize",
        # negative — register_steps must NOT match register
        "https://example.com/register_steps",
    ])

    api_set = set(classified.get("api", []))
    auth_set = set(classified.get("auth", []))
    assert "https://example.com/wp-json/wp/v2/posts" in api_set
    assert "https://example.com/odata/Customers" in api_set
    assert "https://example.com/services/data/v40.0/sobjects" in api_set
    assert "https://example.com/jsonrpc" in api_set
    assert "https://example.com/swagger/index.html" in api_set
    assert "https://example.com/openapi.json" in api_set
    assert "https://example.com/oauth/authorize" in auth_set
    assert "https://example.com/oauth/token" in auth_set
    assert "https://example.com/users/sign_in" in auth_set
    assert "https://example.com/saml/acs" in auth_set
    assert "https://example.com/connect/authorize" in auth_set
    # Substring of `register` must not collide on path segment with suffix.
    assert "https://example.com/register_steps" not in auth_set


def test_classify_recognises_sourcemaps_as_sensitive(tmp_path):
    """A `.js.map` sourcemap is sensitive (leaks app source), not just a static asset."""
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    classified = module._classify(["https://example.com/main.js.map"])
    # The HTTP verification step strips unreachable URLs but the unverified
    # candidate counter must surface the hit.
    assert classified.get("sensitive_files_unverified", 0) >= 1


def test_classify_filters_modern_framework_build_paths(tmp_path):
    """Next.js / Nuxt / Astro / Vite build paths must not be classified as api/auth."""
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    classified = module._classify([
        "https://example.com/_next/static/chunks/main-abc.js",
        "https://example.com/_nuxt/entry.def.js",
        "https://example.com/_astro/page.ghi.js",
        "https://example.com/cdn-cgi/scripts/zaraz.js",
    ])
    # None of these are api/auth surfaces.
    assert classified.get("api", []) == []
    assert classified.get("auth", []) == []


def test_classify_surfaces_interesting_directories_and_endpoints(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])

    classified = module._classify([
        "https://example.com/backup/",
        "https://example.com/old/data.zip",
        "https://example.com/uploads/photo.png",
        "https://example.com/.git/config",
        "https://example.com/api/users",
        "https://example.com/api/v1/orders/123",
        "https://example.com/v2/products",
        "https://example.com/graphql/schema",
        "https://example.com/static/app.js",
    ])

    interesting_dirs = classified.get("interesting_directories", [])
    assert any("/backup" in u for u in interesting_dirs)
    assert any("/old" in u for u in interesting_dirs)
    assert any("/uploads" in u for u in interesting_dirs)
    assert any("/.git" in u for u in interesting_dirs)
    assert not any("/static/" in u for u in interesting_dirs)

    interesting_endpoints = classified.get("interesting_endpoints", [])
    assert "https://example.com/api/users" in interesting_endpoints
    assert "https://example.com/api/v1/orders/123" in interesting_endpoints
    assert "https://example.com/v2/products" in interesting_endpoints
    assert "https://example.com/graphql/schema" in interesting_endpoints
    assert "https://example.com/static/app.js" not in interesting_endpoints


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


def test_screenshot_interesting_skips_when_gowitness_missing(tmp_path, monkeypatch):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    monkeypatch.setattr(module, "has_tool", lambda name: False)
    result = module._screenshot_interesting({
        "admin_panels": ["https://example.com/admin"],
        "interesting_directories": ["https://example.com/backup/"],
    })
    assert result == []


def test_screenshot_interesting_runs_gowitness_and_tags_categories(tmp_path, monkeypatch):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    monkeypatch.setattr(module, "has_tool", lambda name: name == "gowitness")

    shots_dir = module.module_dir / "screenshots_interesting"

    def fake_exec(cmd, **kwargs):
        shots_dir.mkdir(parents=True, exist_ok=True)
        (shots_dir / "https_example_com_admin.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (shots_dir / "https_example_com_backup.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        return None

    monkeypatch.setattr(module, "exec", fake_exec)

    result = module._screenshot_interesting({
        "admin_panels": ["https://example.com/admin"],
        "interesting_directories": ["https://example.com/backup/"],
        "sensitive_files": [],
        "interesting_endpoints": [],
    })

    assert len(result) == 2
    by_filename = {s["filename"]: s for s in result}
    # Both shots should have been matched to a source URL
    assert all("url" in s for s in result)
    assert (module.module_dir / "screenshots_interesting.json").exists()
    assert (module.module_dir / "screenshot_targets.txt").exists()


def test_screenshot_interesting_disabled_via_config(tmp_path, monkeypatch):
    module = FuzzerModule(
        "example.com",
        str(tmp_path),
        {"scan": {"fuzzing": {"screenshot_interesting": False}}},
        live_hosts=[],
    )
    monkeypatch.setattr(module, "has_tool", lambda name: True)
    result = module._screenshot_interesting({"admin_panels": ["https://example.com/admin"]})
    assert result == []


def test_spa_endpoints_reads_session_file_and_filters_scope(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])

    # Write a spa_crawler/endpoints.txt sibling to the fuzzer's session
    spa_dir = tmp_path / "spa_crawler"
    spa_dir.mkdir(parents=True, exist_ok=True)
    (spa_dir / "endpoints.txt").write_text(
        "\n".join([
            "https://api.example.com/v1/users",
            "https://app.example.com/api/orders",
            "https://evil-example.com/leak",         # out of scope — should be filtered
            "ftp://example.com/file",                 # non-HTTP — should be ignored
            "https://example.com/spa/route",
        ]),
        encoding="utf-8",
    )

    out = module._spa_endpoints()

    assert "https://api.example.com/v1/users" in out
    assert "https://app.example.com/api/orders" in out
    assert "https://example.com/spa/route" in out
    assert not any("evil-example.com" in u for u in out)
    assert not any(u.startswith("ftp://") for u in out)


def test_spa_endpoints_returns_empty_when_file_missing(tmp_path):
    module = FuzzerModule("example.com", str(tmp_path), {}, live_hosts=[])
    assert module._spa_endpoints() == []
