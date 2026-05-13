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
