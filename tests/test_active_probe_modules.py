from modules.api_key_validator import APIKeyValidatorModule
from modules.api_schema_audit import APISchemaAuditModule
from modules.cache_poison import CachePoisonModule
from modules.deserialization_probe import DeserializationProbeModule
from modules.graphql_audit import GraphQLAuditModule
from modules.host_header_injection import HostHeaderInjectionModule
from modules.http_smuggling import HTTPSmugglingModule
from modules.idor_probe import IDORProbeModule
from modules.js_security_audit import JSSecurityAuditModule
from modules.jwt_audit import JWTAuditModule
from modules.oauth_probe import OAuthProbeModule
from modules.open_redirect_probe import OpenRedirectProbeModule
from modules.prototype_pollution import PrototypePollutionModule
from modules.race_condition import RaceConditionModule
from modules.websocket_probe import WebSocketProbeModule
from modules.xxe_probe import XXEProbeModule

try:
    import jwt
except ImportError:  # pragma: no cover
    jwt = None


class Response:
    def __init__(self, text="", status_code=200, headers=None, data=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self._data = data

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


def test_http_smuggling_reports_timing_hit(tmp_path, monkeypatch):
    module = HTTPSmugglingModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "_raw_send", lambda *args, **kwargs: 5.0)

    finding = module._probe_cl_te("example.com", 443, "https", "/", "https://example.com", {})

    assert finding["id"] == "http_smuggling_cl_te"
    assert finding["severity"] == "HIGH"


def test_oauth_oidc_config_flags_weak_settings(tmp_path):
    module = OAuthProbeModule("example.com", str(tmp_path), {})

    findings = module._audit_oidc_config(
        {
            "issuer": "http://example.com",
            "id_token_signing_alg_values_supported": ["RS256", "none"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "request_uri_parameter_supported": True,
        },
        "https://example.com/.well-known/openid-configuration",
    )

    assert {finding["id"] for finding in findings} >= {"oidc_http_issuer", "oidc_weak_algorithms"}


def test_cache_poison_detects_reflected_unkeyed_header(tmp_path, monkeypatch):
    module = CachePoisonModule("example.com", str(tmp_path), {})
    responses = [
        Response("baseline"),
        Response(f"<a href='https://{module.marker}/'>x</a>", headers={"X-Cache": "MISS"}),
    ]
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: responses.pop(0))

    finding = module._probe_header("https://example.com", object(), {}, {"cache_detected": False}, "X-Forwarded-Host", "host")

    assert finding["id"] == "cache_poisoning_unkeyed_header"
    assert finding["evidence"]["header"] == "X-Forwarded-Host"


def test_host_header_detects_reset_poisoning_indicator(tmp_path, monkeypatch):
    module = HostHeaderInjectionModule("example.com", str(tmp_path), {})
    responses = [Response("baseline"), Response(f"reset link https://{module.marker}/token")]
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: responses.pop(0) if responses else Response(""))

    findings = module._probe("https://example.com/forgot-password", object(), {})

    assert findings[0]["id"] == "password_reset_poisoning_indicator"


def test_prototype_pollution_query_reflection(tmp_path, monkeypatch):
    module = PrototypePollutionModule("example.com", str(tmp_path), {})
    responses = [Response("baseline"), Response(f"ok {module.marker_value}")]
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: responses.pop(0))

    findings = module._probe_query("https://example.com/api/search", object(), {})

    assert findings[0]["id"] == "sspp_qs_reflection"


def test_xxe_payload_and_oob_matching(tmp_path):
    module = XXEProbeModule("example.com", str(tmp_path), {})

    payload = module._xml_payload("http://xxe0000.oast.pro/xxe")
    matches = module._matching_interactions([{"full-id": "xxe0000.oast.pro"}], "xxe0000")

    assert "<!DOCTYPE reconx" in payload
    assert matches


def test_deserialization_detects_serialized_parameter(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})

    marker = module._serialized_marker("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==")

    assert marker == "java_serialized_base64"


def test_graphql_audit_detects_batching(tmp_path, monkeypatch):
    module = GraphQLAuditModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "http_post", lambda *args, **kwargs: Response(data=[{"data": {"__typename": "Query"}}] * 2))

    findings = module._check_batching("https://example.com/graphql", object(), {"batch_size": 2})

    assert findings[0]["id"] == "graphql_batching_enabled"


def test_race_condition_candidates_from_keywords(tmp_path):
    module = RaceConditionModule(
        "example.com",
        str(tmp_path),
        {},
        fuzzer_results={"classified": {"api": ["https://example.com/api/redeem?coupon=SAVE"]}},
    )

    assert module._candidates()[0]["matched_keywords"] == ["redeem", "coupon"]


def test_api_key_validator_extracts_and_redacts_candidates(tmp_path):
    module = APIKeyValidatorModule(
        "example.com",
        str(tmp_path),
        {},
        fuzzer_results={"classified": {"js_secrets": [{
            "match": "token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'",
            "file": "https://example.com/app.js",
        }]}},
    )

    candidate = module._candidates()[0]

    assert candidate["type"] == "github_token"
    assert "..." in candidate["redacted"]
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in candidate["redacted"]


def test_open_redirect_detects_location_to_attacker(tmp_path, monkeypatch):
    module = OpenRedirectProbeModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "http_get", lambda *args, **kwargs: Response(status_code=302, headers={"Location": "https://attacker.reconx.invalid/"}))

    finding = module._probe("https://example.com/login?next=/", object(), {})

    assert finding["id"] == "open_redirect"


def test_idor_probe_classifies_identifier_candidates(tmp_path):
    module = IDORProbeModule(
        "example.com",
        str(tmp_path),
        {},
        parameter_results={"parameters": [{"url": "https://example.com/api/users?user_id=42", "param": "user_id"}]},
        openapi_results={"endpoints": [{"url": "https://example.com/api/accounts/{account_id}", "path": "/api/accounts/{account_id}", "method": "GET"}]},
    )

    findings = module._classify_candidates(module._candidates())
    ids = {finding["id"] for finding in findings}

    assert "idor_query_identifier_candidate" in ids
    assert "idor_openapi_object_endpoint" in ids
    assert all("risk_score" in finding for finding in findings)


def test_jwt_audit_flags_weak_secret_and_header_issues(tmp_path):
    if jwt is None:
        return
    token = jwt.encode(
        {"sub": "123", "iat": 1000, "exp": 1000 + 10 * 24 * 3600},
        "secret",
        algorithm="HS256",
        headers={"kid": "../../keys/jwt.key", "jku": "https://evil.example/jwks.json"},
    )
    module = JWTAuditModule(
        "example.com",
        str(tmp_path),
        {"scan": {"jwt_audit": {"tokens": [token], "weak_secrets": ["secret"], "max_token_ttl_seconds": 3600}}},
    )

    findings = module.run()["findings"]
    ids = {finding["id"] for finding in findings}

    assert {"jwt_weak_hmac_secret", "jwt_kid_path_traversal", "jwt_untrusted_jku_x5u", "jwt_long_lived_token"} <= ids


def test_websocket_probe_detects_unauthenticated_and_origin_issues(tmp_path, monkeypatch):
    module = WebSocketProbeModule("example.com", str(tmp_path), {})
    monkeypatch.setattr(module, "_handshake", lambda *args, **kwargs: {"status": 101, "headers": {"server": "test"}})

    findings = module._probe_endpoint("wss://example.com/ws")
    ids = {finding["id"] for finding in findings}

    assert "websocket_unauthenticated_connect" in ids
    assert "websocket_origin_not_validated" in ids


def test_api_schema_audit_flags_unauthenticated_sensitive_route(tmp_path):
    module = APISchemaAuditModule("example.com", str(tmp_path), {})
    endpoint = {
        "method": "POST",
        "url": "https://example.com/api/users/{user_id}",
        "path": "/api/users/{user_id}",
        "summary": "Update user profile",
        "effective_security": [],
        "security_defined": True,
        "request_schema": {"type": "object", "additionalProperties": True},
        "responses": {"200": {"description": "ok"}},
    }

    ids = {finding["id"] for finding in module._audit_endpoint(endpoint)}

    assert "openapi_sensitive_route_without_auth" in ids
    assert "openapi_dangerous_method_without_auth" in ids
    assert "openapi_overly_broad_schema" in ids


def test_js_security_audit_finds_common_static_risks(tmp_path):
    module = JSSecurityAuditModule("example.com", str(tmp_path), {})
    content = """
      const q = new URLSearchParams(location.search).get('q');
      document.querySelector('#out').innerHTML = q;
      window.addEventListener('message', function(event) { document.body.innerHTML = event.data; });
      const gql = "/graphql";
      location.href = new URLSearchParams(location.search).get('next');
    """

    ids = {finding["id"] for finding in module._analyse_js("https://example.com/app.js", content)}

    assert "js_dom_xss_sink" in ids
    assert "js_postmessage_missing_origin_check" in ids
    assert "js_hardcoded_graphql_endpoint" in ids
    assert "js_unsafe_redirect" in ids
