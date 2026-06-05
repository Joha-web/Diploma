"""Parser/targeting coverage for xxe_probe and deserialization_probe.

These exercise the pure detection logic (serialized-object markers, ViewState
extraction, error-signature matching, XXE payload variants and XML-hint
targeting) so version drift or regex regressions surface in CI rather than only
during a live scan.
"""

from types import SimpleNamespace

from modules.deserialization_probe import DeserializationProbeModule
from modules.xxe_probe import XXEProbeModule, _xxe_payload_variants


# --------------------------------------------------------------------------- #
# deserialization_probe
# --------------------------------------------------------------------------- #

def test_serialized_markers_per_language(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    cases = {
        # Java ObjectOutputStream, base64 (rO0AB...)
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==": "java_serialized_base64",
        # Python pickle protocol 4 (\x80\x04\x95 -> gASV...) and protocol 2 dict
        "gASVAAAAAAAAAA==": "python_pickle",
        "gAJ9cQ==": "python_pickle",
        "cos\nsystem": "python_pickle",
        # PHP serialize()
        'O:8:"stdClass":0:{}': "php_serialized",
        "a:1:{i:0;i:1;}": "php_serialized",
        # Ruby Marshal (\x04\x08 -> BAg...)
        "BAgiCGZvbw==": "ruby_marshal",
        # Node.js node-serialize function payload
        '{"rce":"_$$ND_FUNC$$_function(){}"}': "node_serialize_function",
        # ASP.NET ViewState canonical prefix
        "/wEPDwUKLT...": "aspnet_viewstate_like",
    }
    for value, expected in cases.items():
        assert module._serialized_marker(value) == expected, value


def test_loose_viewstate_prefix_is_not_flagged(tmp_path):
    """A base64 blob beginning '/w' but not '/wE' must not be called ViewState."""
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    # '/wd...' -> first byte 0xFF, but not the \xff\x01 ViewState version marker.
    assert module._serialized_marker("/wdG90YWxseS1ub3Qtdmlld3N0YXRl") == ""


def test_serialized_marker_ignores_plain_values(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    for value in ("", "12345", "hello world", "eyJhbGciOiJIUzI1NiJ9"):
        assert module._serialized_marker(value) == ""


def test_serialized_object_in_query_parameter(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    url = "https://example.com/load?state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
    module.http_get = lambda *a, **k: None  # skip the live fetch
    findings = module._inspect_url(url, session=None, cfg={})
    assert any(f["id"] == "serialized_object_in_parameter" for f in findings)
    hit = next(f for f in findings if f["id"] == "serialized_object_in_parameter")
    assert hit["evidence"]["param"] == "state"
    assert hit["evidence"]["marker"] == "java_serialized_base64"


def test_viewstate_and_error_signature_in_body(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    body = (
        '<form><input type="hidden" name="__VIEWSTATE" '
        'value="/wEPDwUKLTEx..." /></form>'
        "<pre>java.io.ObjectInputStream readObject failed</pre>"
    )
    module.http_get = lambda *a, **k: SimpleNamespace(text=body, status_code=200)
    findings = module._inspect_url("https://example.com/page", session=None, cfg={})
    ids = {f["id"] for f in findings}
    assert "aspnet_viewstate_detected" in ids
    assert "deserialization_error_signature" in ids
    vs = next(f for f in findings if f["id"] == "aspnet_viewstate_detected")
    assert vs["evidence"]["format"] == "ASP.NET LosFormatter"


def test_error_signature_fires_once(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    body = "InvalidClassException and also NotSerializableException both present"
    module.http_get = lambda *a, **k: SimpleNamespace(text=body, status_code=200)
    findings = module._inspect_url("https://example.com/x", session=None, cfg={})
    sigs = [f for f in findings if f["id"] == "deserialization_error_signature"]
    assert len(sigs) == 1  # breaks after first match, no per-signature spam


def test_dedup_collapses_repeats(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    f = module._finding("x", "HIGH", "https://example.com/a", "t", {"param": "p"})
    assert len(module._dedup([f, dict(f)])) == 1


def _resp(text="", cookies=()):
    cookie_objs = [SimpleNamespace(name=n, value=v) for n, v in cookies]
    return SimpleNamespace(text=text, status_code=200, cookies=cookie_objs)


def test_serialized_object_in_cookie(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    module.http_get = lambda *a, **k: _resp(
        cookies=[("sess", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==")])
    findings = module._inspect_url("https://example.com/", session=None, cfg={})
    hit = next(f for f in findings if f["id"] == "serialized_object_in_cookie")
    assert hit["evidence"]["cookie"] == "sess"
    assert hit["evidence"]["marker"] == "java_serialized_base64"


def test_url_encoded_php_cookie_is_decoded(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    # PHP serialized object, percent-encoded as it would appear in Set-Cookie.
    module.http_get = lambda *a, **k: _resp(
        cookies=[("data", "O%3A8%3A%22stdClass%22%3A0%3A%7B%7D")])
    findings = module._inspect_url("https://example.com/", session=None, cfg={})
    hit = next(f for f in findings if f["id"] == "serialized_object_in_cookie")
    assert hit["evidence"]["marker"] == "php_serialized"


def test_distinct_cookies_not_collapsed_by_dedup(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    module.http_get = lambda *a, **k: _resp(cookies=[
        ("a", "rO0ABXNyAAAA"), ("b", "rO0ABXNyBBBB")])
    findings = module._inspect_url("https://example.com/", session=None, cfg={})
    cookie_hits = [f for f in findings if f["id"] == "serialized_object_in_cookie"]
    assert {f["evidence"]["cookie"] for f in cookie_hits} == {"a", "b"}


def test_serialized_object_in_hidden_field(tmp_path):
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    body = ('<form><input name="payload" type="hidden" '
            'value="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="></form>')
    module.http_get = lambda *a, **k: _resp(text=body)
    findings = module._inspect_url("https://example.com/f", session=None, cfg={})
    hit = next(f for f in findings if f["id"] == "serialized_object_in_hidden_field")
    assert hit["evidence"]["field"] == "payload"
    assert hit["evidence"]["marker"] == "java_serialized_base64"


def test_hidden_field_scan_skips_aspnet_state_fields(tmp_path):
    """__VIEWSTATE is reported once (as ViewState), not also as a hidden field."""
    module = DeserializationProbeModule("example.com", str(tmp_path), {})
    body = '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKLTEx...">'
    module.http_get = lambda *a, **k: _resp(text=body)
    findings = module._inspect_url("https://example.com/p", session=None, cfg={})
    ids = [f["id"] for f in findings]
    assert "aspnet_viewstate_detected" in ids
    assert "serialized_object_in_hidden_field" not in ids


# --------------------------------------------------------------------------- #
# xxe_probe
# --------------------------------------------------------------------------- #

def test_xxe_payload_variants_carry_callback_url():
    url = "http://xxe0001.oast.pro/xxe"
    variants = _xxe_payload_variants(url)
    names = {name for name, _ct, _body in variants}
    assert {
        "standard_external_entity",
        "svg_external_entity",
        "soap_envelope_xxe",
        "parameter_entity_dtd_chain",
        "xinclude_external",
    } <= names
    # Every variant must embed the OOB callback URL or it can never fire.
    for _name, _ct, body in variants:
        assert url in body


def test_xxe_targets_keep_only_xml_like_urls(tmp_path):
    module = XXEProbeModule(
        "example.com",
        str(tmp_path),
        {},
        fuzzer_results={"classified": {"with_params": [
            "https://example.com/soap/endpoint",
            "https://example.com/api/products",
        ]}},
    )
    targets = module._targets()
    assert "https://example.com/soap/endpoint" in targets
    assert "https://example.com/api/products" not in targets


def test_xxe_oob_payload_host_extraction(tmp_path):
    module = XXEProbeModule("example.com", str(tmp_path), {})
    payload = module._oob_payload("https://abc.oast.pro/path", "xxe0007")
    assert payload == "http://xxe0007.abc.oast.pro/xxe"
