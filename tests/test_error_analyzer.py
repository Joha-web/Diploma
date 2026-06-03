import json

from modules.error_analyzer import ErrorAnalyzerModule


def _module(tmp_path, **kwargs):
    config = {"scope": {"enforce": False}, "scan": {"error_analyzer": {"probe_errors": False, "scan_baseline": False}}}
    return ErrorAnalyzerModule("example.com", str(tmp_path), config, **kwargs)


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def _write_audit(tmp_path, entries):
    path = tmp_path / "error_analyzer" / "audit.jsonl"
    # audit.jsonl lives in the session dir (output_dir), not the module dir
    audit = tmp_path / "audit.jsonl"
    audit.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")


def test_aggregates_5xx_and_401_from_audit_log(tmp_path):
    # Scope enforced (default) so non-target hosts (github) are excluded.
    module = ErrorAnalyzerModule("example.com", str(tmp_path),
                                 {"scan": {"error_analyzer": {}}})
    _write_audit(tmp_path, [
        {"url": "https://example.com/a", "status": 500},
        {"url": "https://example.com/b", "status": 503},
        {"url": "https://example.com/c", "status": 500},
        {"url": "https://example.com/login", "status": 401},
        {"url": "https://example.com/admin", "status": 401},
        {"url": "https://example.com/ok", "status": 200},
        # out-of-scope third-party API (logged in_scope true) must be excluded
        {"url": "https://api.github.com/x", "status": 500, "in_scope": True},
    ])
    s5xx, s401, _ = module._aggregate_audit_statuses(module.module_config())

    assert s5xx["total"] == 3
    assert s5xx["hosts"][0]["host"] == "example.com"
    assert s5xx["hosts"][0]["statuses"] == {"500": 2, "503": 1}
    assert s401["total"] == 2
    assert all(h["host"] == "example.com" for h in s5xx["hosts"])  # github excluded


def test_status_findings_respect_thresholds(tmp_path):
    module = _module(tmp_path)
    agg = {"hosts": [{"host": "x.com", "count": 4, "statuses": {"500": 4}, "sample_urls": []}]}
    cfg = {"min_5xx": 3}
    findings = module._status_findings(agg, "5xx", cfg)
    assert findings and findings[0]["id"] == "server_5xx_hotspot"
    # below threshold → nothing
    agg2 = {"hosts": [{"host": "x.com", "count": 1, "statuses": {}, "sample_urls": []}]}
    assert module._status_findings(agg2, "5xx", cfg) == []


def test_detect_sql_error_in_response(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": True, "probe_errors": False, "probe_debug": False}}},
        live_hosts=["https://example.com/page"],
    )
    body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '''"
    monkeypatch.setattr(module, "http_get", lambda url, **kw: _Resp(text=body))
    sql_errors, server_errors, _debug = module._detect_error_disclosure(module.module_config())

    assert len(sql_errors) == 1
    assert sql_errors[0]["dbms"] in ("MySQL", "MySQL/MariaDB")
    assert "SQL syntax" in sql_errors[0]["snippet"]
    assert server_errors == []


def test_detect_stack_trace(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": True, "probe_errors": False, "probe_debug": False}}},
        live_hosts=["https://example.com/boom"],
    )
    monkeypatch.setattr(module, "http_get",
                        lambda url, **kw: _Resp(text="Traceback (most recent call last):\n  File x"))
    sql_errors, server_errors, _debug = module._detect_error_disclosure(module.module_config())
    assert sql_errors == []
    assert server_errors and server_errors[0]["stack"] == "Python"


def test_detect_django_debug_mode(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": False, "probe_errors": False, "probe_debug": True}}},
        live_hosts=["https://example.com"],
    )
    page = ("Page not found (404). Using the URLconf defined in myapp.urls, "
            "Django tried these URL patterns, in this order:")
    monkeypatch.setattr(module, "http_get", lambda url, **kw: _Resp(text=page, status_code=404))
    sql_errors, server_errors, debug_modes = module._detect_error_disclosure(module.module_config())

    assert len(debug_modes) == 1
    assert "Django" in debug_modes[0]["framework"]
    assert sql_errors == [] and server_errors == []


def test_debug_page_not_double_counted_as_stack_trace(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": True, "probe_errors": False, "probe_debug": False}}},
        live_hosts=["https://example.com/x"],
    )
    # Werkzeug debugger page also contains a Python traceback — count once, as debug.
    body = "Werkzeug Debugger\nTraceback (most recent call last):\n  File app.py"
    monkeypatch.setattr(module, "http_get", lambda url, **kw: _Resp(text=body))
    _sql, server_errors, debug_modes = module._detect_error_disclosure(module.module_config())

    assert len(debug_modes) == 1 and "Werkzeug" in debug_modes[0]["framework"]
    assert server_errors == []  # not also reported as a generic stack trace


def test_run_flags_framework_debug_enabled(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": True, "probe_errors": False, "probe_debug": False}}},
        live_hosts=["https://example.com"],
    )
    monkeypatch.setattr(module, "http_get",
                        lambda url, **kw: _Resp(text="Whoops, looks like something went wrong."))
    result = module.run()
    assert any(f["id"] == "framework_debug_enabled" for f in result["findings"])
    assert result["debug_modes"][0]["framework"].startswith("Laravel")


def test_probe_injects_payload_into_param(tmp_path):
    module = _module(tmp_path)
    injected = module._inject("https://example.com/x?id=5&p=1", "id", "'")
    assert injected == "https://example.com/x?id=5%27&p=1"


def test_run_end_to_end_builds_findings(tmp_path, monkeypatch):
    module = ErrorAnalyzerModule(
        "example.com", str(tmp_path),
        {"scope": {"enforce": False},
         "scan": {"error_analyzer": {"scan_baseline": True, "probe_errors": False, "min_5xx": 2}}},
        live_hosts=["https://example.com/p"],
    )
    _write_audit(tmp_path, [
        {"url": "https://example.com/a", "status": 500},
        {"url": "https://example.com/b", "status": 500},
    ])
    monkeypatch.setattr(module, "http_get",
                        lambda url, **kw: _Resp(text="ORA-00933: SQL command not properly ended"))
    result = module.run()

    ids = {f["id"] for f in result["findings"]}
    assert "sql_error_disclosure" in ids
    assert "server_5xx_hotspot" in ids
    assert result["status_5xx"]["total"] == 2
