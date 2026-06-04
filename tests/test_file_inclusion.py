import base64
import json
import subprocess

from modules.file_inclusion import FileInclusionModule


def _module(tmp_path, cfg=None, **kwargs):
    config = {"scope": {"enforce": False}, "scan": {"file_inclusion": cfg or {}}}
    return FileInclusionModule("example.com", str(tmp_path), config, **kwargs)


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def test_targets_prefers_file_inclusion_param_names(tmp_path):
    module = _module(
        tmp_path,
        parameter_results={"parameters": [
            {"url": "https://example.com/index?page=home", "param": "page"},
            {"url": "https://example.com/list?id=5", "param": "id"},
        ]},
    )
    targets = {t["url"]: t["params"] for t in module._targets(module.module_config())}
    assert targets["https://example.com/index?page=home"] == ["page"]
    # 'id' is not a file-inclusion-prone name and fuzz_all is off
    assert "https://example.com/list?id=5" not in targets


def test_targets_fuzz_all_includes_every_param(tmp_path):
    module = _module(
        tmp_path, cfg={"fuzz_all_params": True},
        parameter_results={"parameters": [{"url": "https://example.com/x?id=5", "param": "id"}]},
    )
    targets = module._targets(module.module_config())
    assert targets and targets[0]["params"] == ["id"]


def test_inject_fuzz_keyword_survives(tmp_path):
    module = _module(tmp_path)
    assert module._inject_fuzz("https://example.com/p?file=x&a=1", "file") == \
        "https://example.com/p?file=FUZZ&a=1"


def test_parse_ffuf_extracts_payload_hits(tmp_path):
    module = _module(tmp_path)
    out = tmp_path / "file_inclusion" / "ffuf" / "lfi_001.json"
    out.write_text(json.dumps({"results": [
        {"input": {"FUZZ": "../../../../etc/passwd"}, "status": 200, "length": 1234,
         "url": "https://example.com/p?file=../../../../etc/passwd"},
    ]}), encoding="utf-8")
    hits = module._parse_ffuf(out, "https://example.com/p?file=x", "file", "/wl/LFI-Jhaddix.txt")
    assert len(hits) == 1
    assert hits[0]["payload"] == "../../../../etc/passwd"
    assert hits[0]["signature"] == "/etc/passwd (Linux)"
    assert hits[0]["wordlist"] == "LFI-Jhaddix.txt"


def test_run_lfi_invokes_ffuf_and_builds_findings(tmp_path, monkeypatch):
    module = _module(
        tmp_path, cfg={"rfi": False, "lfi_wordlists": [str(tmp_path / "wl.txt")]},
        parameter_results={"parameters": [{"url": "https://example.com/p?file=home", "param": "file"}]},
    )
    (tmp_path / "wl.txt").write_text("../../etc/passwd\n", encoding="utf-8")
    monkeypatch.setattr(module, "has_tool", lambda t: t == "ffuf")
    captured = {}

    def fake_exec(cmd, timeout=300, label=None, **kw):
        captured["cmd"] = cmd
        # ffuf writes its JSON to the -o path
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            json.dump({"results": [{"input": {"FUZZ": "../../etc/passwd"}, "status": 200,
                                    "url": "https://example.com/p?file=../../etc/passwd"}]}, fh)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(module, "exec", fake_exec)
    result = module.run()

    assert "-mr" in captured["cmd"] and "FUZZ" in " ".join(captured["cmd"])
    assert any(f["id"] == "lfi_detected" for f in result["findings"])
    assert result["findings"][0]["severity"] == "HIGH"


def test_run_rfi_detects_data_wrapper_reflection(tmp_path, monkeypatch):
    module = _module(
        tmp_path, cfg={"lfi": False},
        parameter_results={"parameters": [{"url": "https://example.com/p?file=home", "param": "file"}]},
    )

    from urllib.parse import unquote

    def fake_get(url, **kw):
        # The payload is URL-encoded in the query; a real server decodes it.
        u = unquote(url)
        if "data://text/plain;base64," in u:
            b64 = u.split("base64,")[1].split("&")[0]
            return _Resp(text="page: " + base64.b64decode(b64).decode())
        return _Resp(text="nothing")

    monkeypatch.setattr(module, "http_get", fake_get)
    result = module.run()

    assert any(f["id"] == "rfi_detected" for f in result["findings"])
    assert result["rfi"][0]["wrapper"] == "data://"


def test_wordlists_resolve_existing_only(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("x", encoding="utf-8")
    module = _module(tmp_path, cfg={"lfi_wordlists": [str(real), "/nope/missing.txt"]})
    assert module._wordlists(module.module_config()) == [str(real)]


def test_detect_lfi_passwd_win_and_php_filter():
    # /etc/passwd content
    assert "Linux" in FileInclusionModule._detect_lfi("root:x:0:0:root:/root:/bin/bash\n")
    # win.ini content
    assert "Windows" in FileInclusionModule._detect_lfi("[fonts]\nfor 16-bit app support")
    # raw PHP source leak
    assert "PHP source disclosure" == FileInclusionModule._detect_lfi("<?php $db='secret'; ?>")
    # php://filter base64 output that decodes to PHP source
    blob = base64.b64encode(b"<?php $config = 'db_password'; ?>" * 3).decode()
    assert "php://filter" in FileInclusionModule._detect_lfi(f"<html>{blob}</html>")
    # benign page → no detection
    assert FileInclusionModule._detect_lfi("<html>welcome home</html>") == ""


def test_lfi_payloads_include_encodings_and_php_filter(tmp_path):
    module = _module(tmp_path)
    payloads = [p for p, _ in module._lfi_payloads("view.php")]
    assert "/etc/passwd" in payloads
    assert any("%2e%2e%2f" in p for p in payloads)             # url-encoded traversal
    assert any("%252f" in p for p in payloads)                 # double-encoded
    assert any("....//" in p for p in payloads)                # ....// bypass
    assert any(p.endswith("%00") for p in payloads)            # null-byte
    assert any("win.ini" in p for p in payloads)               # windows
    assert "php://filter/convert.base64-encode/resource=view.php" in payloads  # page-aware php filter


def test_run_inband_lfi_confirms_via_signature(tmp_path, monkeypatch):
    module = _module(tmp_path, cfg={"inband_lfi": True, "max_lfi_requests": 50})
    # The vulnerable param returns /etc/passwd when a traversal payload is sent.
    def fake_get(url, **kwargs):
        if "passwd" in url or "%2e%2e" in url or "%252f" in url:
            return _Resp("root:x:0:0:root:/root:/bin/bash")
        return _Resp("welcome")
    monkeypatch.setattr(module, "http_get", fake_get)
    hits = module._run_inband_lfi([{"url": "https://example.com/view.php?page=home", "params": ["page"]}],
                                  module.module_config())
    assert len(hits) == 1
    assert hits[0]["signature"] == "/etc/passwd (Linux)"
    assert hits[0]["tool"] == "in-band probe"


def test_run_inband_lfi_no_false_positive(tmp_path, monkeypatch):
    module = _module(tmp_path, cfg={"inband_lfi": True})
    monkeypatch.setattr(module, "http_get", lambda url, **kw: _Resp("welcome home, nothing here"))
    hits = module._run_inband_lfi([{"url": "https://example.com/view.php?page=home", "params": ["page"]}],
                                  module.module_config())
    assert hits == []


def test_oob_url_and_matching_interactions():
    assert FileInclusionModule._oob_url("http://abc.oob.example/", "rfi0001", "/x.txt") \
        == "http://rfi0001.abc.oob.example/x.txt"
    interactions = [{"unique-id": "rfi0001.abc.oob.example", "protocol": "http"}]
    assert FileInclusionModule._matching_interactions(interactions, "rfi0001", "abc.oob.example")
    assert FileInclusionModule._matching_interactions(interactions, "nope", "abc.oob.example") == []


def test_run_oob_rfi_confirms_on_callback(tmp_path, monkeypatch):
    module = _module(tmp_path, cfg={"rfi_oob_wait": 0})
    runtime = {"callback_url": "http://abc.oob.example/", "client_available": True,
               "cooldown_period": 0, "interactions_log": ""}
    monkeypatch.setattr(module, "_start_oob_runtime", lambda cfg: runtime)
    monkeypatch.setattr(module, "_stop_oob_client", lambda rt: None)
    fetched = []
    monkeypatch.setattr(module, "http_get", lambda url, **kw: (fetched.append(url), _Resp("ok"))[1])
    # The server "fetched" our URL → interactsh logs an interaction for token rfi0000.
    (module.module_dir / "interactsh_interactions.jsonl").write_text(
        json.dumps({"unique-id": "rfi0000.abc.oob.example", "protocol": "http",
                    "remote-address": "203.0.113.9"}) + "\n", encoding="utf-8")

    hits = module._run_oob_rfi([{"url": "https://example.com/view.php?page=home", "params": ["page"]}],
                               {"rfi_oob_wait": 0})

    assert len(hits) == 1 and hits[0]["tool"] == "interactsh"
    assert fetched and "rfi0000.abc.oob.example" in fetched[0]
    finding = module._rfi_finding(hits[0])
    assert finding["confidence"] == 0.95
    assert "OOB callback" in finding["title"]
    assert finding["evidence"]["interactions"]


def test_run_oob_rfi_skips_without_callback(tmp_path, monkeypatch):
    module = _module(tmp_path)
    monkeypatch.setattr(module, "_start_oob_runtime",
                        lambda cfg: {"callback_url": "", "client_available": False})
    stopped = {"v": False}
    monkeypatch.setattr(module, "_stop_oob_client", lambda rt: stopped.__setitem__("v", True))
    hits = module._run_oob_rfi([{"url": "https://x/?page=1", "params": ["page"]}], {})
    assert hits == []
    assert stopped["v"] is True  # client was cleaned up
