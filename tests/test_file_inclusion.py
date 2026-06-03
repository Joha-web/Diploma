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
