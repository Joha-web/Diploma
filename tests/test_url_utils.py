"""Direct tests for the browser-style redirect host resolver.

redirect_host is the security-critical primitive behind open-redirect and OAuth
redirect_uri bypass detection: both callers flag a finding when
redirect_host(location) == the attacker host they injected. So the contract that
must hold is "every browser-honoured encoding of attacker.com resolves to
attacker.com" (detection fires) and "benign / hostless targets do not"
(no false positive). These were only covered indirectly before.
"""

from modules.url_utils import redirect_host

ATTACKER = "attacker.com"


def test_plain_host_extraction_normalises_case_port_and_trailing_dot():
    assert redirect_host("https://example.com/path") == "example.com"
    assert redirect_host("https://EXAMPLE.com:8443/x") == "example.com"
    assert redirect_host("  https://Example.COM./x ") == "example.com"


def test_open_redirect_bypass_forms_all_resolve_to_attacker_host():
    # Each of these is a real filter-bypass that a browser sends to attacker.com;
    # urlparse mis-parses several of them, which is why we have redirect_host.
    bypasses = [
        "https://attacker.com/cb",
        "//attacker.com",                 # protocol-relative
        "////attacker.com",               # leading-slash collapse
        r"https:\\attacker.com",          # backslashes as slashes
        r"/\attacker.com",                # slash-backslash
        "https:attacker.com",             # missing-slash scheme
        "https://trusted.com@attacker.com",   # userinfo@host
        "https://a@b@attacker.com",       # multiple @ -> last host wins
        r"//attacker.com\@trusted.com",   # backslash makes attacker.com the host
    ]
    for loc in bypasses:
        assert redirect_host(loc) == ATTACKER, loc


def test_benign_targets_do_not_resolve_to_attacker_host():
    for loc in ("/dashboard", "https://trusted.com/cb", "", None,
                "https://trusted.com@safe.example"):
        assert redirect_host(loc) != ATTACKER, loc


def test_empty_and_hostless_inputs_return_empty():
    assert redirect_host("") == ""
    assert redirect_host(None) == ""
    assert redirect_host("   ") == ""
