"""Direct tests for the browser-style redirect host resolver.

redirect_host is the security-critical primitive behind open-redirect and OAuth
redirect_uri bypass detection: both callers flag a finding when
redirect_host(location) == the attacker host they injected. So the contract that
must hold is "every browser-honoured encoding of attacker.com resolves to
attacker.com" (detection fires) and "benign / hostless targets do not"
(no false positive). These were only covered indirectly before.
"""

from modules.url_utils import redirect_host, same_site

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


def test_tab_newline_obfuscation_resolves_like_a_browser():
    # Browsers strip TAB/LF/CR before parsing, so these navigate to attacker.com;
    # the detector must see attacker.com too (previously a false negative).
    assert redirect_host("//attac\tker.com") == ATTACKER
    assert redirect_host("htt\nps://attacker.com") == ATTACKER
    assert redirect_host("https://attac\r\nker.com/path") == ATTACKER


def test_single_leading_slash_is_a_path_not_a_host():
    # `/dashboard` is same-origin path-absolute (no authority) -> no host.
    assert redirect_host("/dashboard") == ""
    assert redirect_host("/a/b/c") == ""
    assert redirect_host("relative/path") == ""
    # but protocol-relative (two slashes) still yields a host
    assert redirect_host("//attacker.com/x") == ATTACKER


def test_same_site_exact_and_subdomain_only():
    assert same_site("example.com", "example.com")
    assert same_site("api.example.com", "example.com")
    assert same_site("a.b.example.com", "example.com")
    # suffix lookalikes and unrelated hosts are rejected
    assert not same_site("notexample.com", "example.com")
    assert not same_site("example.com.evil.com", "example.com")
    assert not same_site("example.org", "example.com")


def test_same_site_is_case_and_trailing_dot_insensitive_and_empty_safe():
    assert same_site("API.Example.COM.", "example.com")
    assert not same_site("", "example.com")
    assert not same_site("example.com", "")
    assert not same_site(None, None)
