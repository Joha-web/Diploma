from datetime import datetime, timedelta, timezone

from modules.ssl_checker import SSLCheckerModule


def _module(tmp_path):
    return SSLCheckerModule("example.com", str(tmp_path), {"scope": {"enforce": False}})


def _fmt(dt):
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _cert(not_after, issuer_org, issuer_cn, subject_org, subject_cn, san=("example.com",)):
    return {
        "notAfter": not_after,
        "issuer": ((("organizationName", issuer_org),), (("commonName", issuer_cn),)),
        "subject": ((("organizationName", subject_org),), (("commonName", subject_cn),)),
        "subjectAltName": tuple(("DNS", s) for s in san),
    }


def test_host_port_from_url_handles_nonstandard_port():
    assert SSLCheckerModule._host_port_from_url("https://h.example:8443/x") == ("h.example", 8443)
    assert SSLCheckerModule._host_port_from_url("https://h.example/x") == ("h.example", 443)
    assert SSLCheckerModule._host_port_from_url("http://h.example") == ("h.example", 80)


def test_analyze_cert_flags_expired(tmp_path):
    m = _module(tmp_path)
    base = {}
    cert = _cert(_fmt(datetime.now(timezone.utc) - timedelta(days=10)),
                 "DigiCert Inc", "DigiCert CA", "Example", "example.com")
    issues = m._analyze_cert(cert, base)
    assert "CERT_EXPIRED" in issues
    assert base["days_until_expiry"] < 0


def test_analyze_cert_flags_self_signed(tmp_path):
    m = _module(tmp_path)
    cert = _cert(_fmt(datetime.now(timezone.utc) + timedelta(days=200)),
                 "Acme Internal", "box.local", "Acme Internal", "box.local")
    assert "SELF_SIGNED" in m._analyze_cert(cert, {})


def test_analyze_cert_known_ca_not_self_signed(tmp_path):
    """issuer == subject but issued by a known public CA must NOT be self-signed."""
    m = _module(tmp_path)
    cert = _cert(_fmt(datetime.now(timezone.utc) + timedelta(days=200)),
                 "DigiCert Inc", "DigiCert", "DigiCert Inc", "DigiCert")
    assert "SELF_SIGNED" not in m._analyze_cert(cert, {})


def test_analyze_cert_valid_sets_expiry_no_issue(tmp_path):
    m = _module(tmp_path)
    base = {}
    cert = _cert(_fmt(datetime.now(timezone.utc) + timedelta(days=300)),
                 "Let's Encrypt", "R3", "Example", "example.com")
    issues = m._analyze_cert(cert, base)
    assert "CERT_EXPIRED" not in issues
    assert base["days_until_expiry"] > 200
    assert base["san"] == ["example.com"]


def test_classify_verify_error():
    C = SSLCheckerModule._classify_verify_error
    assert C("certificate has expired") == "CERT_EXPIRED"
    assert C("self-signed certificate") == "SELF_SIGNED"
    assert C("hostname 'x' doesn't match 'y'") == "HOSTNAME_MISMATCH"
    assert C("unable to get local issuer certificate") == "CERT_UNTRUSTED"
    assert C("some other tls failure") == "CERT_INVALID"
