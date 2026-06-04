from modules.portscan import PortScanModule


def test_parse_nmap_xml(tmp_path):
    xml = tmp_path / "nmap.xml"
    xml.write_text(
        """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports></host></nmaprun>""",
        encoding="utf-8",
    )
    module = PortScanModule("example.com", str(tmp_path), {}, resolved_ips=[])

    ports = module._parse_nmap_xml(xml, {80, 22})

    assert ports == [{
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "product": "nginx",
        "version": "1.24",
        "extrainfo": "",
    }]


def test_parse_masscan_valid_json():
    from modules.portscan import PortScanModule
    text = """[
{"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
{"ip": "1.2.3.4", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
{"ip": "5.6.7.8", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}
]"""
    result = PortScanModule._parse_masscan(text)
    assert result["1.2.3.4"] == {80, 443}
    assert result["5.6.7.8"] == {22}


def test_parse_masscan_tolerates_trailing_comma():
    """masscan often emits a trailing comma before ] → invalid JSON; the old
    json.loads dropped ALL ports. The robust parser must still recover them."""
    from modules.portscan import PortScanModule
    text = """[
{"ip": "10.0.0.1", "ports": [{"port": 8080, "status": "open"}]},
]"""
    assert PortScanModule._parse_masscan(text) == {"10.0.0.1": {8080}}


def test_parse_masscan_recovers_from_truncated_final_record():
    """A timeout-killed masscan leaves a cut-off last record; earlier complete
    records must still be parsed."""
    from modules.portscan import PortScanModule
    text = """[
{"ip": "10.0.0.1", "ports": [{"port": 80, "status": "open"}]},
{"ip": "10.0.0.2", "ports": [{"port": 4"""
    assert PortScanModule._parse_masscan(text) == {"10.0.0.1": {80}}


def test_parse_masscan_empty():
    from modules.portscan import PortScanModule
    assert PortScanModule._parse_masscan("") == {}
