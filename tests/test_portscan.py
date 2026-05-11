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
