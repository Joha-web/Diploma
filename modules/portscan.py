"""
ReconX — Module: Port Scanning
Phase 1: masscan fast sweep (optional, if installed)
Phase 2: nmap service+version detection on open ports
"""

import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from modules.base import BaseModule

PORT_NAMES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"MSRPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 465:"SMTPS", 587:"SMTP-SUB",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 1521:"Oracle",
    2375:"Docker", 2376:"Docker-TLS", 3000:"Grafana/Dev",
    3306:"MySQL", 3389:"RDP", 4848:"GlassFish",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis",
    7001:"WebLogic", 8000:"HTTP-Alt", 8080:"HTTP-Proxy",
    8081:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter/Dev",
    9000:"SonarQube", 9090:"Prometheus", 9200:"Elasticsearch",
    9300:"ES-Transport", 10000:"Webmin", 11211:"Memcached",
    15672:"RabbitMQ", 27017:"MongoDB", 50000:"SAP",
}

HIGH_RISK_PORTS = {
    21, 23, 25, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 4848, 5432, 5900, 6379,
    7001, 9200, 11211, 15672, 27017, 50000,
}


class PortScanModule(BaseModule):
    name = "portscan"
    description = "Port Scanning (masscan + nmap)"
    required_tools = ["nmap"]

    def __init__(self, target: str, output_dir: str, config: dict,
                 resolved_ips: list | None = None):
        super().__init__(target, output_dir, config)
        self.resolved_ips = resolved_ips or []

    def run(self) -> dict:
        if not self.resolved_ips:
            self.warn("No IPs to scan")
            return {"hosts": [], "summary": {"total_open_ports": 0, "hosts_with_ports": 0, "high_risk": []}}

        ip_file = self.module_dir / "target_ips.txt"
        self.save_text(self.resolved_ips, "target_ips.txt")

        self.info(f"Targets: {len(self.resolved_ips)} IPs")

        # Phase 1: fast sweep
        open_ports: dict[str, set[int]] = {}
        if self.has_tool("masscan"):
            open_ports = self._masscan(ip_file)
        if not open_ports:
            open_ports = self._nmap_sweep(ip_file)

        if not open_ports:
            self.info("No open ports found")
            return {"hosts": [], "summary": {"total_open_ports": 0, "hosts_with_ports": 0, "high_risk": []}}

        # Phase 2: service detection on found ports
        hosts = self._nmap_service(open_ports)

        total_ports = sum(h["total_open"] for h in hosts)
        high_risk = [
            {"ip": h["ip"], "port": p["port"], "service": p["service"]}
            for h in hosts
            for p in h["open_ports"]
            if p["port"] in HIGH_RISK_PORTS
        ]

        self.save_json(hosts, "ports_by_host.json")
        self.success(f"{total_ports} open ports on {len(hosts)} hosts")
        if high_risk:
            self.warn(f"⚠  {len(high_risk)} high-risk port(s) detected!")

        return {
            "hosts": hosts,
            "summary": {
                "hosts_with_ports": len(hosts),
                "total_open_ports": total_ports,
                "high_risk": high_risk,
            },
        }

    # ── masscan ───────────────────────────────────────────────────────────────

    def _masscan(self, ip_file: Path) -> dict[str, set[int]]:
        out = self.module_dir / "masscan.json"
        rate = self.config.get("scan", {}).get("ports", {}).get("masscan_rate", 3000)

        self.exec(
            ["masscan", "-iL", str(ip_file), "-p", "0-65535",
             "--rate", str(rate), "--open", "-oJ", str(out)],
            timeout=900,
        )
        if not out.exists():
            return {}

        result: dict[str, set[int]] = {}
        try:
            for entry in json.loads(out.read_text()):
                ip   = entry.get("ip", "")
                port = (entry.get("ports") or [{}])[0].get("port", 0)
                if ip and port:
                    result.setdefault(ip, set()).add(int(port))
            self.success(f"masscan → {sum(len(v) for v in result.values())} open ports")
        except Exception:
            pass
        return result

    # ── nmap sweep ────────────────────────────────────────────────────────────

    def _nmap_sweep(self, ip_file: Path) -> dict[str, set[int]]:
        cfg  = self.config.get("scan", {}).get("ports", {})
        mode = cfg.get("mode", "top-1000")
        top  = mode.replace("top-", "") if "top-" in mode else "1000"

        gnmap = self.module_dir / "nmap_sweep.gnmap"
        self.info(f"nmap --top-ports {top} on {len(self.resolved_ips)} IPs")
        self.exec(
            ["nmap", "-iL", str(ip_file), "--top-ports", top,
             "--open", "-T4", "-n", "--min-parallelism", "100",
             "-oG", str(gnmap)],
            timeout=900,
        )
        return self._parse_gnmap(gnmap)

    def _parse_gnmap(self, path: Path) -> dict[str, set[int]]:
        result: dict[str, set[int]] = {}
        if not path.exists():
            return result
        for line in path.read_text().splitlines():
            if not line.startswith("Host:"):
                continue
            m_ip    = re.search(r"Host:\s+([0-9.]+)", line)
            m_ports = re.search(r"Ports:\s+(.+)", line)
            if not m_ip:
                continue
            ip = m_ip.group(1)
            if m_ports:
                for part in m_ports.group(1).split(","):
                    parts = part.strip().split("/")
                    if len(parts) >= 2 and parts[1] == "open":
                        try:
                            result.setdefault(ip, set()).add(int(parts[0]))
                        except ValueError:
                            pass
        return result

    # ── nmap service detection ────────────────────────────────────────────────

    def _nmap_service(self, open_ports: dict[str, set[int]]) -> list[dict]:
        hosts: list[dict] = []
        for ip, ports in open_ports.items():
            if not ports:
                continue
            port_str = ",".join(str(p) for p in sorted(ports))
            xml_out  = self.module_dir / f"nmap_{ip.replace('.','_')}.xml"

            self.exec(
                ["nmap", ip, "-p", port_str, "-sV", "--version-intensity", "5",
                 "-sC", "--open", "-T4", "-n", "-oX", str(xml_out)],
                timeout=300,
            )

            port_list = self._parse_nmap_xml(xml_out, ports)
            if port_list:
                hosts.append({
                    "ip":         ip,
                    "open_ports": port_list,
                    "total_open": len(port_list),
                    "interesting": [p for p in port_list if p["port"] in HIGH_RISK_PORTS],
                })

        return hosts

    def _parse_nmap_xml(self, xml_file: Path, fallback: set[int]) -> list[dict]:
        port_list: list[dict] = []
        if not xml_file.exists():
            return [{"port": p, "protocol": "tcp", "state": "open",
                     "service": PORT_NAMES.get(p, "unknown"), "product": "", "version": ""}
                    for p in sorted(fallback)]
        try:
            tree = ET.parse(str(xml_file))
            for port_el in tree.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc   = port_el.find("service")
                pnum  = int(port_el.get("portid", 0))
                port_list.append({
                    "port":      pnum,
                    "protocol":  port_el.get("protocol", "tcp"),
                    "state":     "open",
                    "service":   svc.get("name", PORT_NAMES.get(pnum, "unknown")) if svc is not None else PORT_NAMES.get(pnum, "unknown"),
                    "product":   svc.get("product", "") if svc is not None else "",
                    "version":   svc.get("version", "") if svc is not None else "",
                    "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                })
        except ET.ParseError:
            return [{"port": p, "protocol": "tcp", "state": "open",
                     "service": PORT_NAMES.get(p, "unknown"), "product": "", "version": ""}
                    for p in sorted(fallback)]
        return sorted(port_list, key=lambda x: x["port"])
