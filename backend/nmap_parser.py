import os
import xml.etree.ElementTree as ET
from datetime import datetime

class NmapXMLParser:
    """
    Module for importing and parsing Nmap XML discovery scans (data/scan.xml).
    Converts XML host, port, service, and OS data into CyberTwin Digital Twin assets.
    """

    @staticmethod
    def parse_scan_xml(xml_filepath=None):
        if xml_filepath is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            xml_filepath = os.path.join(base_dir, "data", "scan.xml")

        if not os.path.exists(xml_filepath):
            return []

        try:
            tree = ET.parse(xml_filepath)
            root = tree.getroot()
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            return []

        imported_assets = []
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for host in root.findall("host"):
            # Check host status
            status_elem = host.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            # Extract IP & MAC addresses
            ip_addr = "0.0.0.0"
            mac_addr = "00:00:00:00:00:00"
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip_addr = addr.get("addr")
                elif addr_type == "mac":
                    mac_addr = addr.get("addr")

            if ip_addr == "0.0.0.0":
                continue

            # Extract Hostname
            hostname = f"host-{ip_addr.replace('.', '-')}.local"
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                h_node = hostnames_elem.find("hostname")
                if h_node is not None and h_node.get("name"):
                    hostname = h_node.get("name").strip()

            # Extract Operating System info
            os_name = "Unknown OS"
            os_elem = host.find("os")
            if os_elem is not None:
                os_match = os_elem.find("osmatch")
                if os_match is not None and os_match.get("name"):
                    os_name = os_match.get("name")

            # Fallback OS check from service ostype/cpe
            if os_name == "Unknown OS":
                for port in host.findall(".//port"):
                    srv = port.find("service")
                    if srv is not None:
                        ostype = srv.get("ostype")
                        if ostype:
                            os_name = f"{ostype.capitalize()} OS"
                            break
                        cpe = srv.find("cpe")
                        if cpe is not None and cpe.text and "linux" in cpe.text.lower():
                            os_name = "Linux OS"
                            break

            # Extract Open Ports & Services
            asset_ports = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    protocol = port.get("protocol", "tcp").upper()
                    port_id = port.get("portid")
                    if not port_id:
                        continue
                    port_num = int(port_id)

                    state_elem = port.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    srv_elem = port.find("service")
                    srv_name = "unknown"
                    srv_version = "1.0"

                    if srv_elem is not None:
                        srv_name = srv_elem.get("name", "unknown")
                        product = srv_elem.get("product", "")
                        version = srv_elem.get("version", "")
                        extrainfo = srv_elem.get("extrainfo", "")

                        version_parts = [p for p in [product, version, extrainfo] if p]
                        if version_parts:
                            srv_version = " ".join(version_parts)
                        else:
                            srv_version = f"{srv_name} 1.0"

                    asset_ports.append({
                        "port": port_num,
                        "protocol": protocol,
                        "state": "Open",
                        "service": srv_name.upper() if len(srv_name) <= 4 else srv_name.capitalize(),
                        "version": srv_version
                    })

            device_type = "Server" if len(asset_ports) > 3 or "server" in hostname.lower() else "Workstation"
            asset_id = f"AST-{ip_addr.replace('.', '')}"

            asset_obj = {
                "asset_id": asset_id,
                "hostname": hostname,
                "ip_address": ip_addr,
                "mac_address": mac_addr,
                "device_type": device_type,
                "os": os_name,
                "status": "Online",
                "first_seen": now_str,
                "last_seen": now_str,
                "importance": "Critical" if "101" in ip_addr or "server" in hostname.lower() else "High",
                "data_source": "IMPORTED_LAB_SCAN",
                "ports": asset_ports
            }
            imported_assets.append(asset_obj)

        return imported_assets
