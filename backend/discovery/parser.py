"""
parser.py
=========
RESPONSIBILITY: Parse Nmap XML output into clean Python dictionaries.
Nothing else.

This file does NOT run scans and does NOT touch MongoDB. It only
knows how to read an XML file (produced by scanner.py) and turn it
into plain Python data structures that the rest of the project can
use without ever needing to know what Nmap's XML format looks like.

We use `xml.etree.ElementTree` from Python's standard library --
no extra dependency needed for this.
"""

import xml.etree.ElementTree as ET
from typing import List, Optional


def parse_scan(xml_path: str) -> List[dict]:
    """
    Parse an Nmap XML file and return a list of device dictionaries.

    Args:
        xml_path: path to the XML file produced by scanner.run_scan()

    Returns:
        A list of dicts, one per discovered host, shaped like:
        {
            "hostname": "metasploitable.local" | None,
            "ip_address": "192.168.56.101",
            "mac_address": "08:00:27:XX:XX:XX" | None,
            "operating_system": "Linux 2.6.X" | "Unknown",
            "status": "up" | "down",
            "ports": [21, 22, 80, 445],
            "services": [
                {"port": 21, "protocol": "tcp", "state": "open",
                 "service_name": "ftp", "version": "vsftpd 2.3.4"},
                ...
            ]
        }
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    devices = []

    # Every discovered device is a <host> element in Nmap's XML
    for host in root.findall("host"):
        device = _parse_single_host(host)
        if device is not None:
            devices.append(device)

    print(f"[parser] Parsed {len(devices)} device(s) from {xml_path}")
    return devices


def _parse_single_host(host_element) -> Optional[dict]:
    """
    Parse ONE <host> XML element into a device dictionary.

    Leading underscore means this is an internal helper function --
    not meant to be called directly from outside this file.
    """
    # --- Status (up/down) ---
    status_element = host_element.find("status")
    status = status_element.get("state") if status_element is not None else "unknown"

    # --- IP address (required -- skip host entirely if missing) ---
    ip_address = None
    mac_address = None
    for addr in host_element.findall("address"):
        addr_type = addr.get("addrtype")
        if addr_type == "ipv4":
            ip_address = addr.get("addr")
        elif addr_type == "mac":
            mac_address = addr.get("addr")

    if ip_address is None:
        return None  # Can't identify a device without an IP -- skip it

    # --- Hostname (optional) ---
    hostname = None
    hostnames_element = host_element.find("hostnames")
    if hostnames_element is not None:
        hostname_element = hostnames_element.find("hostname")
        if hostname_element is not None:
            hostname = hostname_element.get("name")

    # --- Operating System guess (optional, requires -O flag in scanner.py) ---
    operating_system = "Unknown"
    os_element = host_element.find("os")
    if os_element is not None:
        osmatch = os_element.find("osmatch")
        if osmatch is not None:
            operating_system = osmatch.get("name", "Unknown")

    # --- Ports and services ---
    ports = []
    services = []
    ports_element = host_element.find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            port_number = int(port_element.get("portid"))
            protocol = port_element.get("protocol")

            state_element = port_element.find("state")
            state = state_element.get("state") if state_element is not None else "unknown"

            # Only keep ports that are actually open -- closed/filtered
            # ports add noise without adding security-relevant information
            if state != "open":
                continue

            service_element = port_element.find("service")
            service_name = service_element.get("name") if service_element is not None else "unknown"
            version = None
            if service_element is not None:
                product = service_element.get("product", "")
                version_number = service_element.get("version", "")
                version = f"{product} {version_number}".strip() or None

            ports.append(port_number)
            services.append({
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service_name": service_name,
                "version": version,
            })

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "operating_system": operating_system,
        "status": status,
        "ports": ports,
        "services": services,
    }
