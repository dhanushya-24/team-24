"""
service.py
==========
Defines the Service class -- represents ONE open port + the network
service running on it (e.g. "port 22, ssh, OpenSSH 7.2").

An Asset holds a LIST of these (see asset.py -> `services` field).
Kept as a separate class (rather than just a dict) so that later
modules (Threat Detection, Attack Path Analysis) can work with
well-defined objects instead of guessing dictionary key names.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Service:
    """
    Represents a single network service discovered on an asset.

    Fields:
        service_name:  e.g. "ftp", "ssh", "http"
        port:          port number, e.g. 21, 22, 80
        protocol:      "tcp" or "udp"
        state:         "open" (we only keep open ports -- see parser.py)
        version:       software/version string if Nmap detected it,
                       e.g. "vsftpd 2.3.4" (None if unknown)
    """
    service_name: str
    port: int
    protocol: str
    state: str
    version: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to a plain dict for MongoDB storage."""
        return {
            "service_name": self.service_name,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "version": self.version,
        }

    @staticmethod
    def from_dict(data: dict) -> "Service":
        """Build a Service object back from a MongoDB document / dict."""
        return Service(
            service_name=data.get("service_name", "unknown"),
            port=data.get("port"),
            protocol=data.get("protocol", "tcp"),
            state=data.get("state", "open"),
            version=data.get("version"),
        )
