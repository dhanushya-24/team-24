"""
connection.py
=============
Defines the Connection class -- represents a network link between two
assets (e.g. "PC-01 connects to SRV-01 over port 3306/tcp").

SCOPE NOTE: Like vulnerability.py, this class is defined now as part
of the Module 2 data model, but no code in Module 1 or Module 2
creates Connection objects yet. Nmap's basic scan tells us what's
running ON a device, not how devices talk TO each other -- discovering
that requires traffic analysis or topology mapping, which belongs to
the future "Knowledge Graph" module (built with NetworkX, per your
tech stack). The `connections` MongoDB collection exists and is ready
to receive this data once that module is built.
"""

from dataclasses import dataclass


@dataclass
class Connection:
    """
    Represents a directed network connection between two assets.

    Fields:
        source_asset:       asset_id of the initiating device
        destination_asset:  asset_id of the receiving device
        protocol:           "tcp" or "udp"
        port:                destination port number
    """
    source_asset: str
    destination_asset: str
    protocol: str
    port: int

    def to_dict(self) -> dict:
        """Convert to a plain dict for MongoDB storage."""
        return {
            "source_asset": self.source_asset,
            "destination_asset": self.destination_asset,
            "protocol": self.protocol,
            "port": self.port,
        }

    @staticmethod
    def from_dict(data: dict) -> "Connection":
        """Build a Connection object back from a MongoDB document / dict."""
        return Connection(
            source_asset=data.get("source_asset"),
            destination_asset=data.get("destination_asset"),
            protocol=data.get("protocol", "tcp"),
            port=data.get("port"),
        )
