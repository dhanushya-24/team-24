"""
asset.py
========
Defines the Asset class -- the core building block of the Digital Twin.

One Asset = one real (or lab) network device, represented in software.
This is intentionally a plain data container (a dataclass) with two
small helper methods for converting to/from MongoDB documents. All
the DECISION logic (how to build one, when to update it) lives in
twin_manager.py, not here -- this file only describes the SHAPE of
an asset.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class Asset:
    """
    Represents a single network device inside the Digital Twin.

    Fields:
        asset_id:          unique identifier (we use the IP address,
                            since it's unique on a given lab network
                            and simple to reason about)
        hostname:           device's network name, if discovered
        ip_address:         required -- primary identifier
        mac_address:        hardware address, if discovered
        operating_system:   OS guess from Nmap, or "Unknown"
        device_type:        "server" | "workstation" | "router" | "unknown"
        status:             "online" | "offline"
        ports:              list of open port numbers
        services:           list of service dicts (see service.py)
        vulnerabilities:    list of vulnerability dicts (see vulnerability.py)
                            -- empty for now; populated by a future
                            Threat Detection module
        risk_score:         0-100. Initially set by twin_manager.py using
                            a basic heuristic at discovery time, then
                            RECALCULATED and overwritten by
                            backend/risk/risk_calculator.py (Module 4)
                            once vulnerabilities are known -- that pass
                            is more accurate since it accounts for
                            actual vulnerability findings, not just
                            port count.
        risk_level:         "Low" | "Medium" | "High" | "Critical",
                            derived from risk_score. Empty string until
                            Module 4's RiskCalculator runs at least once.
        last_updated:       ISO timestamp of the last time this asset
                            was created or refreshed by a scan
    """
    asset_id: str
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str] = None
    operating_system: str = "Unknown"
    device_type: str = "unknown"
    status: str = "online"
    ports: List[int] = field(default_factory=list)
    services: List[dict] = field(default_factory=list)
    vulnerabilities: List[dict] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = ""
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """
        Convert this Asset into a plain dictionary, ready to be saved
        into MongoDB. MongoDB documents are just dicts, so this is a
        straightforward field-by-field conversion.
        """
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "operating_system": self.operating_system,
            "device_type": self.device_type,
            "status": self.status,
            "ports": self.ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "last_updated": self.last_updated,
        }

    @staticmethod
    def from_dict(data: dict) -> "Asset":
        """
        Build an Asset object back FROM a MongoDB document.
        Used when loading the twin's current state out of the database
        (e.g. for the Twin Manager to compare "previous scan" vs
        "current scan").
        """
        return Asset(
            asset_id=data.get("asset_id"),
            hostname=data.get("hostname"),
            ip_address=data.get("ip_address"),
            mac_address=data.get("mac_address"),
            operating_system=data.get("operating_system", "Unknown"),
            device_type=data.get("device_type", "unknown"),
            status=data.get("status", "online"),
            ports=data.get("ports", []),
            services=data.get("services", []),
            vulnerabilities=data.get("vulnerabilities", []),
            risk_score=data.get("risk_score", 0),
            risk_level=data.get("risk_level", ""),
            last_updated=data.get("last_updated", datetime.now().isoformat()),
        )
