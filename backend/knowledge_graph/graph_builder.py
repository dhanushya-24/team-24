"""
graph_builder.py
=================
RESPONSIBILITY: Convert existing Digital Twin Asset objects/dicts
(Modules 1-4) into a NetworkX graph of typed nodes and relationships.

This file contains GRAPH CONSTRUCTION LOGIC ONLY. It does not scan,
does not detect vulnerabilities, does not calculate risk, and does
not perform attack-path analysis -- it only reads data that Modules
1-4 have already computed and represents it as a graph.

Node types produced:
    asset, ip, operating_system, port, service, vulnerability, risk

Edge relationships produced:
    ASSET_HAS_IP, ASSET_RUNS_OS, ASSET_EXPOSES_PORT,
    ASSET_RUNS_SERVICE, ASSET_HAS_VULNERABILITY, ASSET_HAS_RISK,
    and (only if real connection data is supplied) ASSET_CONNECTED_TO_ASSET.

IMPORTANT: this module NEVER invents device-to-device connections.
ASSET_CONNECTED_TO_ASSET edges are only created when the caller
explicitly supplies real connection records (e.g. from
backend/twin/connection.py or a future Knowledge Graph data source).
If none are supplied, no such edges are created.
"""

from typing import Any, Dict, List, Optional, Union

import networkx as nx

# An Asset can be passed in either as the real Asset dataclass
# (backend/twin/asset.py) or as a plain dict (e.g. straight from the
# Flask API / MongoDB). Both are supported without a hard import
# dependency on Asset, so this module works from either source.
AssetLike = Union[Dict[str, Any], Any]


class KnowledgeGraphBuilder:
    """
    Builds a NetworkX directed graph representing the relationships
    between assets, IPs, operating systems, ports, services,
    vulnerabilities, and risk levels.

    A single builder instance accumulates nodes/edges across multiple
    add_asset()/build_from_asset() calls, and de-duplicates nodes and
    edges automatically (safe to call repeatedly with overlapping data).
    """

    def __init__(self) -> None:
        # Directed graph: edges point FROM the asset TO the thing it
        # has/runs/exposes (e.g. asset -> port), which matches the
        # relationship names (ASSET_EXPOSES_PORT, etc.) and lets
        # future modules walk outward from an asset naturally.
        self.graph: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    # PUBLIC BUILD ENTRY POINTS
    # ------------------------------------------------------------------
    def build_from_asset(self, asset: AssetLike) -> nx.DiGraph:
        """Add a single asset (and everything connected to it) to the graph."""
        self.add_asset(asset)
        return self.graph

    def build_from_assets(
        self,
        assets: List[AssetLike],
        connections: Optional[List[Dict[str, Any]]] = None,
    ) -> nx.DiGraph:
        """
        Add a list of assets to the graph.

        Args:
            assets: list of Asset objects or asset dictionaries.
            connections: OPTIONAL list of real connection records
                (each shaped like backend/twin/connection.py's
                Connection.to_dict(): {"source_asset", "destination_asset",
                "protocol", "port"}). If omitted or empty, NO
                device-to-device edges are created -- this builder
                never fabricates network topology.
        """
        for asset in assets:
            self.add_asset(asset)

        if connections:
            for connection in connections:
                self.add_connection(
                    connection.get("source_asset"),
                    connection.get("destination_asset"),
                    protocol=connection.get("protocol", "tcp"),
                    port=connection.get("port"),
                )

        return self.graph

    # ------------------------------------------------------------------
    # ASSET + ITS DIRECT RELATIONSHIPS
    # ------------------------------------------------------------------
    def add_asset(self, asset: AssetLike) -> str:
        """
        Add one asset and all of its known attributes (IP, OS, ports,
        services, vulnerabilities, risk) to the graph.

        Never mutates the original `asset` object -- it is only read from.

        Returns:
            The stable node ID assigned to this asset (e.g. "asset:192.168.56.101").
        """
        data = self._normalize_asset(asset)

        asset_id = data.get("asset_id") or data.get("ip_address")
        if not asset_id:
            raise ValueError("Asset is missing both 'asset_id' and 'ip_address' -- cannot build a graph node.")

        asset_node_id = f"asset:{asset_id}"
        if asset_node_id not in self.graph:
            self.graph.add_node(
                asset_node_id,
                node_type="asset",
                label=data.get("hostname") or data.get("ip_address") or str(asset_id),
                asset_id=asset_id,
                hostname=data.get("hostname"),
                status=data.get("status"),
                device_type=data.get("device_type"),
            )

        ip_address = data.get("ip_address")
        if ip_address:
            ip_node_id = self.add_ip(ip_address)
            self._add_edge(asset_node_id, ip_node_id, "ASSET_HAS_IP")

        operating_system = data.get("operating_system")
        if operating_system and operating_system != "Unknown":
            os_node_id = self.add_os(operating_system)
            self._add_edge(asset_node_id, os_node_id, "ASSET_RUNS_OS")

        for port in data.get("ports") or []:
            port_node_id = self.add_port(port)
            self._add_edge(asset_node_id, port_node_id, "ASSET_EXPOSES_PORT")

        for service in data.get("services") or []:
            service_name = self._get_field(service, "service_name")
            if not service_name:
                continue
            service_node_id = self.add_service(service_name)
            self._add_edge(
                asset_node_id,
                service_node_id,
                "ASSET_RUNS_SERVICE",
                port=self._get_field(service, "port"),
                protocol=self._get_field(service, "protocol"),
            )

        for vulnerability in data.get("vulnerabilities") or []:
            vulnerability_id = self._get_field(vulnerability, "id")
            if not vulnerability_id:
                continue
            vulnerability_data = vulnerability if isinstance(vulnerability, dict) else {}
            vulnerability_node_id = self.add_vulnerability(vulnerability_id, vulnerability_data)
            self._add_edge(asset_node_id, vulnerability_node_id, "ASSET_HAS_VULNERABILITY")

        risk_level = data.get("risk_level")
        if risk_level:
            risk_node_id = self.add_risk(risk_level)
            self._add_edge(
                asset_node_id, risk_node_id, "ASSET_HAS_RISK",
                risk_score=data.get("risk_score"),
            )

        return asset_node_id

    # ------------------------------------------------------------------
    # INDIVIDUAL TYPED NODE HELPERS (each de-duplicates automatically)
    # ------------------------------------------------------------------
    def add_ip(self, ip_address: str) -> str:
        """Add (or reuse) an 'ip' node. Returns its stable node ID."""
        node_id = f"ip:{ip_address}"
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type="ip", label=ip_address, ip_address=ip_address)
        return node_id

    def add_os(self, operating_system: str) -> str:
        """Add (or reuse) an 'operating_system' node, using a normalized ID
        so e.g. 'Linux 2.6.X' and 'linux 2.6.x' merge into one node."""
        normalized = operating_system.strip().lower().replace(" ", "_")
        node_id = f"os:{normalized}"
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type="operating_system", label=operating_system)
        return node_id

    def add_port(self, port: int) -> str:
        """Add (or reuse) a 'port' node. Ports are globally shared across
        assets on purpose (e.g. every asset with port 80 open links to
        the SAME port:80 node) -- this is what lets future modules ask
        "which assets share this exposure?" via graph_queries.py."""
        node_id = f"port:{port}"
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type="port", label=str(port), port=port)
        return node_id

    def add_service(self, service_name: str) -> str:
        """Add (or reuse) a 'service' node, normalized to lowercase so
        e.g. 'HTTP' and 'http' merge into one shared node."""
        normalized = service_name.strip().lower()
        node_id = f"service:{normalized}"
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type="service", label=service_name)
        return node_id

    def add_vulnerability(self, vulnerability_id: str, vulnerability_data: Optional[Dict[str, Any]] = None) -> str:
        """Add (or reuse) a 'vulnerability' node, keyed by its own ID
        (e.g. "VULN-001" from Module 3), so it is NOT shared across
        assets even if two assets happen to have the same finding ID
        -- each asset's VULN-00X is its own local finding."""
        vulnerability_data = vulnerability_data or {}
        node_id = f"vulnerability:{vulnerability_id}"
        if node_id not in self.graph:
            self.graph.add_node(
                node_id,
                node_type="vulnerability",
                label=vulnerability_data.get("name", vulnerability_id),
                vulnerability_id=vulnerability_id,
                severity=vulnerability_data.get("severity"),
                description=vulnerability_data.get("description"),
                recommendation=vulnerability_data.get("recommendation"),
            )
        return node_id

    def add_risk(self, risk_level: str) -> str:
        """Add (or reuse) a shared 'risk' node per risk level
        (e.g. all "High" risk assets link to the same risk:high node)."""
        normalized = risk_level.strip().lower()
        node_id = f"risk:{normalized}"
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type="risk", label=risk_level)
        return node_id

    # ------------------------------------------------------------------
    # DEVICE-TO-DEVICE CONNECTIONS (only from REAL supplied data)
    # ------------------------------------------------------------------
    def add_connection(
        self,
        source_asset_id: Optional[str],
        destination_asset_id: Optional[str],
        protocol: str = "tcp",
        port: Optional[int] = None,
    ) -> None:
        """
        Add a real, known device-to-device connection edge.

        This is ONLY called when actual connection data is supplied
        (see build_from_assets()'s `connections` parameter) -- this
        builder never fabricates a link between two assets on its own.
        Both assets must already exist in the graph (i.e. must have
        been added via add_asset() first); otherwise the connection
        is silently skipped, since we cannot draw an edge to a node
        that doesn't exist.
        """
        if not source_asset_id or not destination_asset_id:
            return

        source_node_id = f"asset:{source_asset_id}"
        destination_node_id = f"asset:{destination_asset_id}"

        if source_node_id not in self.graph or destination_node_id not in self.graph:
            return  # cannot link assets that were never added to the graph

        self._add_edge(
            source_node_id, destination_node_id, "ASSET_CONNECTED_TO_ASSET",
            protocol=protocol, port=port,
        )

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------
    def _add_edge(self, source: str, target: str, relationship: str, **extra_attributes: Any) -> None:
        """Add an edge with a `relationship` attribute, skipping if it
        already exists (avoids duplicate edges on repeated builds)."""
        if self.graph.has_edge(source, target):
            return
        self.graph.add_edge(source, target, relationship=relationship, **extra_attributes)

    @staticmethod
    def _normalize_asset(asset: AssetLike) -> Dict[str, Any]:
        """
        Convert an Asset object (with a to_dict() method) or an
        already-plain dict into a plain dict, without ever mutating
        the original object.
        """
        if isinstance(asset, dict):
            return asset
        if hasattr(asset, "to_dict") and callable(asset.to_dict):
            return asset.to_dict()
        raise TypeError(
            f"Unsupported asset type: {type(asset)!r}. "
            "Expected a dict or an object with a to_dict() method."
        )

    @staticmethod
    def _get_field(item: Union[Dict[str, Any], Any], field_name: str) -> Any:
        """Read a field from either a dict or an object with attributes,
        so service/vulnerability entries work whether they arrived as
        dicts (the normal case) or as dataclass instances."""
        if isinstance(item, dict):
            return item.get(field_name)
        return getattr(item, field_name, None)
