"""
graph_queries.py
=================
RESPONSIBILITY: Read-only INFORMATION RETRIEVAL against an
already-built Knowledge Graph. Every function here takes a NetworkX
graph and returns data -- none of them modify the graph, and none of
them implement attack-path finding, exploitation, simulation, AI
reasoning, or recommendations. Those belong to Modules 7-9.
"""

from typing import Any, Dict, List

import networkx as nx

HIGH_RISK_LEVELS = {"high", "critical"}


def get_nodes_by_type(graph: nx.DiGraph, node_type: str) -> List[Dict[str, Any]]:
    """Return every node whose 'node_type' attribute matches `node_type`
    (e.g. "asset", "port", "service", "vulnerability", "risk")."""
    return [
        {"id": node_id, **attributes}
        for node_id, attributes in graph.nodes(data=True)
        if attributes.get("node_type") == node_type
    ]


def get_edges_by_relationship(graph: nx.DiGraph, relationship: str) -> List[Dict[str, Any]]:
    """Return every edge whose 'relationship' attribute matches
    `relationship` (e.g. "ASSET_EXPOSES_PORT")."""
    return [
        {"source": source, "target": target, **attributes}
        for source, target, attributes in graph.edges(data=True)
        if attributes.get("relationship") == relationship
    ]


def get_asset_neighbors(graph: nx.DiGraph, asset_id: str) -> List[Dict[str, Any]]:
    """
    Return every node directly connected to the given asset (its IP,
    OS, ports, services, vulnerabilities, and risk level -- and any
    connected assets, if real connection data exists).
    """
    node_id = f"asset:{asset_id}"
    if node_id not in graph:
        return []
    return [{"id": neighbor, **graph.nodes[neighbor]} for neighbor in graph.successors(node_id)]


def get_asset_services(graph: nx.DiGraph, asset_id: str) -> List[Dict[str, Any]]:
    """Return every 'service' node connected to the given asset."""
    return [
        neighbor for neighbor in get_asset_neighbors(graph, asset_id)
        if neighbor.get("node_type") == "service"
    ]


def get_asset_ports(graph: nx.DiGraph, asset_id: str) -> List[Dict[str, Any]]:
    """Return every 'port' node connected to the given asset."""
    return [
        neighbor for neighbor in get_asset_neighbors(graph, asset_id)
        if neighbor.get("node_type") == "port"
    ]


def get_asset_vulnerabilities(graph: nx.DiGraph, asset_id: str) -> List[Dict[str, Any]]:
    """Return every 'vulnerability' node connected to the given asset."""
    return [
        neighbor for neighbor in get_asset_neighbors(graph, asset_id)
        if neighbor.get("node_type") == "vulnerability"
    ]


def get_high_risk_assets(graph: nx.DiGraph) -> List[Dict[str, Any]]:
    """
    Return every asset node connected to a 'risk' node whose level is
    "High" or "Critical". This is a lookup, not a calculation -- risk
    levels were already computed by Module 4.
    """
    results = []
    for node_id, attributes in graph.nodes(data=True):
        if attributes.get("node_type") != "risk":
            continue
        if (attributes.get("label") or "").strip().lower() not in HIGH_RISK_LEVELS:
            continue
        for predecessor in graph.predecessors(node_id):
            predecessor_attrs = graph.nodes[predecessor]
            if predecessor_attrs.get("node_type") == "asset":
                results.append({"id": predecessor, **predecessor_attrs})
    return results


def get_assets_with_vulnerability(graph: nx.DiGraph, vulnerability_id: str) -> List[Dict[str, Any]]:
    """Return every asset node connected to the given vulnerability ID
    (e.g. "VULN-001")."""
    node_id = f"vulnerability:{vulnerability_id}"
    if node_id not in graph:
        return []
    return [
        {"id": predecessor, **graph.nodes[predecessor]}
        for predecessor in graph.predecessors(node_id)
        if graph.nodes[predecessor].get("node_type") == "asset"
    ]


def get_asset_risk(graph: nx.DiGraph, asset_id: str) -> Dict[str, Any]:
    """
    Return {"risk_score": int, "risk_level": str} for the given asset,
    read from its ASSET_HAS_RISK edge (risk_score lives on the edge,
    risk_level is the connected 'risk' node's label -- see
    graph_builder.add_asset()). Added for Module 7 (Attack Path
    Analysis), which needs to read an asset's already-computed risk
    back out of the graph without recalculating anything.

    Returns {"risk_score": 0, "risk_level": "Unknown"} if the asset or
    its risk edge isn't present, rather than raising.
    """
    node_id = f"asset:{asset_id}"
    if node_id not in graph:
        return {"risk_score": 0, "risk_level": "Unknown"}

    for _, target, attributes in graph.out_edges(node_id, data=True):
        if attributes.get("relationship") == "ASSET_HAS_RISK":
            risk_node = graph.nodes.get(target, {})
            return {
                "risk_score": attributes.get("risk_score") or 0,
                "risk_level": risk_node.get("label", "Unknown"),
            }

    return {"risk_score": 0, "risk_level": "Unknown"}
