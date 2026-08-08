"""
test_knowledge_graph.py
========================
Standalone test for Module 6 (Knowledge Graph), using fake in-memory
asset data only.

Does NOT require: a live Nmap scan, Kali Linux, Metasploitable2, the
Flask server, MongoDB, or any external network access -- it only
exercises backend.knowledge_graph.graph_builder and
backend.knowledge_graph.graph_queries directly.

Run from the project root:
    python -m tests.test_knowledge_graph
"""

from collections import Counter

from backend.knowledge_graph.graph_builder import KnowledgeGraphBuilder
from backend.knowledge_graph import graph_queries


def build_fake_assets() -> list:
    """Three fake assets with ports/services/vulnerabilities/risk,
    shaped exactly like Asset.to_dict() (see backend/twin/asset.py)."""
    return [
        {
            "asset_id": "192.168.56.101",
            "hostname": "metasploitable",
            "ip_address": "192.168.56.101",
            "mac_address": "08:00:27:11:11:11",
            "operating_system": "Linux 2.6.X",
            "device_type": "server",
            "status": "online",
            "ports": [21, 80],
            "services": [
                {"service_name": "ftp", "port": 21, "protocol": "tcp",
                 "state": "open", "version": "vsftpd 2.3.4"},
                {"service_name": "http", "port": 80, "protocol": "tcp",
                 "state": "open", "version": "Apache 2.2.8"},
            ],
            "vulnerabilities": [
                {"id": "VULN-001", "name": "vsftpd 2.3.4 Backdoor",
                 "severity": "Critical", "description": "Known backdoor.",
                 "recommendation": "Upgrade vsftpd."},
            ],
            "risk_score": 85,
            "risk_level": "Critical",
            "last_updated": "2026-08-08T10:00:00",
        },
        {
            "asset_id": "192.168.56.102",
            "hostname": "win-workstation",
            "ip_address": "192.168.56.102",
            "mac_address": "08:00:27:22:22:22",
            "operating_system": "Windows Server 2016",
            "device_type": "server",
            "status": "online",
            "ports": [445, 80],
            "services": [
                {"service_name": "smb", "port": 445, "protocol": "tcp",
                 "state": "open", "version": None},
                {"service_name": "http", "port": 80, "protocol": "tcp",
                 "state": "open", "version": "IIS 8.5"},
            ],
            "vulnerabilities": [],
            "risk_score": 55,
            "risk_level": "High",
            "last_updated": "2026-08-08T10:01:00",
        },
        {
            "asset_id": "192.168.56.103",
            "hostname": "kali",
            "ip_address": "192.168.56.103",
            "mac_address": "08:00:27:33:33:33",
            "operating_system": "Linux Kali",
            "device_type": "workstation",
            "status": "online",
            "ports": [22],
            "services": [
                {"service_name": "ssh", "port": 22, "protocol": "tcp",
                 "state": "open", "version": "OpenSSH 8.4"},
            ],
            "vulnerabilities": [],
            "risk_score": 10,
            "risk_level": "Low",
            "last_updated": "2026-08-08T10:02:00",
        },
    ]


def run_test() -> None:
    assets = build_fake_assets()

    builder = KnowledgeGraphBuilder()
    # No `connections` argument is passed -- this deliberately proves
    # that fake device-to-device links are never created on their own.
    graph = builder.build_from_assets(assets)

    node_type_counts = Counter(
        attributes.get("node_type") for _, attributes in graph.nodes(data=True)
    )
    relationship_counts = Counter(
        attributes.get("relationship") for _, _, attributes in graph.edges(data=True)
    )

    print("=" * 50)
    print("CYBERTWINAI KNOWLEDGE GRAPH TEST")
    print("=" * 50)
    print(f"Assets: {len(assets)}")
    print(f"Nodes: {graph.number_of_nodes()}")
    print(f"Edges: {graph.number_of_edges()}")
    print()
    print("Node types:")
    for node_type, count in sorted(node_type_counts.items()):
        print(f"  {node_type}: {count}")
    print()
    print("Relationships:")
    for relationship, count in sorted(relationship_counts.items()):
        print(f"  {relationship}: {count}")
    print()

    # --- Assertions -----------------------------------------------------
    assert len(graph_queries.get_nodes_by_type(graph, "asset")) == 3, \
        "Expected 3 asset nodes"

    assert len(graph_queries.get_nodes_by_type(graph, "port")) > 0, \
        "Expected at least one port node"

    assert len(graph_queries.get_nodes_by_type(graph, "service")) > 0, \
        "Expected at least one service node"

    vulnerability_nodes = graph_queries.get_nodes_by_type(graph, "vulnerability")
    assert len(vulnerability_nodes) == 1, "Expected exactly 1 vulnerability node"

    risk_nodes = graph_queries.get_nodes_by_type(graph, "risk")
    assert len(risk_nodes) == 3, "Expected 3 distinct risk-level nodes (Critical/High/Low)"

    # Relationship checks
    assert len(graph_queries.get_edges_by_relationship(graph, "ASSET_EXPOSES_PORT")) == 5
    assert len(graph_queries.get_edges_by_relationship(graph, "ASSET_RUNS_SERVICE")) == 5
    assert len(graph_queries.get_edges_by_relationship(graph, "ASSET_HAS_VULNERABILITY")) == 1
    assert len(graph_queries.get_edges_by_relationship(graph, "ASSET_HAS_RISK")) == 3

    # Query function checks
    services = graph_queries.get_asset_services(graph, "192.168.56.101")
    assert {s["label"] for s in services} == {"ftp", "http"}

    ports = graph_queries.get_asset_ports(graph, "192.168.56.101")
    assert {p["port"] for p in ports} == {21, 80}

    vulnerabilities = graph_queries.get_asset_vulnerabilities(graph, "192.168.56.101")
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0]["vulnerability_id"] == "VULN-001"

    high_risk_assets = graph_queries.get_high_risk_assets(graph)
    high_risk_ids = {a["asset_id"] for a in high_risk_assets}
    assert high_risk_ids == {"192.168.56.101", "192.168.56.102"}, \
        "Expected the Critical and High risk assets, not the Low risk one"

    assets_with_vuln = graph_queries.get_assets_with_vulnerability(graph, "VULN-001")
    assert len(assets_with_vuln) == 1
    assert assets_with_vuln[0]["asset_id"] == "192.168.56.101"

    # --- Critical honesty check: no fabricated device-to-device links ---
    connected_edges = graph_queries.get_edges_by_relationship(graph, "ASSET_CONNECTED_TO_ASSET")
    assert len(connected_edges) == 0, \
        "No ASSET_CONNECTED_TO_ASSET edges should exist -- no real connection data was supplied"

    print("Knowledge Graph test PASSED")
    print("=" * 50)


if __name__ == "__main__":
    run_test()
