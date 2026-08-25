"""
test_attack_paths.py
=====================
Standalone test suite for Module 7 (Attack Path Analysis), using fake
in-memory Knowledge Graphs only. Does NOT require a live Nmap scan,
Kali Linux, Metasploitable2, the Flask server, or MongoDB -- it only
exercises backend.knowledge_graph.graph_builder (pure graph
construction) and backend.attack_paths (pure analysis).

Run from the project root:
    python -m tests.test_attack_paths

Covers:
    1. Empty graph
    2. Single asset
    3. Simple entry -> target path
    4. Multiple possible paths
    5. Cyclic graph
    6. Missing vulnerability information
    7. Risk ranking
    8. No available path
"""

import networkx as nx

from backend.knowledge_graph.graph_builder import KnowledgeGraphBuilder
from backend.attack_paths.attack_path_analyzer import AttackPathAnalyzer
from backend.attack_paths.attack_path_queries import (
    summarize_paths,
    get_highest_risk_path,
    get_paths_by_severity,
)


def make_asset(asset_id, ports=None, services=None, vulnerabilities=None,
                risk_score=0, risk_level=None, operating_system="Unknown",
                device_type="server", hostname=None):
    """Small helper to build a fake asset dict shaped like Asset.to_dict()."""
    return {
        "asset_id": asset_id,
        "hostname": hostname or asset_id,
        "ip_address": asset_id,
        "mac_address": None,
        "operating_system": operating_system,
        "device_type": device_type,
        "status": "online",
        "ports": ports or [],
        "services": services or [],
        "vulnerabilities": vulnerabilities or [],
        "risk_score": risk_score,
        "risk_level": risk_level or "",
        "last_updated": "2026-08-08T10:00:00",
    }


# ----------------------------------------------------------------------
# 1. EMPTY GRAPH
# ----------------------------------------------------------------------
def test_empty_graph():
    analyzer = AttackPathAnalyzer(nx.DiGraph())
    paths = analyzer.find_attack_paths()
    assert paths == []
    summary = summarize_paths(paths)
    assert summary["total_paths"] == 0
    assert summary["message"] == "No potential attack paths identified from the available Cyber Twin data."
    print("[PASS] test_empty_graph")


# ----------------------------------------------------------------------
# 2. SINGLE ASSET
# ----------------------------------------------------------------------
def test_single_asset():
    asset = make_asset("10.0.0.1", ports=[80], services=[{"service_name": "http", "port": 80}])
    graph = KnowledgeGraphBuilder().build_from_assets([asset])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()
    # A single asset can never be both entry and target of a path.
    assert paths == []
    print("[PASS] test_single_asset")


# ----------------------------------------------------------------------
# 3. SIMPLE ENTRY -> TARGET PATH
# ----------------------------------------------------------------------
def test_simple_entry_to_target_path():
    entry = make_asset(
        "10.0.0.1", ports=[21, 80],
        services=[{"service_name": "ftp", "port": 21}, {"service_name": "http", "port": 80}],
        vulnerabilities=[{"id": "VULN-001", "name": "vsftpd backdoor", "severity": "Critical"}],
        risk_score=40, risk_level="Medium",
    )
    target = make_asset(
        "10.0.0.2", ports=[80],
        services=[{"service_name": "http", "port": 80}],
        risk_score=85, risk_level="Critical",
    )
    graph = KnowledgeGraphBuilder().build_from_assets([entry, target])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()

    assert len(paths) >= 1, "Expected at least one path via the shared http service/port"
    path = paths[0]
    assert path.entry_asset_id == "10.0.0.1"
    assert path.target_asset_id == "10.0.0.2"
    assert path.path_length >= 2
    assert "theoretical" in path.explanation.lower() or "potential" in path.explanation.lower()
    assert "successfully compromised" not in path.explanation.lower()
    print("[PASS] test_simple_entry_to_target_path")


# ----------------------------------------------------------------------
# 4. MULTIPLE POSSIBLE PATHS
# ----------------------------------------------------------------------
def test_multiple_possible_paths():
    entry = make_asset(
        "10.0.1.1", ports=[80, 443],
        services=[{"service_name": "http", "port": 80}, {"service_name": "https", "port": 443}],
        vulnerabilities=[{"id": "VULN-010", "name": "Outdated Apache", "severity": "Medium"}],
    )
    bridge = make_asset(
        "10.0.1.2", ports=[80], services=[{"service_name": "http", "port": 80}],
        operating_system="Windows Server 2016",
    )
    target = make_asset(
        "10.0.1.3", ports=[445], services=[{"service_name": "smb", "port": 445}],
        operating_system="Windows Server 2016",
        risk_score=90, risk_level="Critical",
    )
    graph = KnowledgeGraphBuilder().build_from_assets([entry, bridge, target])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths(max_paths_per_pair=5, top_n=10)

    assert len(paths) > 1, "Expected multiple distinct paths (via shared service AND shared OS)"
    path_ids = {p.path_id for p in paths}
    assert len(path_ids) == len(paths), "Path IDs must be unique (no duplicate paths returned)"
    print(f"[PASS] test_multiple_possible_paths ({len(paths)} paths found)")


# ----------------------------------------------------------------------
# 5. CYCLIC GRAPH (three assets all sharing the same service -> a ring)
# ----------------------------------------------------------------------
def test_cyclic_graph_does_not_hang_or_repeat_nodes():
    assets = [
        make_asset(f"10.0.2.{i}", ports=[80], services=[{"service_name": "http", "port": 80}],
                   risk_score=20 * i, risk_level="Medium" if i < 3 else "Critical")
        for i in range(1, 4)
    ]
    graph = KnowledgeGraphBuilder().build_from_assets(assets)
    analyzer = AttackPathAnalyzer(graph)

    # All three assets share the same 'service:http' node -- a classic
    # hub structure that would cycle forever without simple-path
    # de-duplication. This must complete quickly and never revisit a node.
    paths = analyzer.find_attack_paths(max_path_length=6, top_n=20)
    for path in paths:
        node_ids = [step.node_id for step in path.nodes]
        assert len(node_ids) == len(set(node_ids)), "A single path must never revisit a node"
    print(f"[PASS] test_cyclic_graph_does_not_hang_or_repeat_nodes ({len(paths)} paths found)")


# ----------------------------------------------------------------------
# 6. MISSING VULNERABILITY INFORMATION
# ----------------------------------------------------------------------
def test_missing_vulnerability_information():
    entry = make_asset("10.0.3.1", ports=[3389], services=[{"service_name": "rdp", "port": 3389}])
    target = make_asset("10.0.3.2", ports=[3389], services=[{"service_name": "rdp", "port": 3389}],
                         risk_score=70, risk_level="High")
    # Neither asset has any vulnerabilities -- the analyzer must still
    # work, scoring purely from ports/target risk, not crash.
    graph = KnowledgeGraphBuilder().build_from_assets([entry, target])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()

    assert len(paths) >= 1
    assert paths[0].vulnerabilities_involved == []
    assert paths[0].risk_score >= 0  # never negative, never crashes
    print("[PASS] test_missing_vulnerability_information")


# ----------------------------------------------------------------------
# 7. RISK RANKING
# ----------------------------------------------------------------------
def test_risk_ranking_orders_highest_first():
    entry = make_asset(
        "10.0.4.1", ports=[21], services=[{"service_name": "ftp", "port": 21}],
        vulnerabilities=[{"id": "VULN-020", "name": "Weak FTP", "severity": "Critical"}],
    )
    low_value_target = make_asset(
        "10.0.4.2", ports=[21], services=[{"service_name": "ftp", "port": 21}],
        risk_score=15, risk_level="Low",
    )
    high_value_target = make_asset(
        "10.0.4.3", ports=[21], services=[{"service_name": "ftp", "port": 21}],
        risk_score=95, risk_level="Critical",
    )
    graph = KnowledgeGraphBuilder().build_from_assets([entry, low_value_target, high_value_target])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()

    assert len(paths) >= 2
    scores = [p.risk_score for p in paths]
    assert scores == sorted(scores, reverse=True), "Paths must be sorted highest risk_score first"

    highest = get_highest_risk_path(paths)
    assert highest.target_asset_id == "10.0.4.3", "The path reaching the higher-risk target should rank highest"
    print("[PASS] test_risk_ranking_orders_highest_first")


# ----------------------------------------------------------------------
# 8. NO AVAILABLE PATH
# ----------------------------------------------------------------------
def test_no_available_path_between_disconnected_assets():
    # Two assets that share NOTHING (different ports, services, OS,
    # no vulnerabilities in common) -- there must be no fabricated path.
    entry = make_asset("10.0.5.1", ports=[21], services=[{"service_name": "ftp", "port": 21}],
                        operating_system="Linux")
    target = make_asset("10.0.5.2", ports=[3389], services=[{"service_name": "rdp", "port": 3389}],
                         operating_system="Windows Server 2019", risk_score=90, risk_level="Critical")
    graph = KnowledgeGraphBuilder().build_from_assets([entry, target])
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()

    assert paths == [], "No path should be found between assets sharing no exposure"
    summary = summarize_paths(paths)
    assert summary["message"] == "No potential attack paths identified from the available Cyber Twin data."
    print("[PASS] test_no_available_path_between_disconnected_assets")


def run_all():
    print("=" * 50)
    print("CYBERTWINAI MODULE 7 -- ATTACK PATH ANALYSIS TESTS")
    print("=" * 50)
    test_empty_graph()
    test_single_asset()
    test_simple_entry_to_target_path()
    test_multiple_possible_paths()
    test_cyclic_graph_does_not_hang_or_repeat_nodes()
    test_missing_vulnerability_information()
    test_risk_ranking_orders_highest_first()
    test_no_available_path_between_disconnected_assets()
    print("=" * 50)
    print("All Module 7 tests PASSED")
    print("=" * 50)


if __name__ == "__main__":
    run_all()
