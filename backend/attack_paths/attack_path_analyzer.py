"""
attack_path_analyzer.py
========================
RESPONSIBILITY: Defensive attack-path ANALYSIS over the existing
Module 6 Knowledge Graph. This module:

    - identifies plausible entry points and critical targets from
      data Modules 1-4 already computed (exposed ports, known
      vulnerabilities, risk levels) -- it does not scan or detect
      anything new,
    - traverses the existing Knowledge Graph to find POSSIBLE paths
      between them,
    - scores each path with a transparent, explainable formula that
      reuses the existing Module 4 risk-scoring constants,
    - never performs exploitation, never executes anything against a
      real machine, and never claims a path was actually exploited.

Every AttackPath produced here is a THEORETICAL / POSSIBLE path
inferred from existing Cyber Twin data -- see attack_path_models.py.
"""

import hashlib
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from backend.knowledge_graph.graph_queries import (
    get_nodes_by_type,
    get_asset_ports,
    get_asset_vulnerabilities,
    get_high_risk_assets,
    get_asset_risk,
)
from backend.risk.scoring import (
    VULNERABILITY_SEVERITY_SCORES,
    CRITICAL_PORTS,
    CRITICAL_PORT_BONUS,
    MAX_RISK_SCORE,
    get_risk_level,
)
from backend.vulnerability.rules import PORT_RULES
from backend.attack_paths.attack_path_models import AttackPath, AttackPathStep

# Node types excluded from PATH TRAVERSAL (they can still appear as
# attributes on a step, they just aren't used as pivots between
# assets):
#   - "ip":   an asset's IP is unique to that asset -- it provides no
#             lateral movement value, it's just an identifier.
#   - "risk": a risk level (e.g. "risk:high") is a shared CLASSIFICATION
#             label, not a real attack-surface mechanism -- treating it
#             as a pivot would create meaningless paths connecting
#             every high-risk asset to every other one.
# Ports, services, vulnerabilities, and operating systems ARE kept as
# pivots: two assets sharing a vulnerable service/port/OS is a real,
# defensible lateral-movement signal.
EXCLUDED_PIVOT_NODE_TYPES = {"ip", "risk"}

# Ports considered "exposure-relevant" for entry-point identification,
# reusing knowledge the project already has rather than inventing a
# new port list: Module 4's CRITICAL_PORTS plus Module 3's PORT_RULES
# keys (FTP/Telnet/HTTP/RDP).
EXPOSURE_RELEVANT_PORTS = set(CRITICAL_PORTS) | set(PORT_RULES.keys())


class AttackPathAnalyzer:
    """
    Analyzes an existing Knowledge Graph (built by Module 6) to find
    and score potential attack paths. Does not build, save, or modify
    the Knowledge Graph itself -- it only reads it.
    """

    def __init__(self, graph: nx.DiGraph):
        """
        Args:
            graph: an already-built Knowledge Graph, e.g. from
                backend.knowledge_graph.graph_manager.KnowledgeGraphManager
                .get_graph()/.build_graph(), or reconstructed via
                graph_from_dict(). This class never builds its own
                graph -- Module 7 is intentionally read-only over
                Module 6's output.
        """
        self.graph = graph
        self.traversal_graph = self._build_traversal_graph(graph)

    # ------------------------------------------------------------------
    # ENTRY POINT / TARGET IDENTIFICATION
    # ------------------------------------------------------------------
    def identify_entry_points(self, max_candidates: int = 10) -> List[Dict[str, Any]]:
        """
        Identify plausible attack entry points: assets with exposed
        risky ports and/or known vulnerabilities. This is a heuristic
        over EXISTING data (ports/vulnerabilities already discovered
        by Modules 1 and 3) -- it does not determine which assets are
        actually internet-facing, since the Cyber Twin does not yet
        track network position (see backend/twin/connection.py).

        Returns a list of candidates sorted by exposure_score
        (highest first), each shaped like:
            {"asset_id", "label", "exposure_score",
             "exposed_ports", "vulnerability_count"}
        """
        candidates = []
        for asset in get_nodes_by_type(self.graph, "asset"):
            asset_id = asset.get("asset_id")
            if not asset_id:
                continue

            ports = get_asset_ports(self.graph, asset_id)
            port_numbers = {p.get("port") for p in ports if p.get("port") is not None}
            exposed_risky_ports = sorted(port_numbers & EXPOSURE_RELEVANT_PORTS)

            vulnerabilities = get_asset_vulnerabilities(self.graph, asset_id)

            exposure_score = (
                len(exposed_risky_ports) * 10
                + len(vulnerabilities) * 15
                + len(port_numbers) * 2
            )
            if exposure_score <= 0:
                continue  # no known exposure at all -- not a plausible entry point

            candidates.append({
                "asset_id": asset_id,
                "label": asset.get("label", asset_id),
                "exposure_score": exposure_score,
                "exposed_ports": exposed_risky_ports,
                "vulnerability_count": len(vulnerabilities),
            })

        candidates.sort(key=lambda c: c["exposure_score"], reverse=True)
        return candidates[:max_candidates]

    def identify_critical_targets(self, max_candidates: int = 10) -> List[Dict[str, Any]]:
        """
        Identify plausible attack targets: assets already flagged
        High/Critical risk by Module 4. Falls back to "server"-type
        assets (still using their real computed risk score) only if
        no High/Critical assets exist, so this never fabricates a
        target out of nothing.

        Returns a list of candidates sorted by risk_score (highest
        first), each shaped like:
            {"asset_id", "label", "risk_score", "risk_level", "device_type"}
        """
        high_risk_assets = get_high_risk_assets(self.graph)
        candidate_assets = high_risk_assets

        if not candidate_assets:
            # No High/Critical assets exist -- fall back to servers,
            # still ranked by their real (possibly low) risk score,
            # never invented.
            candidate_assets = [
                asset for asset in get_nodes_by_type(self.graph, "asset")
                if asset.get("device_type") == "server"
            ]

        results = []
        for asset in candidate_assets:
            asset_id = asset.get("asset_id")
            if not asset_id:
                continue
            risk_info = get_asset_risk(self.graph, asset_id)
            results.append({
                "asset_id": asset_id,
                "label": asset.get("label", asset_id),
                "risk_score": risk_info["risk_score"],
                "risk_level": risk_info["risk_level"],
                "device_type": asset.get("device_type"),
            })

        results.sort(key=lambda c: c["risk_score"], reverse=True)
        return results[:max_candidates]

    # ------------------------------------------------------------------
    # PATH DISCOVERY
    # ------------------------------------------------------------------
    def find_attack_paths(
        self,
        entry_asset_id: Optional[str] = None,
        target_asset_id: Optional[str] = None,
        max_path_length: int = 6,
        max_paths_per_pair: int = 3,
        top_n: int = 10,
    ) -> List[AttackPath]:
        """
        Find and score potential attack paths through the Knowledge Graph.

        Args:
            entry_asset_id: restrict to this entry asset only. If
                None, candidates from identify_entry_points() are used.
            target_asset_id: restrict to this target asset only. If
                None, candidates from identify_critical_targets() are used.
            max_path_length: maximum number of hops (edges) per path.
                Directly bounds traversal depth -- this, plus
                NetworkX's all_simple_paths() never revisiting a node,
                is what prevents infinite/cyclic traversal.
            max_paths_per_pair: cap on how many distinct paths are
                collected for a single (entry, target) pair, to avoid
                combinatorial explosion on a densely-shared graph.
            top_n: maximum number of paths returned overall, highest
                risk_score first.

        Returns:
            A list of AttackPath objects, or an empty list if the
            graph has no assets, no plausible entry points, no
            plausible targets, or no path exists between any of them.
            This function never raises for those cases -- see
            STEP 10 (graceful error handling) in the Module 7 spec.
        """
        if self.graph.number_of_nodes() == 0:
            return []

        entry_candidates = (
            [{"asset_id": entry_asset_id}] if entry_asset_id
            else self.identify_entry_points()
        )
        target_candidates = (
            [{"asset_id": target_asset_id}] if target_asset_id
            else self.identify_critical_targets()
        )

        if not entry_candidates or not target_candidates:
            return []

        discovered_paths: List[AttackPath] = []
        seen_path_ids = set()

        for entry in entry_candidates:
            entry_node_id = f"asset:{entry['asset_id']}"
            if entry_node_id not in self.traversal_graph:
                continue

            for target in target_candidates:
                if entry.get("asset_id") == target.get("asset_id"):
                    continue  # an asset is never its own attack path

                target_node_id = f"asset:{target['asset_id']}"
                if target_node_id not in self.traversal_graph:
                    continue

                paths_for_pair = self._find_simple_paths(
                    entry_node_id, target_node_id, max_path_length, max_paths_per_pair
                )

                for raw_path in paths_for_pair:
                    attack_path = self._build_attack_path(raw_path)
                    if attack_path.path_id in seen_path_ids:
                        continue
                    seen_path_ids.add(attack_path.path_id)
                    discovered_paths.append(attack_path)

        discovered_paths.sort(key=lambda path: path.risk_score, reverse=True)
        return discovered_paths[:top_n]

    def _find_simple_paths(
        self, source: str, target: str, max_path_length: int, max_paths_per_pair: int
    ) -> List[List[str]]:
        """
        Wrap nx.all_simple_paths() with a hard cap on how many paths
        we collect for one (source, target) pair, and safe handling
        if either node is missing or disconnected (no exception --
        just no paths found).
        """
        try:
            path_generator = nx.all_simple_paths(
                self.traversal_graph, source, target, cutoff=max_path_length
            )
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return []

        collected = []
        for path in path_generator:
            collected.append(path)
            if len(collected) >= max_paths_per_pair:
                break
        return collected

    # ------------------------------------------------------------------
    # ATTACK PATH CONSTRUCTION
    # ------------------------------------------------------------------
    def _build_attack_path(self, path_nodes: List[str]) -> AttackPath:
        """Convert a raw list of graph node IDs into a fully-scored, explained AttackPath."""
        steps: List[AttackPathStep] = []
        vulnerabilities_involved: List[Dict[str, Any]] = []
        services_involved: List[str] = []
        ports_encountered: List[int] = []

        for index, node_id in enumerate(path_nodes):
            node_data = self.graph.nodes.get(node_id, {})
            node_type = node_data.get("node_type", "unknown")
            label = node_data.get("label", node_id)

            relationship = None
            if index > 0:
                previous_node_id = path_nodes[index - 1]
                edge_data = self.traversal_graph.get_edge_data(previous_node_id, node_id) or {}
                relationship = edge_data.get("relationship")

            steps.append(AttackPathStep(
                node_id=node_id, node_type=node_type, label=label,
                relationship_from_previous=relationship,
            ))

            if node_type == "vulnerability":
                vulnerabilities_involved.append({
                    "id": node_data.get("vulnerability_id"),
                    "name": node_data.get("label"),
                    "severity": node_data.get("severity"),
                })
            elif node_type == "service":
                services_involved.append(label)
            elif node_type == "port" and node_data.get("port") is not None:
                ports_encountered.append(node_data.get("port"))

        entry_asset_id = self._extract_asset_id(path_nodes[0])
        target_asset_id = self._extract_asset_id(path_nodes[-1])
        path_length = len(path_nodes) - 1

        risk_score, severity, explanation = self._score_path(
            vulnerabilities_involved, ports_encountered, target_asset_id, path_length,
        )

        path_id = "PATH-" + hashlib.md5("|".join(path_nodes).encode("utf-8")).hexdigest()[:10]

        return AttackPath(
            path_id=path_id,
            entry_asset_id=entry_asset_id,
            target_asset_id=target_asset_id,
            nodes=steps,
            vulnerabilities_involved=vulnerabilities_involved,
            services_involved=services_involved,
            path_length=path_length,
            risk_score=risk_score,
            severity=severity,
            explanation=explanation,
        )

    def _extract_asset_id(self, node_id: str) -> str:
        """Read the real asset_id off a graph node, falling back to
        parsing the node ID string if the attribute is somehow missing."""
        node_data = self.graph.nodes.get(node_id, {})
        return node_data.get("asset_id") or node_id.split("asset:", 1)[-1]

    # ------------------------------------------------------------------
    # RISK-AWARE, EXPLAINABLE SCORING
    # ------------------------------------------------------------------
    def _score_path(
        self,
        vulnerabilities_involved: List[Dict[str, Any]],
        ports_encountered: List[int],
        target_asset_id: str,
        path_length: int,
    ) -> Tuple[int, str, str]:
        """
        Transparent, explainable 0-100 risk score for one attack path.
        Every term reuses existing Module 4 scoring constants -- no
        new severity scale or invented CVSS numbers are introduced.

        Formula:
            + severity points per vulnerability encountered along the
              path (backend.risk.scoring.VULNERABILITY_SEVERITY_SCORES)
            + CRITICAL_PORT_BONUS for each commonly-targeted port
              (RDP/SMB/Telnet/FTP) encountered along the path
            + half of the TARGET asset's own already-computed
              risk_score (reaching a high-risk asset matters most)
            - a small penalty for longer, more indirect paths
              (3 points per hop beyond 2), so equally-severe but more
              direct paths rank higher
            capped to [0, 100]

        Returns (risk_score, severity, explanation).
        """
        score = 0

        for vulnerability in vulnerabilities_involved:
            severity_key = (vulnerability.get("severity") or "").lower()
            score += VULNERABILITY_SEVERITY_SCORES.get(severity_key, 0)

        risky_ports_on_path = [port for port in ports_encountered if port in CRITICAL_PORTS]
        score += len(risky_ports_on_path) * CRITICAL_PORT_BONUS

        target_risk = get_asset_risk(self.graph, target_asset_id)
        score += round(target_risk["risk_score"] * 0.5)

        hop_penalty = max(0, path_length - 2) * 3
        score -= hop_penalty

        score = max(0, min(MAX_RISK_SCORE, score))
        severity = get_risk_level(score)

        explanation = self._explain_path(
            vulnerabilities_involved, risky_ports_on_path, target_risk, severity, path_length,
        )
        return score, severity, explanation

    def _explain_path(
        self,
        vulnerabilities_involved: List[Dict[str, Any]],
        risky_ports_on_path: List[int],
        target_risk: Dict[str, Any],
        severity: str,
        path_length: int,
    ) -> str:
        """
        Build a human-readable explanation referencing ONLY data that
        was actually found on this path -- never inventing detail.
        Uses "potential"/"theoretical" wording throughout, per the
        Module 7 requirement to never claim exploitation occurred.
        """
        reasons = []

        if risky_ports_on_path:
            port_list = ", ".join(str(port) for port in sorted(set(risky_ports_on_path)))
            reasons.append(f"the path crosses commonly-targeted exposed port(s) {port_list}")

        if vulnerabilities_involved:
            highest_severity = max(
                (v.get("severity") or "Unknown" for v in vulnerabilities_involved),
                key=lambda s: VULNERABILITY_SEVERITY_SCORES.get(s.lower(), 0),
            )
            reasons.append(
                f"the path involves {len(vulnerabilities_involved)} known vulnerability "
                f"finding(s) (highest severity: {highest_severity})"
            )

        reasons.append(f"the target asset's own computed risk level is {target_risk['risk_level']}")

        reason_text = "; ".join(reasons)
        return (
            f"This is a {severity.lower()}-risk potential path ({path_length} hop(s)) because "
            f"{reason_text}. This represents a theoretical, risk-based path derived from "
            f"existing Cyber Twin data -- no exploitation was performed or simulated."
        )

    # ------------------------------------------------------------------
    # INTERNAL: TRAVERSAL GRAPH CONSTRUCTION
    # ------------------------------------------------------------------
    @staticmethod
    def _build_traversal_graph(graph: nx.DiGraph) -> nx.Graph:
        """
        Build an UNDIRECTED working copy of the graph for path-finding,
        excluding EXCLUDED_PIVOT_NODE_TYPES (ip, risk) entirely.

        Undirected because the Knowledge Graph's edges point FROM an
        asset TO its attributes (asset -> port), so two assets sharing
        a port only "connect" if you can traverse asset_A -> port
        backwards to port -> asset_B. Converting to undirected is what
        makes "shared exposure" traversal possible; it does not
        change what relationships exist, only which direction they
        can be walked for analysis purposes. Edge attributes
        (including `relationship`) are preserved from the original
        directed edges.
        """
        working_graph = nx.Graph()

        for node_id, node_data in graph.nodes(data=True):
            if node_data.get("node_type") in EXCLUDED_PIVOT_NODE_TYPES:
                continue
            working_graph.add_node(node_id, **node_data)

        for source, target, edge_data in graph.edges(data=True):
            if source in working_graph and target in working_graph:
                working_graph.add_edge(source, target, **edge_data)

        return working_graph
