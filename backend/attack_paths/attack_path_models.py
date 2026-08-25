"""
attack_path_models.py
======================
RESPONSIBILITY: Define the internal representation of an attack path.
Pure data shape only -- no path discovery, no scoring, no graph
traversal logic (that lives in attack_path_analyzer.py).

Reuses the existing Knowledge Graph's own node/edge shape (node_type,
label, relationship) rather than inventing a parallel asset or
vulnerability model -- an AttackPathStep is just a thin wrapper around
one graph node as visited along a path.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackPathStep:
    """
    One node visited along an attack path, in order.

    Fields:
        node_id:    the Knowledge Graph node ID (e.g. "asset:192.168.56.101",
                    "port:80", "vulnerability:VULN-001") -- same IDs used
                    throughout backend/knowledge_graph.
        node_type:  "asset" | "ip" | "operating_system" | "port" |
                    "service" | "vulnerability" | "risk"
        label:      human-readable label, copied from the graph node.
        relationship_from_previous:
                    the KG 'relationship' attribute of the edge used to
                    reach this node from the previous step (e.g.
                    "ASSET_EXPOSES_PORT"), or None for the first step.
    """
    node_id: str
    node_type: str
    label: str
    relationship_from_previous: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "relationship_from_previous": self.relationship_from_previous,
        }


@dataclass
class AttackPath:
    """
    A single potential/theoretical attack path through the Knowledge
    Graph, from an entry asset to a target asset.

    IMPORTANT WORDING: this represents a POSSIBLE / THEORETICAL /
    RISK-BASED path derived only from existing Cyber Twin data. It is
    never evidence that exploitation was actually performed -- that
    would require real simulation evidence (a future Module 8 concern).

    Fields:
        path_id:                 stable ID derived from the path's node
                                  sequence (same path -> same ID every time).
        entry_asset_id:           asset_id of the path's starting asset.
        target_asset_id:          asset_id of the path's ending asset.
        nodes:                    ordered list of AttackPathStep.
        vulnerabilities_involved: vulnerability nodes encountered along the path.
        services_involved:        service labels encountered along the path.
        path_length:              number of hops (edges) in the path.
        risk_score:               0-100, see attack_path_analyzer.py's scoring.
        severity:                 "Low" | "Medium" | "High" | "Critical"
                                  (reuses backend.risk.scoring.get_risk_level's
                                  thresholds, so it means the same thing
                                  here as it does everywhere else in the project).
        explanation:              human-readable reasoning, referencing only
                                  data that was actually found in the graph.
    """
    path_id: str
    entry_asset_id: str
    target_asset_id: str
    nodes: List[AttackPathStep] = field(default_factory=list)
    vulnerabilities_involved: List[Dict[str, Any]] = field(default_factory=list)
    services_involved: List[str] = field(default_factory=list)
    path_length: int = 0
    risk_score: int = 0
    severity: str = "Low"
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "entry_asset_id": self.entry_asset_id,
            "target_asset_id": self.target_asset_id,
            "nodes": [step.to_dict() for step in self.nodes],
            "relationships": [
                step.relationship_from_previous for step in self.nodes[1:]
            ],
            "vulnerabilities_involved": self.vulnerabilities_involved,
            "services_involved": self.services_involved,
            "path_length": self.path_length,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "explanation": self.explanation,
        }
