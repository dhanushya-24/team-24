"""
attack_path_queries.py
=======================
RESPONSIBILITY: Read-only lookups and summarization over a list of
already-discovered AttackPath objects (from attack_path_analyzer.py).
No path discovery, no scoring, no graph traversal happens here --
every function just filters or summarizes results that already exist.
"""

from collections import Counter
from typing import Any, Dict, List, Optional

from backend.attack_paths.attack_path_models import AttackPath

NO_PATHS_MESSAGE = "No potential attack paths identified from the available Cyber Twin data."


def get_path_by_id(paths: List[AttackPath], path_id: str) -> Optional[AttackPath]:
    """Return the AttackPath with this exact path_id, or None if not found."""
    return next((path for path in paths if path.path_id == path_id), None)


def get_paths_by_severity(paths: List[AttackPath], severity: str) -> List[AttackPath]:
    """Return every path matching the given severity ('Low'/'Medium'/'High'/'Critical'), case-insensitive."""
    normalized = severity.strip().lower()
    return [path for path in paths if path.severity.strip().lower() == normalized]


def get_paths_involving_asset(paths: List[AttackPath], asset_id: str) -> List[AttackPath]:
    """Return every path where the given asset_id appears as the entry,
    the target, or any intermediate asset along the path."""
    results = []
    for path in paths:
        asset_ids_on_path = {
            step.node_id.split("asset:", 1)[-1]
            for step in path.nodes
            if step.node_type == "asset"
        }
        if asset_id in asset_ids_on_path:
            results.append(path)
    return results


def get_paths_involving_vulnerability(paths: List[AttackPath], vulnerability_id: str) -> List[AttackPath]:
    """Return every path that involves the given vulnerability ID (e.g. "VULN-001")."""
    return [
        path for path in paths
        if any(v.get("id") == vulnerability_id for v in path.vulnerabilities_involved)
    ]


def get_highest_risk_path(paths: List[AttackPath]) -> Optional[AttackPath]:
    """Return the single highest-risk_score path, or None if the list is empty."""
    if not paths:
        return None
    return max(paths, key=lambda path: path.risk_score)


def summarize_paths(paths: List[AttackPath]) -> Dict[str, Any]:
    """
    Build a summary of a list of AttackPath results, safe to call with
    an empty list (returns a clear "no paths" message rather than
    letting a caller divide-by-zero or index into an empty list).
    """
    if not paths:
        return {
            "total_paths": 0,
            "highest_risk_path_id": None,
            "highest_risk_score": None,
            "severity_breakdown": {},
            "distinct_entry_assets": [],
            "distinct_target_assets": [],
            "message": NO_PATHS_MESSAGE,
        }

    highest = get_highest_risk_path(paths)
    severity_breakdown = dict(Counter(path.severity for path in paths))
    entry_assets = sorted({path.entry_asset_id for path in paths})
    target_assets = sorted({path.target_asset_id for path in paths})

    return {
        "total_paths": len(paths),
        "highest_risk_path_id": highest.path_id if highest else None,
        "highest_risk_score": highest.risk_score if highest else None,
        "severity_breakdown": severity_breakdown,
        "distinct_entry_assets": entry_assets,
        "distinct_target_assets": target_assets,
        "message": None,
    }
