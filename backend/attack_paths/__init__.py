"""
Attack Path Analysis package - Module 7.

Defensive ANALYSIS only, over the existing Module 6 Knowledge Graph
and existing Module 3/4 vulnerability/risk data. This package never
performs real exploitation, never executes anything on a discovered
machine, and never claims a path was actually exploited -- every
AttackPath it produces is an explicitly-labeled potential/theoretical
path inferred from data the Cyber Twin already has.
"""

from backend.attack_paths.attack_path_models import AttackPath, AttackPathStep
from backend.attack_paths.attack_path_analyzer import AttackPathAnalyzer
from backend.attack_paths.attack_path_queries import (
    get_path_by_id,
    get_paths_by_severity,
    get_paths_involving_asset,
    get_paths_involving_vulnerability,
    get_highest_risk_path,
    summarize_paths,
)

__all__ = [
    "AttackPath",
    "AttackPathStep",
    "AttackPathAnalyzer",
    "get_path_by_id",
    "get_paths_by_severity",
    "get_paths_involving_asset",
    "get_paths_involving_vulnerability",
    "get_highest_risk_path",
    "summarize_paths",
]
