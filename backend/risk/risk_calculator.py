"""
risk_calculator.py
===================
RESPONSIBILITY: Calculate a numeric risk_score (0-100) and a
risk_level label for Digital Twin assets, using the vulnerability
findings from Module 3 plus the asset's own ports/OS data.

This file contains NO scoring constants itself (no hardcoded point
values or thresholds) -- all of that lives in scoring.py. This file
only orchestrates: extract data from the asset -> add up points from
scoring.py's tables -> cap the total -> translate it to a level ->
save the result back onto the asset. This mirrors the same
separation used by vulnerability_manager.py in Module 3.

Workflow implemented here (matches the project spec):
    Digital Twin Asset (with vulnerabilities from Module 3)
        -> extract OS, open ports, vulnerabilities
        -> apply the scoring rules in scoring.py
        -> cap at 100, translate to a risk_level
        -> update the asset and store it in MongoDB
"""

from typing import List, Optional

from backend.twin.asset import Asset
from backend.twin.twin_manager import TwinManager
from backend.risk.scoring import (
    VULNERABILITY_SEVERITY_SCORES,
    POINTS_PER_OPEN_PORT,
    CRITICAL_PORTS,
    CRITICAL_PORT_BONUS,
    WINDOWS_SERVER_BONUS,
    MAX_RISK_SCORE,
    get_risk_level,
)


class RiskCalculator:
    """
    Owns the risk-scoring workflow: score one asset, or a whole list
    of assets, and (optionally) persist the results back into the
    Digital Twin via TwinManager.
    """

    def __init__(self, twin_manager: Optional[TwinManager] = None):
        """
        Args:
            twin_manager: an existing TwinManager instance, used to
                save the updated asset back into MongoDB. Passing None
                is allowed for pure in-memory scoring (e.g. unit
                tests) where you don't want any database writes.
        """
        self.twin_manager = twin_manager

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    def calculate_asset_risk(self, asset: Asset, persist: bool = True) -> dict:
        """
        Calculate risk_score and risk_level for a single asset, update
        the asset object in place, and (optionally) save it to MongoDB.

        Args:
            asset: an Asset object, ideally already processed by
                Module 3's VulnerabilityManager so `asset.vulnerabilities`
                is populated (if it's empty, this still works -- the
                asset just scores lower).
            persist: if True and a TwinManager was provided at
                construction time, save the updated asset back to
                MongoDB immediately.

        Returns:
            {"risk_score": int, "risk_level": str}
            (matches the exact output format given in the project spec)
        """
        score = 0
        score += self._score_vulnerabilities(asset)
        score += self._score_ports(asset)
        score += self._score_operating_system(asset)

        score = min(score, MAX_RISK_SCORE)
        level = get_risk_level(score)

        # Update the Digital Twin asset in place
        asset.risk_score = score
        asset.risk_level = level

        if persist and self.twin_manager is not None:
            self.twin_manager.save_asset(asset)

        return {"risk_score": score, "risk_level": level}

    def calculate_all_assets(self, asset_list: List[Asset], persist: bool = True) -> List[Asset]:
        """
        Run calculate_asset_risk() on every asset in a list.

        Returns the same list of Asset objects, each updated in place
        with its own risk_score and risk_level populated.
        """
        for asset in asset_list:
            self.calculate_asset_risk(asset, persist=persist)
        return asset_list

    # ------------------------------------------------------------------
    # INTERNAL SCORING STEPS
    # ------------------------------------------------------------------
    def _score_vulnerabilities(self, asset: Asset) -> int:
        """
        Add points for every vulnerability finding on the asset, based
        on its severity (see VULNERABILITY_SEVERITY_SCORES in scoring.py).
        Vulnerability findings are the dicts produced by Module 3's
        VulnerabilityManager, e.g. {"severity": "Critical", ...}.
        """
        points = 0
        for vulnerability in asset.vulnerabilities:
            severity = (vulnerability.get("severity") or "").lower()
            points += VULNERABILITY_SEVERITY_SCORES.get(severity, 0)
        return points

    def _score_ports(self, asset: Asset) -> int:
        """
        Add points for open ports:
            - a flat amount per open port (bigger attack surface)
            - an extra bonus for each port considered "critical"
              (RDP/SMB/Telnet/FTP), since these are common attack
              vectors regardless of what else is running.
        """
        points = 0
        for port in asset.ports:
            points += POINTS_PER_OPEN_PORT
            if port in CRITICAL_PORTS:
                points += CRITICAL_PORT_BONUS
        return points

    def _score_operating_system(self, asset: Asset) -> int:
        """
        Add a bonus if the asset appears to be running a Windows
        Server edition. Windows Server machines are typically
        higher-value targets (domain controllers, file servers, etc.)
        than a generic workstation OS.

        Matching is intentionally simple: both the words "windows" and
        "server" must appear in the operating_system string (case-
        insensitive), so it catches variations like "Windows Server
        2016", "Windows Server 2019 Standard", etc.
        """
        os_name = (asset.operating_system or "").lower()
        if "windows" in os_name and "server" in os_name:
            return WINDOWS_SERVER_BONUS
        return 0
