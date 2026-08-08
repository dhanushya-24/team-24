"""
scoring.py
==========
RESPONSIBILITY: Hold the static scoring rules and the score-to-level
mapping used by risk_calculator.py. Nothing in this file inspects an
asset or performs any calculation on real data -- it only defines the
numbers and thresholds. This mirrors rules.py in Module 3: constants
and lookups stay separate from the orchestration logic that uses them.
"""

from typing import List, Tuple

# ----------------------------------------------------------------------
# VULNERABILITY SEVERITY SCORES
# ----------------------------------------------------------------------
# Points added per vulnerability finding, based on its severity string
# (case-insensitive match against Vulnerability["severity"], as
# produced by Module 3's VulnerabilityManager).
VULNERABILITY_SEVERITY_SCORES = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}

# ----------------------------------------------------------------------
# PORT SCORING
# ----------------------------------------------------------------------
# Flat points added for every open port on the asset (bigger attack
# surface = more risk), regardless of which port it is.
POINTS_PER_OPEN_PORT = 2

# Additional points added on top of POINTS_PER_OPEN_PORT for each of
# these specific high-risk ports that is open:
#   3389 = RDP, 445 = SMB, 23 = Telnet, 21 = FTP
CRITICAL_PORTS = {3389, 445, 23, 21}
CRITICAL_PORT_BONUS = 5

# ----------------------------------------------------------------------
# OPERATING SYSTEM SCORING
# ----------------------------------------------------------------------
# Extra points if the asset's operating_system string indicates it is
# a Windows Server edition (higher-value target, common attack focus).
WINDOWS_SERVER_BONUS = 10

# ----------------------------------------------------------------------
# SCORE CAP
# ----------------------------------------------------------------------
MAX_RISK_SCORE = 100

# ----------------------------------------------------------------------
# RISK LEVEL THRESHOLDS
# ----------------------------------------------------------------------
# Each tuple: (minimum_score, maximum_score, label)
# Checked in order; the first range containing the score wins.
RISK_LEVEL_RANGES: List[Tuple[int, int, str]] = [
    (0, 20, "Low"),
    (21, 50, "Medium"),
    (51, 80, "High"),
    (81, 100, "Critical"),
]


def get_risk_level(risk_score: int) -> str:
    """
    Translate a numeric risk_score (0-100) into a human-readable
    risk_level label, using RISK_LEVEL_RANGES above.

    Returns "Unknown" only if risk_score somehow falls outside the
    documented 0-100 range (should not normally happen, since
    risk_calculator.py caps scores at MAX_RISK_SCORE).
    """
    for minimum, maximum, label in RISK_LEVEL_RANGES:
        if minimum <= risk_score <= maximum:
            return label
    return "Unknown"
