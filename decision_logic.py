"""
decision_logic.py
==================
This is the "brain" of the AI Security Agent for Week 1-2.

IMPORTANT: There is NO machine learning here. Every decision is made
using plain Python if-else statements. This is intentional -- you
asked to understand the agent's reasoning before adding ML on top
of it later.

Every function here is PURE (no side effects, no database calls,
no printing). That makes them trivially testable and easy to explain
one at a time. All "doing" (saving, updating dashboards) happens in
ai_agent.py, not here.
"""


def analyze(event: dict) -> bool:
    """
    Decide whether an event is suspicious.

    Rule: any event_type other than 'normal' is treated as suspicious.
    This is deliberately simple -- in a real SOC, a junior analyst's
    first filter is exactly this: "is this normal traffic, or not?"

    Returns:
        True  -> suspicious, escalate further
        False -> normal, do nothing
    """
    normal_event_types = {"normal"}
    return event.get("event_type") not in normal_event_types


def calculate_risk(device_risk_score: int, event: dict) -> int:
    """
    Combine the device's existing risk score (from the Digital Twin)
    with the severity of THIS specific event.

    Why combine both instead of using just one?
        - device_risk_score alone doesn't tell us anything happened
          right now.
        - event severity alone ignores how valuable/vulnerable the
          target device already is.

    Severity weight (added on top of the device's baseline risk):
        low    -> +10
        medium -> +25
        high   -> +40

    Final score capped at 100.
    """
    severity_weights = {"low": 10, "medium": 25, "high": 40}
    severity = event.get("severity", "low")
    added_risk = severity_weights.get(severity, 10)

    total = device_risk_score + added_risk
    return min(total, 100)


def recommend_defense(event: dict, risk_score: int) -> str:
    """
    Map an event type + risk score to a concrete, human-readable
    recommendation.

    This is a lookup table, not "AI" in the deep-learning sense --
    but it IS the agent's expert knowledge, expressed as code.
    That's exactly what STEP 9 asked for: understand the logic
    before it becomes a black box.
    """
    event_type = event.get("event_type")

    # High-risk situations get the strongest response regardless of type
    if risk_score >= 70:
        prefix = "URGENT: "
    elif risk_score >= 40:
        prefix = "WARNING: "
    else:
        prefix = "INFO: "

    recommendations = {
        "port_scan": "Block the source IP at the firewall and monitor for follow-up connection attempts.",
        "brute_force": "Lock the targeted account temporarily and enable multi-factor authentication.",
        "unusual_traffic": "Isolate the device from the network segment and inspect running processes.",
        "login_attempt": "Verify with the device owner and check login origin/IP reputation.",
    }

    action = recommendations.get(
        event_type,
        "Investigate manually -- no predefined rule exists for this event type yet."
    )

    return prefix + action


def decide_action_taken(risk_score: int) -> str:
    """
    Week 1-2 scope: the agent NEVER performs automatic actions on the
    real network (no auto-blocking, no auto-isolation). It only
    RECORDS what it would recommend. This is a deliberate safety
    boundary for a student prototype.

    This function just labels what happened, for the log.
    """
    if risk_score >= 70:
        return "logged_only"  # future weeks: could become "isolated"
    return "logged_only"
