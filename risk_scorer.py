"""risk_scorer.py — Security event risk scoring.

This stub is intentionally left unimplemented.
The AI Factory agent will implement calculate_risk_score via factory build.
"""


def calculate_risk_score(event: dict) -> float:
    """Score a security event from 0.0 (no risk) to 1.0 (maximum risk).

    Args:
        event: A security event dictionary. Expected keys:
            severity (str): "critical", "high", "medium", or "low"
            privileged (bool): True if the action was performed with elevated privileges
            external_origin (bool): True if the event originated from outside the network
            repeated (bool): True if this event pattern has been seen before

    Returns:
        float: Risk score in [0.0, 1.0].
    """
    score = 0.0

    # Severity contributions
    severity = event.get("severity", "")
    if severity == "critical":
        score += 0.5
    elif severity == "high":
        score += 0.3
    elif severity == "medium":
        score += 0.1

    # Flag contributions
    if event.get("privileged") is True:
        score += 0.3
    if event.get("external_origin") is True:
        score += 0.2
    if event.get("repeated") is True:
        score += 0.1

    # Cap at 1.0
    return min(score, 1.0)


def enrich_event(event: dict) -> dict:
    """Enrich a security event with risk score and derived triage fields.

    Args:
        event: A security event dictionary.

    Returns:
        dict: A new dictionary containing all original event keys plus:
            - risk_score (float): Calculated risk score [0.0, 1.0]
            - priority (str): "P1", "P2", "P3", or "P4"
            - recommended_action (str): Triage instruction
            - escalate (bool): True if P1 or P2, False otherwise
    """
    risk_score = calculate_risk_score(event)

    # Determine priority and action based on risk score
    if risk_score >= 0.8:
        priority, recommended_action = "P1", "Page on-call immediately"
    elif risk_score >= 0.5:
        priority, recommended_action = "P2", "Investigate within 1 hour"
    elif risk_score >= 0.2:
        priority, recommended_action = "P3", "Investigate within 24 hours"
    else:
        priority, recommended_action = "P4", "Log and monitor"

    # Return new dict with original keys + derived fields
    return {
        **event,
        "risk_score": risk_score,
        "priority": priority,
        "recommended_action": recommended_action,
        "escalate": priority in ("P1", "P2"),
    }
