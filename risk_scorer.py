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

    # Add severity-based score
    severity = event.get("severity", "").lower()
    if severity == "critical":
        score += 0.5
    elif severity == "high":
        score += 0.3
    elif severity == "medium":
        score += 0.1

    # Add flag-based scores
    if event.get("privileged") is True:
        score += 0.3
    if event.get("external_origin") is True:
        score += 0.2
    if event.get("repeated") is True:
        score += 0.1

    # Cap at 1.0
    return min(score, 1.0)
