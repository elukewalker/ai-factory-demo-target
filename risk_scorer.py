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
    pass
