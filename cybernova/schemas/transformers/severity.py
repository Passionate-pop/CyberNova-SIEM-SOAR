"""
CyberNova — Severity Mapping
Single source of truth for risk_score → severity string conversion.
"""
from __future__ import annotations


def map_severity(score: float) -> str:
    """Convert a numeric risk score (0–100) to a severity label.

    Thresholds:
        >= 80 → critical
        >= 60 → high
        >= 40 → medium
        <  40 → low
    """
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"
