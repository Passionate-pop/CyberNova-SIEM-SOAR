"""
CyberNova — Correlation Engine (simplified dispatch to rules_engine)
This module re-exports the active correlation system for backward compatibility.
The full sequence-based engine lives in `cybernova.correlation.rules_engine`.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.correlation.rules_engine import rules_engine, CorrelationRule

log = logging.getLogger("cybernova.correlation")


async def evaluate_correlation(db: AsyncSession, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Evaluate a single alert against all active correlation rules (dispatches to rules_engine)."""
    from cybernova.detection.correlation_engine.correlation_service import correlation_service
    tenant_id = alert.get("tenant_id", "default")
    incidents = await correlation_service.correlate_alerts([alert], tenant_id)
    if incidents:
        return {
            "incident_type": "correlated",
            "title": incidents[0].title,
            "severity": incidents[0].severity,
            "summary": incidents[0].description or "",
        }
    return None


__all__ = ["rules_engine", "CorrelationRule", "evaluate_correlation"]
