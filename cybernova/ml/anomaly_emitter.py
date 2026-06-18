from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Alert

log = logging.getLogger("cybernova.ml.anomaly_emitter")

ML_ANOMALY_RULE_NAME = "ml_anomaly_detection"
ML_ANOMALY_SEVERITY = "high"
ML_ANOMALY_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


async def emit_anomaly_alert(
    db: AsyncSession,
    tenant_id: str,
    event_data: Dict[str, Any],
    ml_result: Dict[str, Any],
) -> Optional[str]:
    """Persist an Alert record when the ML model detects an anomaly.

    Returns the alert ID if created, None if the anomaly is below threshold
    or the model version indicates an outdated model.
    """
    if not ml_result.get("is_anomaly"):
        return None

    anomaly_score = ml_result.get("anomaly_score", 0.0)
    confidence = ml_result.get("confidence", 0.0)

    extra_data = event_data.get("extra_data", {}) or {}
    normalized = event_data if event_data.get("event_type") else {}

    risk_score = round(min(100.0, anomaly_score * 100), 1)

    if anomaly_score >= 0.85:
        severity = "critical"
    elif anomaly_score >= 0.75:
        severity = "high"
    elif anomaly_score >= 0.65:
        severity = "medium"
    else:
        severity = "low"

    top_features = ml_result.get("contributing_features", [])
    feature_desc = "; ".join(
        f"{f['feature']}={f['value']}" for f in top_features[:3]
    ) if top_features else "no contributing features"

    alert = Alert(
        id=str(uuid4()),
        tenant_id=tenant_id,
        event_id=event_data.get("id") or extra_data.get("event_id"),
        device_id=extra_data.get("device_id") or normalized.get("device_id"),
        rule_name=ML_ANOMALY_RULE_NAME,
        severity=severity,
        risk_score=risk_score,
        description=(
            f"ML model anomaly score {anomaly_score:.3f} "
            f"(confidence={confidence:.3f}, version={ml_result.get('model_version', '?')}) "
            f"| {feature_desc}"
        ),
        status="new",
        source_ip=extra_data.get("source_ip") or normalized.get("source_ip", ""),
        dest_ip=extra_data.get("dest_ip") or normalized.get("dest_ip", ""),
        user=extra_data.get("user") or normalized.get("user", ""),
        event_type=normalized.get("event_type", extra_data.get("event_type", "unknown")),
        extra_data={
            "ml_anomaly_score": anomaly_score,
            "ml_confidence": confidence,
            "ml_model_version": ml_result.get("model_version"),
            "contributing_features": top_features,
            "features_used": ml_result.get("features_used", {}),
        },
        created_at=datetime.now(timezone.utc),
    )

    db.add(alert)
    await db.commit()
    log.info(
        "ML anomaly alert %s for tenant %s (score=%.3f, severity=%s)",
        alert.id, tenant_id, anomaly_score, severity,
    )
    return alert.id