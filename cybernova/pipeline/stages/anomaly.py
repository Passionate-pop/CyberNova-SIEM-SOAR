from __future__ import annotations

import logging
from typing import Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.detection.anomaly.detector import anomaly_detector
from cybernova.ml.inference import infer_event, MODEL_ID
from cybernova.ml.model_registry import model_registry

log = logging.getLogger("cybernova.pipeline.stage.anomaly")

MODEL_NOT_LOADED_WARNED = False


class AnomalyStage(PipelineStage):
    """ML/anomaly detection stage — scores events and adds anomaly data."""

    def __init__(self):
        super().__init__("anomaly")

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        global MODEL_NOT_LOADED_WARNED

        enriched = envelope.payload.get("enriched_data", {})
        normalized = envelope.payload.get("normalized_data", {})

        event_data = {
            "id": envelope.event_id,
            "event_type": enriched.get("event_type", normalized.get("event_type", "unknown")),
            "source_ip": enriched.get("source_ip", normalized.get("source_ip", "")),
            "severity": enriched.get("severity", normalized.get("severity", "info")),
            "user": enriched.get("user", normalized.get("user", "")),
            "message": enriched.get("message", normalized.get("message", "")),
            "extra_data": normalized.get("extra_data", {}),
            "device_id": normalized.get("device_id"),
            "dest_ip": normalized.get("dest_ip"),
        }

        # ── Statistical anomaly detection (baseline) ──
        stat_result = await anomaly_detector.score_event(envelope.tenant_id, event_data)
        if stat_result:
            envelope.payload["anomaly"] = stat_result
            current_risk = enriched.get("risk_score", 0) if enriched else 0
            anomaly_boost = stat_result.get("anomaly_score", 0) * 30
            new_risk = min(100, current_risk + anomaly_boost)
            if enriched:
                enriched["risk_score"] = new_risk
            envelope.payload["risk_score_boost"] = anomaly_boost

        # ── ML model anomaly detection (Isolation Forest) ──
        model_version = None
        ab_test_id = None
        try:
            from cybernova.database.postgres.session import get_db_session as _get_db
            async for _db in _get_db():
                model_version, ab_test_id = await model_registry.resolve_ab_for_event(
                    _db, envelope.event_id, tenant_id=envelope.tenant_id,
                )
                break
        except Exception as e:
            log.debug("A/B test resolution failed for event %s: %s", envelope.event_id, e)

        try:
            ml_result = infer_event(event_data, model_id=MODEL_ID, version=model_version)
        except Exception as e:
            ml_result = None
            if not MODEL_NOT_LOADED_WARNED:
                log.warning("ML inference unavailable (model not loaded?): %s", e)
                MODEL_NOT_LOADED_WARNED = True

        if ml_result:
            envelope.payload["ml_anomaly"] = ml_result

            # Record A/B test result if active
            if ab_test_id:
                try:
                    from cybernova.database.postgres.session import get_db_session as _get_db
                    async for _db in _get_db():
                        await model_registry.record_ab_result(
                            _db, ab_test_id, envelope.event_id,
                            model_version or ml_result.get("model_version", "?"),
                            ml_result["anomaly_score"], ml_result["is_anomaly"],
                            ml_result.get("confidence", 0.0),
                        )
                        await _db.commit()
                        break
                except Exception as e:
                    log.warning("A/B result recording failed: %s", e)

            if ml_result.get("is_anomaly"):
                ml_boost = ml_result["anomaly_score"] * 50
                current_risk = enriched.get("risk_score", 0) if enriched else 0
                new_risk = min(100, current_risk + ml_boost)
                if enriched:
                    enriched["risk_score"] = new_risk
                envelope.payload["risk_score_boost"] = (
                    envelope.payload.get("risk_score_boost", 0) + ml_boost
                )

                extra_data = normalized.get("extra_data", {}) or {}
                alert_dict = {
                    "id": envelope.event_id,
                    "tenant_id": envelope.tenant_id,
                    "event_id": envelope.event_id,
                    "device_id": extra_data.get("device_id") or normalized.get("device_id"),
                    "rule_name": "ml_anomaly_detection",
                    "severity": "high" if ml_result["anomaly_score"] >= 0.75 else "medium",
                    "risk_score": round(min(100, ml_result["anomaly_score"] * 100), 1),
                    "description": (
                        f"ML model anomaly score {ml_result['anomaly_score']:.3f} "
                        f"(version={ml_result.get('model_version', '?')})"
                    ),
                    "status": "new",
                    "source_ip": event_data.get("source_ip", ""),
                    "dest_ip": event_data.get("dest_ip", ""),
                    "user": event_data.get("user", ""),
                    "event_type": event_data.get("event_type", "unknown"),
                    "extra_data": {
                        "ml_anomaly_score": ml_result["anomaly_score"],
                        "ml_confidence": ml_result.get("confidence"),
                        "ml_model_version": ml_result.get("model_version"),
                        "contributing_features": ml_result.get("contributing_features", []),
                    },
                }

                alerts = envelope.payload.get("alerts", [])
                alerts.append(alert_dict)
                envelope.payload["alerts"] = alerts

                log.info(
                    "ML anomaly detected for event %s (score=%.3f, boost=%.1f, version=%s)",
                    envelope.event_id, ml_result["anomaly_score"], ml_boost,
                    model_version or ml_result.get("model_version", "?"),
                )

        envelope.stage = "detection"
        return envelope


anomaly_stage = AnomalyStage()

# Ensure anomaly stage is registered in the pipeline flow:
# enrichment → anomaly → detection (so ML inference actually runs)
