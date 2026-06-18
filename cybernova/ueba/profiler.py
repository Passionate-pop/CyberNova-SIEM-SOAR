from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.ueba.features import (
    compute_anomaly_score, update_baseline,
)
from cybernova.ueba.models import (
    BehavioralBaseline, BehavioralEvent, EntityType, RiskLevel, UEBAAlert, profile_store,
)

log = logging.getLogger("cybernova.ueba.profiler")


class UEBAProfiler:
    def __init__(self):
        self._alerts: Dict[str, List[UEBAAlert]] = {}
        self._event_history: Dict[str, List[BehavioralEvent]] = {}

    def process_event(self, event: BehavioralEvent) -> Optional[UEBAAlert]:
        profile = profile_store.get_or_create(
            event.entity_id, event.entity_type, event.tenant_id,
        )
        profile.last_seen = event.timestamp or datetime.now(timezone.utc).isoformat()
        profile.total_events += 1

        anomalies = []
        max_anomaly_score = 0.0

        for key, value in event.features.items():
            if key in profile.baselines:
                baseline = profile.baselines[key]
            else:
                baseline = BehavioralBaseline()
                profile.baselines[key] = baseline

            baseline = update_baseline(baseline, value)
            profile.baselines[key] = baseline

            result = compute_anomaly_score(value, baseline)
            if result["is_anomaly"]:
                anomalies.append({
                    "feature": key,
                    "value": value,
                    "z_score": result["z_score"],
                    "severity": result["severity"],
                    "mean": baseline.mean,
                    "std": baseline.std,
                })
                score_val = abs(value - baseline.mean) / max(baseline.std, 0.001)
                max_anomaly_score = max(max_anomaly_score, min(score_val / 5, 1.0))

        event.is_anomaly = len(anomalies) > 0
        event.anomaly_reasons = [a["feature"] for a in anomalies]
        event.risk_score = max_anomaly_score

        profile.current_risk_score = max(profile.current_risk_score * 0.9, max_anomaly_score)
        profile.max_risk_score = max(profile.max_risk_score, max_anomaly_score)

        if profile.current_risk_score > 0.3:
            profile.anomaly_count += 1

        if profile.current_risk_score >= 0.8:
            profile.risk_level = RiskLevel.CRITICAL
        elif profile.current_risk_score >= 0.6:
            profile.risk_level = RiskLevel.HIGH
        elif profile.current_risk_score >= 0.3:
            profile.risk_level = RiskLevel.MEDIUM
        else:
            profile.risk_level = RiskLevel.LOW

        if event.entity_id not in self._event_history:
            self._event_history[event.entity_id] = []
        self._event_history[event.entity_id].append(event)
        if len(self._event_history[event.entity_id]) > 1000:
            self._event_history[event.entity_id] = self._event_history[event.entity_id][-1000:]

        profile.feature_history.append(event.features)
        if len(profile.feature_history) > 100:
            profile.feature_history = profile.feature_history[-100:]

        profile_store.save_profile(profile)

        if anomalies:
            severity = anomalies[0]["severity"]
            alert = UEBAAlert(
                id=f"ueba_{event.entity_id}_{len(self._alerts.get(event.tenant_id, [])) + 1}",
                entity_id=event.entity_id,
                entity_type=event.entity_type,
                tenant_id=event.tenant_id,
                alert_type="behavioral_anomaly",
                severity=severity,
                score=round(max_anomaly_score, 3),
                message=f"Behavioral anomaly: {len(anomalies)} anomalous features for {event.entity_type.value} '{event.entity_id}'",
                features={"anomalies": anomalies, "event_type": event.event_type},
                detected_at=datetime.now(timezone.utc).isoformat(),
            )

            if event.tenant_id not in self._alerts:
                self._alerts[event.tenant_id] = []
            self._alerts[event.tenant_id].append(alert)
            if len(self._alerts[event.tenant_id]) > 1000:
                self._alerts[event.tenant_id] = self._alerts[event.tenant_id][-1000:]

            log.warning("UEBA alert: %s", alert.message)
            return alert

        return None

    def get_alerts(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        alerts = self._alerts.get(tenant_id, [])[-limit:]
        return [
            {
                "id": a.id,
                "entity_id": a.entity_id,
                "entity_type": a.entity_type.value,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "score": a.score,
                "message": a.message,
                "detected_at": a.detected_at,
                "acknowledged": a.acknowledged,
            }
            for a in reversed(alerts)
        ]

    def get_entity_timeline(self, entity_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        events = self._event_history.get(entity_id, [])[-limit:]
        return [
            {
                "event_type": e.event_type,
                "features": e.features,
                "risk_score": e.risk_score,
                "is_anomaly": e.is_anomaly,
                "anomaly_reasons": e.anomaly_reasons,
                "timestamp": e.timestamp,
            }
            for e in reversed(events)
        ]

    def get_stats(self, tenant_id: str) -> Dict[str, Any]:
        profiles = profile_store.list_profiles(tenant_id=tenant_id)
        alerts = self._alerts.get(tenant_id, [])
        critical = sum(1 for p in profiles if p.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for p in profiles if p.risk_level == RiskLevel.HIGH)
        return {
            "total_profiles": len(profiles),
            "total_alerts": len(alerts),
            "profiles_by_type": {
                et.value: sum(1 for p in profiles if p.entity_type == et)
                for et in EntityType
            },
            "risk_distribution": {
                "critical": critical,
                "high": high,
                "medium": sum(1 for p in profiles if p.risk_level == RiskLevel.MEDIUM),
                "low": sum(1 for p in profiles if p.risk_level == RiskLevel.LOW),
            },
            "avg_risk_score": round(
                sum(p.current_risk_score for p in profiles) / max(len(profiles), 1), 3
            ),
        }


ueba_profiler = UEBAProfiler()
