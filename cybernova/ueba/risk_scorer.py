from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.ueba.models import (
    EntityProfile, RiskLevel, profile_store,
)


RISK_WEIGHTS = {
    "failed_logins": 0.25,
    "outside_business_hours": 0.15,
    "external_connections": 0.20,
    "high_risk_port_hits": 0.20,
    "sensitive_resource_access": 0.25,
    "denied_rate": 0.15,
    "mfa_failures": 0.30,
    "privileged_usage": 0.20,
    "unique_source_ips": 0.10,
    "unique_dest_ips": 0.10,
}


def compute_weighted_risk(features: Dict[str, float]) -> float:
    score = 0.0
    total_weight = 0.0
    for key, weight in RISK_WEIGHTS.items():
        if key in features:
            val = features[key]
            normalized = min(val / 10.0, 1.0)
            score += weight * normalized
            total_weight += weight
    return score / max(total_weight, 0.01)


def compute_temporal_risk(profile: EntityProfile) -> float:
    recency_weight = 1.0
    if profile.last_seen:
        try:
            last = datetime.fromisoformat(profile.last_seen)
            hours_ago = (datetime.now(timezone.utc) - last).total_seconds() / 3600
            recency_weight = max(0.1, 1.0 - hours_ago / 72)
        except (ValueError, TypeError):
            pass

    base = profile.current_risk_score
    anomaly_multiplier = 1.0 + min(profile.anomaly_count * 0.1, 1.0)
    volume_factor = min(math.log10(profile.total_events + 1) / 3, 1.0)
    age_factor = min(profile.age_days / 30, 1.0)

    return min(base * anomaly_multiplier * recency_weight * volume_factor * age_factor, 1.0)


def recompute_all_risks(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    profiles = profile_store.list_profiles(tenant_id=tenant_id)
    results = []

    for profile in profiles:
        temporal_risk = compute_temporal_risk(profile)
        profile.current_risk_score = temporal_risk
        profile.max_risk_score = max(profile.max_risk_score, temporal_risk)

        if temporal_risk >= 0.8:
            profile.risk_level = RiskLevel.CRITICAL
        elif temporal_risk >= 0.6:
            profile.risk_level = RiskLevel.HIGH
        elif temporal_risk >= 0.3:
            profile.risk_level = RiskLevel.MEDIUM
        else:
            profile.risk_level = RiskLevel.LOW

        results.append({
            "entity_id": profile.entity_id,
            "entity_type": profile.entity_type.value,
            "risk_score": round(temporal_risk, 3),
            "risk_level": profile.risk_level.value,
            "anomaly_count": profile.anomaly_count,
            "total_events": profile.total_events,
        })

    return sorted(results, key=lambda r: -r["risk_score"])


class UEBARiskScorer:
    """Risk scorer singleton wrapping risk computation functions."""

    @property
    def weights(self) -> Dict[str, float]:
        return dict(RISK_WEIGHTS)

    def score(self, features: Dict[str, float]) -> float:
        return compute_weighted_risk(features)

    def temporal_score(self, profile: EntityProfile) -> float:
        return compute_temporal_risk(profile)

    def recompute_all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return recompute_all_risks(tenant_id)


ueba_risk_scorer = UEBARiskScorer()
