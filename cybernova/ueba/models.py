from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("cybernova.ueba.models")


class EntityType(str, Enum):
    USER = "user"
    DEVICE = "device"
    IP = "ip"
    SERVICE = "service"
    APPLICATION = "application"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehavioralBaseline:
    mean: float = 0.0
    std: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    sample_count: int = 0
    last_updated: str = ""


@dataclass
class EntityProfile:
    entity_id: str
    entity_type: EntityType
    tenant_id: str
    first_seen: str = ""
    last_seen: str = ""
    baselines: Dict[str, BehavioralBaseline] = field(default_factory=dict)
    features: Dict[str, float] = field(default_factory=dict)
    feature_history: List[Dict[str, float]] = field(default_factory=list)
    current_risk_score: float = 0.0
    max_risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    anomaly_count: int = 0
    total_events: int = 0
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def age_days(self) -> float:
        if not self.first_seen:
            return 0.0
        try:
            first = datetime.fromisoformat(self.first_seen)
            return (datetime.now(timezone.utc) - first).total_seconds() / 86400
        except (ValueError, TypeError):
            return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "tenant_id": self.tenant_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "baselines": {k: {"mean": b.mean, "std": b.std, "min_val": b.min_val, "max_val": b.max_val, "sample_count": b.sample_count, "last_updated": b.last_updated} for k, b in self.baselines.items()},
            "features": self.features,
            "feature_history": self.feature_history[-100:],
            "current_risk_score": self.current_risk_score,
            "max_risk_score": self.max_risk_score,
            "risk_level": self.risk_level.value,
            "anomaly_count": self.anomaly_count,
            "total_events": self.total_events,
            "tags": list(self.tags),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EntityProfile":
        baselines = {}
        for k, b in d.get("baselines", {}).items():
            baselines[k] = BehavioralBaseline(**b)
        return cls(
            entity_id=d["entity_id"],
            entity_type=EntityType(d["entity_type"]),
            tenant_id=d["tenant_id"],
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            baselines=baselines,
            features=d.get("features", {}),
            feature_history=d.get("feature_history", []),
            current_risk_score=d.get("current_risk_score", 0.0),
            max_risk_score=d.get("max_risk_score", 0.0),
            risk_level=RiskLevel(d.get("risk_level", "low")),
            anomaly_count=d.get("anomaly_count", 0),
            total_events=d.get("total_events", 0),
            tags=set(d.get("tags", [])),
            metadata=d.get("metadata", {}),
        )


@dataclass
class BehavioralEvent:
    entity_id: str
    entity_type: EntityType
    tenant_id: str
    event_type: str
    features: Dict[str, float]
    timestamp: str = ""
    source_ip: str = ""
    risk_score: float = 0.0
    is_anomaly: bool = False
    anomaly_reasons: List[str] = field(default_factory=list)


@dataclass
class UEBAAlert:
    id: str
    entity_id: str
    entity_type: EntityType
    tenant_id: str
    alert_type: str
    severity: str
    score: float
    message: str
    features: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = ""
    acknowledged: bool = False


def _get_sync_redis():
    """Create sync Redis client with connection verification.

    Returns a connected Redis client or None if Redis is unavailable.
    The health-check ping ensures we fail fast rather than hanging on
    the first real operation (e.g. during tests or degraded startup).
    """
    try:
        import redis as sync_redis
        from cybernova.config.settings import get_settings
        s = get_settings()
        url = s.resolved_redis_url
        client = sync_redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
        # Verify the connection is actually live — avoid hanging later
        # Using a short ping with a tiny timeout to fail fast when Redis is unavailable
        client.ping()
        return client
    except Exception:
        return None


PROFILE_TTL = 86400
MAX_HISTORY = 50


class UEBAProfileStore:
    def __init__(self):
        self._profiles: Dict[str, EntityProfile] = {}
        self._redis = _get_sync_redis()

    def _profile_key(self, entity_id: str, entity_type: EntityType, tenant_id: str) -> str:
        return f"ueba:profile:{tenant_id}:{entity_type.value}:{entity_id}"

    def _get_redis_profile(self, entity_id: str, entity_type: EntityType, tenant_id: str) -> Optional[EntityProfile]:
        if not self._redis:
            return None
        try:
            key = self._profile_key(entity_id, entity_type, tenant_id)
            data = self._redis.get(key)
            if data:
                return EntityProfile.from_dict(json.loads(data))
        except Exception as e:
            log.warning("Redis profile read error: %s", e)
        return None

    def _set_redis_profile(self, profile: EntityProfile) -> None:
        if not self._redis:
            return
        try:
            key = self._profile_key(profile.entity_id, profile.entity_type, profile.tenant_id)
            self._redis.setex(key, PROFILE_TTL, json.dumps(profile.to_dict(), default=str))
        except Exception as e:
            log.warning("Redis profile write error: %s", e)

    def _del_redis_profile(self, entity_id: str, entity_type: EntityType, tenant_id: str) -> None:
        if not self._redis:
            return
        try:
            key = self._profile_key(entity_id, entity_type, tenant_id)
            self._redis.delete(key)
        except Exception as e:
            log.warning("Redis profile delete error: %s", e)

    def get_profile(self, entity_id: str) -> Optional[EntityProfile]:
        return self._profiles.get(entity_id)

    def get_or_create(self, entity_id: str, entity_type: EntityType, tenant_id: str) -> EntityProfile:
        if entity_id in self._profiles:
            return self._profiles[entity_id]

        cached = self._get_redis_profile(entity_id, entity_type, tenant_id)
        if cached:
            self._profiles[entity_id] = cached
            return cached

        now = datetime.now(timezone.utc).isoformat()
        profile = EntityProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            first_seen=now,
            last_seen=now,
        )
        self._profiles[entity_id] = profile
        self._set_redis_profile(profile)
        return profile

    def save_profile(self, profile: EntityProfile) -> None:
        self._profiles[profile.entity_id] = profile
        self._set_redis_profile(profile)

    def list_profiles(self, tenant_id: Optional[str] = None, entity_type: Optional[EntityType] = None) -> List[EntityProfile]:
        profiles = list(self._profiles.values())
        if tenant_id:
            profiles = [p for p in profiles if p.tenant_id == tenant_id]
        if entity_type:
            profiles = [p for p in profiles if p.entity_type == entity_type]
        return profiles

    def delete_profile(self, entity_id: str) -> bool:
        profile = self._profiles.pop(entity_id, None)
        if profile:
            self._del_redis_profile(profile.entity_id, profile.entity_type, profile.tenant_id)
            return True
        return False


profile_store = UEBAProfileStore()
