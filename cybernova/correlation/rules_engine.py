"""
CyberNova — Correlation Rules Engine
Sequence-based attack chain detection with sliding window matching.
Rules are stored in DB and hot-reloadable at runtime.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import redis.asyncio as aioredis
from sqlalchemy import text

from cybernova.core.utils.helpers import utcnow

log = logging.getLogger("cybernova.correlation.rules_engine")

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "id": "brute_force_success",
        "name": "Brute Force → Successful Login",
        "description": "Failed logins followed by successful login indicates compromised credentials",
        "sequence": ["failed_login", "failed_login", "failed_login", "successful_login"],
        "entity_field": "source_ip",
        "window_seconds": 300,
        "severity": "critical",
        "enabled": True,
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege Escalation Chain",
        "description": "User login followed by admin/privilege activity",
        "sequence": ["successful_login", "privilege_escalation"],
        "entity_field": "user",
        "window_seconds": 600,
        "severity": "high",
        "enabled": True,
    },
    {
        "id": "port_scan_then_exploit",
        "name": "Port Scan → Exploitation Attempt",
        "description": "Port scan followed by exploitation attempt from same source",
        "sequence": ["port_scan", "exploitation_attempt"],
        "entity_field": "source_ip",
        "window_seconds": 120,
        "severity": "high",
        "enabled": True,
    },
    {
        "id": "data_exfiltration",
        "name": "Data Exfiltration Pattern",
        "description": "Large outbound transfer after successful login",
        "sequence": ["successful_login", "large_outbound_transfer"],
        "entity_field": "source_ip",
        "window_seconds": 3600,
        "severity": "critical",
        "enabled": True,
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement Detection",
        "description": "Multiple successful logins to different hosts from same source",
        "sequence": ["successful_login", "successful_login"],
        "entity_field": "source_ip",
        "window_seconds": 300,
        "severity": "high",
        "enabled": True,
    },
    {
        "id": "malware_c2",
        "name": "Malware C2 Communication",
        "description": "Malware detection followed by suspicious network activity",
        "sequence": ["malware_detected", "suspicious_outbound"],
        "entity_field": "source_ip",
        "window_seconds": 600,
        "severity": "critical",
        "enabled": True,
    },
    {
        "id": "credential_theft",
        "name": "Credential Theft Followed by Exploitation",
        "description": "Credential access followed by remote exploitation",
        "sequence": ["credential_access", "remote_exploitation"],
        "entity_field": "source_ip",
        "window_seconds": 900,
        "severity": "critical",
        "enabled": True,
    },
]


@dataclass
class CorrelationRule:
    id: str
    name: str
    description: str
    sequence: List[str]
    entity_field: str
    window_seconds: int
    severity: str
    enabled: bool
    tenant_id: str
    created_at: datetime = field(default_factory=utcnow)

    @classmethod
    def from_dict(cls, d: Dict[str, Any], tenant_id: str = "default") -> "CorrelationRule":
        return cls(
            id=d.get("id", str(uuid4())),
            name=d.get("name", ""),
            description=d.get("description", ""),
            sequence=d.get("sequence", []),
            entity_field=d.get("entity_field", "source_ip"),
            window_seconds=d.get("window_seconds", 300),
            severity=d.get("severity", "medium"),
            enabled=d.get("enabled", True),
            tenant_id=tenant_id or d.get("tenant_id", "default"),
            created_at=d.get("created_at", utcnow()),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "sequence": self.sequence,
            "entity_field": self.entity_field,
            "window_seconds": self.window_seconds,
            "severity": self.severity,
            "enabled": self.enabled,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
        }


class CorrelationRulesEngine:
    def __init__(self, redis: Optional[aioredis.Redis] = None) -> None:
        self.redis = redis
        self._rules: Dict[str, List[CorrelationRule]] = {}
        self._lock = asyncio.Lock()
        self._redis_cache_ttl = 3600

    def _cache_key(self, tenant_id: str) -> str:
        return f"cybernova:correlation_rules:{tenant_id}"

    async def _cache_get(self, tenant_id: str) -> Optional[List[CorrelationRule]]:
        if not self.redis:
            return None
        try:
            data = await self.redis.get(self._cache_key(tenant_id))
            if data:
                raw = json.loads(data)
                return [CorrelationRule.from_dict(r, tenant_id) for r in raw]
        except Exception as e:
            log.warning("Redis cache read error for rules %s: %s", tenant_id, e)
        return None

    async def _cache_set(self, tenant_id: str, rules: List[CorrelationRule]) -> None:
        if not self.redis:
            return
        try:
            raw = [r.to_dict() for r in rules]
            await self.redis.setex(self._cache_key(tenant_id), self._redis_cache_ttl, json.dumps(raw, default=str))
        except Exception as e:
            log.warning("Redis cache write error for rules %s: %s", tenant_id, e)

    async def _cache_del(self, tenant_id: str) -> None:
        if not self.redis:
            return
        try:
            await self.redis.delete(self._cache_key(tenant_id))
        except Exception as e:
            log.warning("Redis cache delete error for %s: %s", tenant_id, e)

    async def load_rules(self, tenant_id: str = "default") -> List[CorrelationRule]:
        async with self._lock:
            if tenant_id in self._rules:
                return self._rules[tenant_id]

            cached = await self._cache_get(tenant_id)
            if cached is not None:
                self._rules[tenant_id] = cached
                return cached

            rules = await self._load_from_db(tenant_id)
            if not rules:
                rules = [CorrelationRule.from_dict(r, tenant_id) for r in DEFAULT_RULES]
                await self._save_to_db(rules, tenant_id)
                log.info("Seeded %d correlation rules for tenant %s", len(rules), tenant_id)

            self._rules[tenant_id] = rules
            await self._cache_set(tenant_id, rules)
            return rules

    async def _load_from_db(self, tenant_id: str) -> List[CorrelationRule]:
        try:
            from cybernova.database.postgres.session import get_db_session
            async for db in get_db_session():
                # Try loading from the `data` JSON column first
                result = await db.execute(
                    text("SELECT data FROM correlation_rules WHERE tenant_id = :tid AND enabled = true"),
                    {"tid": tenant_id}
                )
                rows = result.fetchall()
                if rows:
                    rules = []
                    for r in rows:
                        raw_data = r[0]
                        if raw_data is not None:
                            # data column is populated — parse it
                            rules.append(CorrelationRule.from_dict(json.loads(raw_data), tenant_id))
                        else:
                            # data column is NULL — fall back entirely to individual columns
                            # to avoid duplicates from partially parsed data-column rows
                            rules = await self._load_from_individual_columns(db, tenant_id)
                            break
                    return rules
                return []
        except Exception as exc:
            log.warning("Could not load correlation rules from DB: %s", exc)
            return []

    async def _load_from_individual_columns(self, db, tenant_id: str) -> List[CorrelationRule]:
        """Fallback: load rules from individual columns when the `data` JSON column is NULL."""
        try:
            result = await db.execute(
                text("""
                    SELECT id, name, description, sequence, entity_field,
                           window_seconds, severity, enabled, tenant_id, created_at
                    FROM correlation_rules
                    WHERE tenant_id = :tid AND enabled = true
                """),
                {"tid": tenant_id}
            )
            rows = result.fetchall()
            rules = []
            for r in rows:
                rule_dict = {
                    "id": r[0],
                    "name": r[1],
                    "description": r[2],
                    "sequence": json.loads(r[3]) if isinstance(r[3], str) else (r[3] or []),
                    "entity_field": r[4],
                    "window_seconds": r[5],
                    "severity": r[6],
                    "enabled": r[7],
                    "tenant_id": r[8],
                    "created_at": r[9],
                }
                rules.append(CorrelationRule.from_dict(rule_dict, tenant_id))
            return rules
        except Exception as exc:
            log.warning("Could not load correlation rules from individual columns: %s", exc)
            return []

    async def _save_to_db(self, rules: List[CorrelationRule], tenant_id: str) -> None:
        try:
            from cybernova.database.postgres.session import get_db_session
            async for db in get_db_session():
                for rule in rules:
                    rule_data = json.dumps(rule.to_dict())
                    await db.execute(
                        text("""
                            INSERT INTO correlation_rules (id, name, description, sequence, entity_field, window_seconds, severity, enabled, tenant_id, created_at, data)
                            VALUES (:id, :name, :desc, :seq, :ef, :win, :sev, :en, :tid, :ca, :data)
                            ON CONFLICT (id) DO NOTHING
                        """),
                        {
                            "id": rule.id,
                            "name": rule.name,
                            "desc": rule.description,
                            "seq": json.dumps(rule.sequence),
                            "ef": rule.entity_field,
                            "win": rule.window_seconds,
                            "sev": rule.severity,
                            "en": rule.enabled,
                            "tid": rule.tenant_id,
                            "ca": rule.created_at,
                            "data": rule_data,
                        }
                    )
                await db.commit()
        except Exception as exc:
            log.warning("Could not save correlation rules to DB: %s", exc)

    async def add_rule(self, rule: CorrelationRule) -> None:
        async with self._lock:
            tenant = rule.tenant_id
            if tenant not in self._rules:
                self._rules[tenant] = []
            existing = [r for r in self._rules[tenant] if r.id == rule.id]
            if existing:
                self._rules[tenant] = [r if r.id != rule.id else rule for r in self._rules[tenant]]
            else:
                self._rules[tenant].append(rule)
            await self._cache_del(tenant)

    async def disable_rule(self, rule_id: str, tenant_id: str) -> None:
        async with self._lock:
            if tenant_id in self._rules:
                for rule in self._rules[tenant_id]:
                    if rule.id == rule_id:
                        rule.enabled = False
                await self._cache_del(tenant_id)

    async def enable_rule(self, rule_id: str, tenant_id: str) -> None:
        async with self._lock:
            if tenant_id in self._rules:
                for rule in self._rules[tenant_id]:
                    if rule.id == rule_id:
                        rule.enabled = True
                await self._cache_del(tenant_id)

    async def match_sequence(
        self,
        alerts: List[Dict[str, Any]],
        rule: CorrelationRule,
    ) -> Tuple[bool, float]:
        if len(alerts) < len(rule.sequence):
            return False, 0.0

        entity_field = rule.entity_field
        entity_values = set()
        for alert in alerts:
            val = alert.get(entity_field) or alert.get("raw_event", {}).get(entity_field, "")
            if val:
                entity_values.add(val)

        matched_entities = 0
        total_entities = len(entity_values) if entity_values else 1

        for entity_value in entity_values:
            entity_alerts = [
                a for a in alerts
                if (a.get(entity_field) or a.get("raw_event", {}).get(entity_field, "")) == entity_value
            ]
            entity_alerts.sort(key=lambda a: a.get("created_at", ""))

            window_start = alerts[-1].get("created_at", "")
            try:
                latest_time = datetime.fromisoformat(window_start.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                log.warning("Invalid timestamp format in alert: %s", window_start)
                latest_time = utcnow()
            cutoff = datetime.fromtimestamp(latest_time.timestamp() - rule.window_seconds, tz=timezone.utc)

            windowed_alerts = [
                a for a in entity_alerts
                if a.get("created_at", "") and self._within_window(a.get("created_at", ""), cutoff)
            ]

            if self._matches_sequence(windowed_alerts, rule.sequence, entity_field):
                matched_entities += 1

        confidence = matched_entities / total_entities if total_entities > 0 else 0.0
        return matched_entities > 0, confidence

    def _within_window(self, timestamp_str: str, cutoff: datetime) -> bool:
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return ts >= cutoff
        except (ValueError, TypeError):
            log.warning("Invalid timestamp in _within_window: %s", timestamp_str)
            return True

    def _matches_sequence(
        self,
        alerts: List[Dict[str, Any]],
        sequence: List[str],
        entity_field: str,
    ) -> bool:
        if len(sequence) > len(alerts):
            log.debug("_matches_sequence: not enough alerts (%d < %d)", len(alerts), len(sequence))
            return False

        log.debug("_matches_sequence: matching sequence=%s for %d alerts", sequence, len(alerts))
        seq_idx = 0
        for alert in alerts:
            event_type = self._normalize_event_type(alert, entity_field)
            log.debug("_matches_sequence: alert id=%s normalized_type=%s, looking for seq[%d]=%s", 
                alert.get("id"), event_type, seq_idx, sequence[seq_idx] if seq_idx < len(sequence) else "N/A")
            if seq_idx < len(sequence) and self._type_matches(event_type, sequence[seq_idx]):
                log.debug("_matches_sequence: MATCHED seq[%d]=%s", seq_idx, sequence[seq_idx])
                seq_idx += 1
                if seq_idx == len(sequence):
                    log.debug("_matches_sequence: FULL SEQUENCE MATCHED!")
                    return True

        log.debug("_matches_sequence: no match, final seq_idx=%d", seq_idx)
        return False

    def _normalize_event_type(self, alert: Dict[str, Any], entity_field: str) -> str:
        rule_name = alert.get("rule_name", "").lower()
        event_type = alert.get("event_type", "").lower()
        raw_event = alert.get("raw_event", {})
        message = (raw_event.get("message", "") or alert.get("description", "")).lower()
        
        log.debug("_normalize: rule_name=%s event_type=%s message=%s", rule_name, event_type, message[:50])

        if "failed_login" in rule_name or "failed_login" in event_type or "failed" in message and "login" in message:
            return "failed_login"
        if "successful_login" in rule_name or "successful_login" in event_type or "login success" in message:
            return "successful_login"
        if "port_scan" in rule_name or "port_scan" in event_type or "scan" in message:
            return "port_scan"
        if "exploit" in rule_name or "exploit" in event_type or "exploitation" in message:
            return "exploitation_attempt"
        if "privilege" in rule_name or "escalat" in message or "admin" in message:
            return "privilege_escalation"
        if "malware" in rule_name or "malware" in event_type or "malware" in message:
            return "malware_detected"
        if "exfil" in rule_name or "exfil" in message or ("outbound" in message and "large" in message):
            return "large_outbound_transfer"
        if "credential" in rule_name or "credential" in event_type:
            return "credential_access"
        if "c2" in rule_name or "command" in message and "control" in message:
            return "suspicious_outbound"
        if "remote" in message and "exploit" in message:
            return "remote_exploitation"
        return event_type or rule_name or "unknown"

    def _type_matches(self, actual: str, expected: str) -> bool:
        actual = actual.lower().strip()
        expected = expected.lower().strip()
        if actual == expected:
            return True
        if expected in actual or actual in expected:
            return True
        if expected == "exploitation_attempt" and "exploit" in actual:
            return True
        if expected == "large_outbound_transfer" and ("exfil" in actual or ("outbound" in actual and "large" in actual)):
            return True
        return False


rules_engine = CorrelationRulesEngine()
