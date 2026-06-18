"""
CyberNova — Entity Tracker
Tracks entities (IPs, users, hosts) over time using Redis sorted sets for fast lookups.
Enables multi-stage attack chain detection across sliding time windows.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import redis.asyncio as aioredis

log = logging.getLogger("cybernova.correlation.entity_tracker")

ENTITY_TRACKER_PREFIX = "entity_tracker"
DEFAULT_TTL_HOURS = 24


class EntityTracker:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.ttl_seconds = DEFAULT_TTL_HOURS * 3600

    def _key(self, entity_field: str, entity_value: str) -> str:
        safe_value = entity_value.replace(":", "_").replace("/", "_")
        return f"{ENTITY_TRACKER_PREFIX}:{entity_field}:{safe_value}"

    async def track_alert(
        self,
        alert: Dict[str, Any],
        entity_field: str = "source_ip",
    ) -> None:
        entity_value = alert.get(entity_field) or alert.get("raw_event", {}).get(entity_field, "")
        if not entity_value:
            return

        key = self._key(entity_field, entity_value)
        score = datetime.now(timezone.utc).timestamp()
        data = json.dumps({
            "alert_id": alert.get("id"),
            "event_type": alert.get("event_type", ""),
            "rule_name": alert.get("rule_name", ""),
            "severity": alert.get("severity", ""),
            "user": alert.get("user", ""),
            "timestamp": alert.get("created_at", datetime.now(timezone.utc).isoformat()),
            "raw": alert,
        })

        await self.redis.zadd(key, {data: score})
        await self.redis.expire(key, self.ttl_seconds)

        await self._track_reverse(entity_field, entity_value, alert)

    async def _track_reverse(self, entity_field: str, entity_value: str, alert: Dict[str, Any]) -> None:
        reverse_mappings = {
            "source_ip": "user",
            "user": "source_ip",
        }
        reverse_field = reverse_mappings.get(entity_field)
        if not reverse_field:
            return

        reverse_value = alert.get(reverse_field) or alert.get("raw_event", {}).get(reverse_field, "")
        if not reverse_value:
            return

        reverse_key = self._key(reverse_field, reverse_value)
        link_data = json.dumps({
            "linked_entity_field": entity_field,
            "linked_entity_value": entity_value,
            "alert_id": alert.get("id"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        score = datetime.now(timezone.utc).timestamp()
        await self.redis.zadd(reverse_key, {link_data: score})
        await self.redis.expire(reverse_key, self.ttl_seconds)

    async def get_entity_timeline(
        self,
        entity_field: str,
        entity_value: str,
        window_seconds: int = 3600,
    ) -> List[Dict[str, Any]]:
        key = self._key(entity_field, entity_value)
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds

        try:
            results = await self.redis.zrangebyscore(key, cutoff, "+inf", withscores=True)
        except Exception as exc:
            log.error("Entity timeline error: %s", exc)
            return []

        alerts = []
        for data_str, score in results:
            try:
                alert = json.loads(data_str)
                alert["_score"] = score
                alerts.append(alert)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning("Failed to parse Redis alert data: %s", e)

        alerts.sort(key=lambda a: a.get("_score", 0))
        return alerts

    async def get_related_entities(
        self,
        entity_field: str,
        entity_value: str,
    ) -> Dict[str, List[str]]:
        reverse_mappings = {
            "source_ip": "user",
            "user": "source_ip",
        }
        reverse_field = reverse_mappings.get(entity_field)
        if not reverse_field:
            return {}

        key = self._key(entity_field, entity_value)
        try:
            results = await self.redis.zrange(key, 0, -1)
        except aioredis.ResponseError as e:
            log.warning("Redis zrange error for key %s: %s", key, e)
            return {}

        related: Dict[str, List[str]] = {}
        for data_str in results:
            try:
                data = json.loads(data_str)
                rf = data.get("linked_entity_field", "")
                rv = data.get("linked_entity_value", "")
                if rf and rv:
                    if rf not in related:
                        related[rf] = []
                    if rv not in related[rf]:
                        related[rf].append(rv)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning("Failed to parse related entity data: %s", e)

        return related

    async def get_entity_count(self, entity_field: str, window_seconds: int = 3600) -> int:
        pattern = f"{ENTITY_TRACKER_PREFIX}:{entity_field}:*"
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        count = 0

        async for key in self.redis.scan_iter(match=pattern):
            try:
                count += await self.redis.zcount(key, cutoff, "+inf")
            except (aioredis.ResponseError, TypeError) as e:
                log.warning("Redis zcount error: %s", e)

        return count

    async def cleanup_old_entries(self) -> int:
        cutoff = datetime.now(timezone.utc).timestamp() - self.ttl_seconds
        pattern = f"{ENTITY_TRACKER_PREFIX}:*"
        removed = 0

        async for key in self.redis.scan_iter(match=pattern):
            try:
                removed += await self.redis.zremrangebyscore(key, "-inf", cutoff)
            except (aioredis.ResponseError, TypeError) as e:
                log.warning("Redis zremrangebyscore error: %s", e)

        return removed
