"""
CyberNova — Alert Deduplication
Prevents alert spam from the same source within a configurable time window.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import redis.asyncio as aioredis


log = logging.getLogger("cybernova.alert_dedup")

DEDUP_WINDOW_SECONDS = 60
DEDUP_KEY_PREFIX = "dedup:alert"


class AlertDeduplicator:
    def __init__(self, redis: Optional[aioredis.Redis] = None, window_seconds: int = DEDUP_WINDOW_SECONDS) -> None:
        self.redis = redis
        self.window_seconds = window_seconds

    def _make_key(self, alert: Dict[str, Any]) -> str:
        components = [
            alert.get("rule_name", ""),
            alert.get("source_ip", ""),
            alert.get("dest_ip", ""),
            alert.get("user", ""),
            alert.get("event_type", ""),
            alert.get("severity", ""),
        ]
        key_str = "|".join(str(c) for c in components)
        hash_val = hashlib.sha256(key_str.encode()).hexdigest()[:16]
        return f"{DEDUP_KEY_PREFIX}:{hash_val}"

    async def is_duplicate(self, alert: Dict[str, Any]) -> bool:
        if not self.redis:
            return False

        key = self._make_key(alert)
        try:
            exists = await self.redis.exists(key)
            return exists > 0
        except Exception as e:
            log.warning("Dedup Redis exists check failed: %s", e)
            return False

    async def mark_seen(self, alert: Dict[str, Any]) -> None:
        if not self.redis:
            return

        key = self._make_key(alert)
        alert_data = {
            "alert_id": alert.get("id", str(uuid4())),
            "rule_name": alert.get("rule_name", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self.redis.set(
                key,
                json.dumps(alert_data),
                ex=self.window_seconds,
            )
        except Exception as exc:
            log.warning("Failed to mark alert deduplication key: %s", exc)

    async def should_fire(self, alert: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Returns (should_fire, dedup_key).
        If duplicate within window, returns (False, key).
        """
        key = self._make_key(alert)
        if not self.redis:
            return True, None

        is_dup = await self.is_duplicate(alert)
        if is_dup:
            log.debug("Alert deduplicated: %s", key)
            return False, key

        await self.mark_seen(alert)
        return True, key

    async def get_suppressed_count(self, tenant_id: str = "default") -> int:
        if not self.redis:
            return 0
        pattern = f"{DEDUP_KEY_PREFIX}:*"
        count = 0
        async for _ in self.redis.scan_iter(match=pattern, count=1000):
            count += 1
        return count


class AlertDeduplicatorWindow:
    """Sliding window deduplication for fine-grained control."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.window_ms = DEDUP_WINDOW_SECONDS * 1000

    async def check_and_fire(
        self,
        alert: Dict[str, Any],
        tenant_id: str = "default",
    ) -> tuple[bool, int]:
        """Check if alert should fire (not suppressed). Returns (allowed, suppressed_count)."""
        key = f"dedup:window:{tenant_id}:{alert.get('rule_name', 'unknown')}:{alert.get('source_ip', 'unknown')}"
        now = datetime.now(timezone.utc).timestamp() * 1000
        window_start = now - self.window_ms

        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, self.window_ms // 1000 + 60)
        results = await pipe.execute()

        current_count = results[1]

        return current_count == 0, current_count


deduplicator = AlertDeduplicator()

# Alias for unified API access
deduplication_engine = deduplicator


async def init_deduplication(redis_client) -> None:
    """Initialize deduplicator with Redis at startup."""
    global deduplicator, deduplication_engine
    deduplicator = AlertDeduplicator(redis=redis_client)
    deduplication_engine = deduplicator
    log.info("Alert deduplicator initialized with Redis")

