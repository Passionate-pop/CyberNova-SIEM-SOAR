"""
CyberNova — Correlation Memory Bounds
Enforces TTL + size limits on entity tracking to prevent memory leaks.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict

import redis.asyncio as aioredis

from cybernova.correlation.entity_tracker import ENTITY_TRACKER_PREFIX, EntityTracker

log = logging.getLogger("cybernova.correlation.memory")

MAX_ENTITIES = 50_000
MAX_EVENTS_PER_ENTITY = 1_000
ENTITY_TTL_HOURS = 24
CLEANUP_INTERVAL = 300


class MemoryBoundedEntityTracker(EntityTracker):
    """
    EntityTracker with enforced memory bounds:
    - Max events per entity
    - Max total entities
    - TTL-based eviction
    - Periodic cleanup
    """

    def __init__(self, redis: aioredis.Redis) -> None:
        super().__init__(redis)
        self.ttl_seconds = ENTITY_TTL_HOURS * 3600
        self._max_per_entity = MAX_EVENTS_PER_ENTITY
        self._running = False
        self._cleanup_task: asyncio.Task[None] | None = None

    async def start_cleanup(self) -> None:
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("Entity tracker cleanup started (max_entities=%d, max_per_entity=%d)", MAX_ENTITIES, MAX_EVENTS_PER_ENTITY)

    async def stop_cleanup(self) -> None:
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def track_alert(
        self,
        alert: Dict[str, Any],
        entity_field: str = "source_ip",
    ) -> None:
        entity_value = alert.get(entity_field) or alert.get("raw_event", {}).get(entity_field, "")
        if not entity_value:
            return

        key = self._key(entity_field, entity_value)

        current_count = await self.redis.zcard(key)
        if current_count >= self._max_per_entity:
            await self._trim_entity(key)
        else:
            await self._check_entity_limit()

        await super().track_alert(alert, entity_field)

    async def _trim_entity(self, key: str) -> None:
        """Remove oldest events when entity exceeds max events."""
        count = await self.redis.zcard(key)
        remove_count = count - self._max_per_entity + 100
        if remove_count > 0:
            await self.redis.zremrangebyrank(key, 0, remove_count - 1)
            log.debug("Trimmed %d events from %s", remove_count, key)

    async def _check_entity_limit(self) -> None:
        """Check total entity count and evict oldest if over limit."""
        pattern = f"{ENTITY_TRACKER_PREFIX}:*"
        entity_count = 0

        async for key in self.redis.scan_iter(match=pattern, count=1000):
            entity_count += 1

        if entity_count >= MAX_ENTITIES:
            oldest_key = None
            oldest_score = float("inf")

            async for key in self.redis.scan_iter(match=pattern, count=100):
                try:
                    oldest = await self.redis.zrange(key, 0, 0, withscores=True)
                    if oldest:
                        score = oldest[0][1]
                        if score < oldest_score:
                            oldest_score = score
                            oldest_key = key
                except (aioredis.ResponseError, TypeError) as e:
                    log.warning("Redis zrange error: %s", e)

            if oldest_key:
                await self.redis.delete(oldest_key)
                log.warning("Evicted oldest entity %s (limit=%d reached)", oldest_key, MAX_ENTITIES)

    async def _cleanup_loop(self) -> None:
        """Periodic cleanup of expired entities."""
        while self._running:
            try:
                removed = await self.cleanup_old_entries()
                if removed > 0:
                    log.info("Cleanup removed %d expired entries", removed)

                evicted = await self._evict_orphaned()
                if evicted > 0:
                    log.info("Evicted %d orphaned entity keys", evicted)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Cleanup error: %s", exc)

            await asyncio.sleep(CLEANUP_INTERVAL)

    async def _evict_orphaned(self) -> int:
        """Remove entity keys with no recent events."""
        pattern = f"{ENTITY_TRACKER_PREFIX}:*"
        cutoff = datetime.now(timezone.utc).timestamp() - (ENTITY_TTL_HOURS * 3600)
        evicted = 0

        async for key in self.redis.scan_iter(match=pattern, count=500):
            try:
                count = await self.redis.zcount(key, "-inf", cutoff)
                if count > 0:
                    total = await self.redis.zcard(key)
                    if count == total:
                        await self.redis.delete(key)
                        evicted += 1
            except (aioredis.ResponseError, TypeError) as e:
                log.warning("Redis evict scan/delete error: %s", e)

        return evicted

    async def get_stats(self) -> Dict[str, Any]:
        """Return memory statistics for entity tracking."""
        pattern = f"{ENTITY_TRACKER_PREFIX}:*"
        total_entities = 0
        total_events = 0
        field_counts: Dict[str, int] = {}

        async for key in self.redis.scan_iter(match=pattern, count=1000):
            try:
                count = await self.redis.zcard(key)
                total_entities += 1
                total_events += count

                parts = key.split(":")
                if len(parts) >= 3:
                    field = parts[2]
                    field_counts[field] = field_counts.get(field, 0) + 1
            except (aioredis.ResponseError, TypeError) as e:
                log.warning("Redis stats scan error: %s", e)

        return {
            "total_entities": total_entities,
            "total_events": total_events,
            "max_entities": MAX_ENTITIES,
            "max_per_entity": MAX_EVENTS_PER_ENTITY,
            "utilization_pct": round(total_entities / MAX_ENTITIES * 100, 2) if MAX_ENTITIES > 0 else 0,
            "by_field": field_counts,
            "ttl_hours": ENTITY_TTL_HOURS,
        }
