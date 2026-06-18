"""
CyberNova — Event Bus: Producer
Publishes events to Redis Streams (or bounded in-memory fallback).
Bounded fallback with max size, retry drain, and no unbounded growth.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.event_bus.producer")

MAX_FALLBACK_SIZE = 5000


class EventProducer:
    """Publishes events to Redis Streams with idempotency protection."""

    def __init__(self, stream_prefix: str = "cybernova") -> None:
        self.stream_prefix = stream_prefix
        self._fallback: list = []
        self._fallback_lock = asyncio.Lock()
        self._drain_task: Optional[asyncio.Task] = None

    def _stream_key(self, topic: str) -> str:
        return f"{self.stream_prefix}:{topic}"

    async def publish(
        self,
        topic: str,
        data: Dict[str, Any],
        tenant_id: str,
        event_id: Optional[str] = None,
        max_len: int = 100_000,
    ) -> str:
        event_id = event_id or str(uuid4())
        envelope = {
            "event_id": event_id,
            "topic": topic,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

        redis = await get_redis()
        stream_key = self._stream_key(topic)

        if not redis:
            async with self._fallback_lock:
                if len(self._fallback) >= MAX_FALLBACK_SIZE:
                    log.error("Event bus fallback full (%d) — dropping event %s",
                              MAX_FALLBACK_SIZE, event_id)
                else:
                    self._fallback.append(envelope)
            return event_id

        try:
            idemp_key = f"idemp:{stream_key}:{event_id}"
            if not await redis.set(idemp_key, "1", nx=True, ex=3600):
                log.warning("Duplicate event rejected: %s", event_id)
                return event_id

            await redis.xadd(stream_key, {"data": json.dumps(envelope)}, maxlen=max_len)
        except Exception as e:
            log.warning("Redis publish failed for %s: %s — queuing in memory", event_id, e)
            async with self._fallback_lock:
                if len(self._fallback) >= MAX_FALLBACK_SIZE:
                    log.error("Event bus fallback full — dropping event %s", event_id)
                else:
                    self._fallback.append(envelope)

        # Schedule drain task if fallback has items and Redis is back
        if self._fallback and redis and not self._drain_task:
            self._drain_task = asyncio.create_task(self._drain_fallback_loop())

        return event_id

    async def _drain_fallback_loop(self) -> None:
        """Background drain of in-memory fallback to Redis."""
        for _ in range(10):
            await asyncio.sleep(5)
            async with self._fallback_lock:
                if not self._fallback:
                    break
                redis = await get_redis()
                if not redis:
                    continue
                remaining = []
                for env in self._fallback:
                    try:
                        sk = self._stream_key(env["topic"])
                        await redis.xadd(sk, {"data": json.dumps(env)}, maxlen=100_000)
                    except Exception as e:
                        log.warning("Failed to drain event to Redis, will retry: %s", e)
                        remaining.append(env)
                self._fallback = remaining
        self._drain_task = None


event_producer = EventProducer()
