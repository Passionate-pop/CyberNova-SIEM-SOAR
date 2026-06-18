"""
CyberNova — Event Bus: Consumer
Consumes events from Redis Streams with consumer groups.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.event_bus.consumer")


class EventConsumer:
    """Reads events from Redis Streams using consumer groups."""

    def __init__(self, stream_prefix: str = "cybernova") -> None:
        self.stream_prefix = stream_prefix

    def _stream_key(self, topic: str) -> str:
        return f"{self.stream_prefix}:{topic}"

    async def consume(
        self,
        topic: str,
        group: str,
        consumer: str,
        batch_size: int = 100,
        block_ms: int = 10,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Consume a batch of events from a topic."""
        redis = await get_redis()
        if not redis:
            return []

        stream_key = self._stream_key(topic)

        # Ensure consumer group exists
        try:
            await redis.xgroup_create(stream_key, group, id="0", mkstream=True)
        except Exception:
            log.debug("Stream group %s already exists for %s", group, stream_key)

        try:
            messages = await redis.xreadgroup(
                group, consumer, {stream_key: ">"}, count=batch_size, block=block_ms,
            )
        except Exception as exc:
            log.error("Redis consumer error on %s: %s", topic, exc)
            return []

        results: List[Tuple[str, Dict[str, Any]]] = []
        for _stream, msgs in messages:
            for msg_id, msg_data in msgs:
                try:
                    envelope = json.loads(msg_data["data"])
                    results.append((msg_id, envelope))
                except Exception as exc:
                    log.error("Malformed event %s: %s", msg_id, exc)
                    await self.nack(topic, group, msg_id)
        return results

    async def ack(self, topic: str, group: str, msg_id: str) -> None:
        redis = await get_redis()
        if redis:
            await redis.xack(self._stream_key(topic), group, msg_id)

    async def nack(self, topic: str, group: str, msg_id: str) -> None:
        """Send to dead-letter queue."""
        redis = await get_redis()
        if redis:
            dlq_key = f"{self._stream_key(topic)}_dlq"
            await redis.xadd(dlq_key, {"msg_id": msg_id}, maxlen=10_000)
            await redis.xack(self._stream_key(topic), group, msg_id)


event_consumer = EventConsumer()
