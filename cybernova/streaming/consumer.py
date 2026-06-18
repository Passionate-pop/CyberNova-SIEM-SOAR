"""
CyberNova — Stream Consumer
Reads from Redis Streams consumer groups with ack/nack/dead-letter support.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

import redis.asyncio as aioredis

from cybernova.streaming.streams import (
    STREAM_DLQ, MAX_RETRIES, DLQ_MAX_LEN,
)

log = logging.getLogger("cybernova.streaming.consumer")


class StreamConsumer:
    def __init__(
        self,
        redis: aioredis.Redis,
        group: str,
        consumer: str,
        streams: Dict[str, str],
    ) -> None:
        self.redis = redis
        self.group = group
        self.consumer = consumer
        self.streams = streams

    async def ensure_groups(self) -> None:
        for stream in self.streams.values():
            try:
                await self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
                log.info("Created consumer group %s on %s", self.group, stream)
            except aioredis.ResponseError:
                pass

    async def read(
        self,
        count: int = 100,
        block_ms: int = 5000,
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        results: List[Tuple[str, str, Dict[str, Any]]] = []
        try:
            stream_ids = {stream: ">" for stream in self.streams.values()}
            messages = await self.redis.xreadgroup(
                self.group,
                self.consumer,
                stream_ids,
                count=count,
                block=block_ms,
            )
        except Exception as exc:
            log.error("xreadgroup error: %s", exc)
            return results

        if not messages:
            return results

        for stream_name, msgs in messages:
            for msg_id, data in msgs:
                try:
                    raw_data_field = data.get("data", "{}")
                    event = json.loads(raw_data_field)
                    envelope = dict(data)
                    envelope["data"] = raw_data_field
                    envelope["_msg_id"] = msg_id
                    envelope["_stream"] = stream_name
                    envelope.update(event)
                    results.append((stream_name, msg_id, envelope))
                except Exception as exc:
                    log.error("Malformed message %s in %s: %s", msg_id, stream_name, exc)
                    await self.send_to_dlq(stream_name, msg_id, str(exc), data)
                    await self.ack(stream_name, msg_id)
        return results

    async def read_with_pending(
        self,
        count: int = 100,
        block_ms: int = 5000,
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Reclaim stale, then read pending, then read new messages."""
        results: List[Tuple[str, str, Dict[str, Any]]] = []
        
        for stream in self.streams.values():
            try:
                stale = await self.claim_stale(stream, min_idle_ms=10000, limit=count)
                for msg_id, envelope in stale:
                    envelope["_msg_id"] = msg_id
                    envelope["_stream"] = stream
                    results.append((stream, msg_id, envelope))
                    log.info("Claimed stale %s from %s", msg_id, stream)
            except Exception as exc:
                log.warning("Reclaim failed for %s: %s", stream, exc)

        for stream in self.streams.values():
            try:
                pending = await self.redis.xreadgroup(
                    self.group,
                    self.consumer,
                    {stream: "0"},
                    count=count,
                )
                if pending:
                    for stream_name, msgs in pending:
                        for msg_id, data in msgs:
                            try:
                                raw_data_field = data.get("data", "{}")
                                event = json.loads(raw_data_field)
                                envelope = dict(data)
                                envelope["data"] = raw_data_field
                                envelope["_msg_id"] = msg_id
                                envelope["_stream"] = stream_name
                                envelope.update(event)
                                results.append((stream_name, msg_id, envelope))
                            except Exception as exc:
                                log.warning("Malformed pending %s in %s: %s", msg_id, stream_name, exc)
            except Exception as exc:
                log.warning("Error reading pending from %s: %s", stream, exc)

        try:
            stream_ids = {stream: ">" for stream in self.streams.values()}
            new_messages = await self.redis.xreadgroup(
                self.group,
                self.consumer,
                stream_ids,
                count=count,
                block=block_ms,
            )
            if new_messages:
                for stream_name, msgs in new_messages:
                    for msg_id, data in msgs:
                        try:
                            raw_data_field = data.get("data", "{}")
                            event = json.loads(raw_data_field)
                            envelope = dict(data)
                            envelope["data"] = raw_data_field
                            envelope["_msg_id"] = msg_id
                            envelope["_stream"] = stream_name
                            envelope.update(event)
                            results.append((stream_name, msg_id, envelope))
                        except Exception as exc:
                            log.warning("Malformed new msg %s in %s: %s", msg_id, stream_name, exc)
        except Exception as exc:
            log.error("xreadgroup error for new: %s", exc)

        return results

    async def ack(self, stream: str, *msg_ids: str) -> int:
        if not msg_ids:
            return 0
        try:
            return await self.redis.xack(stream, self.group, *msg_ids)
        except Exception as exc:
            log.error("xack error on %s: %s", stream, exc)
            return 0

    async def nack(self, stream: str, msg_id: str) -> None:
        retry_key = f"retry:{stream}:{msg_id}"
        retry_count_str = await self.redis.get(retry_key)
        retry_count = int(retry_count_str or 0)

        if retry_count >= MAX_RETRIES:
            log.warning("Max retries reached for %s:%s — sending to DLQ", stream, msg_id)
            await self.send_to_dlq(stream, msg_id, "Max retries exceeded", {})
            await self.ack(stream, msg_id)
            await self.redis.delete(retry_key)
        else:
            await self.redis.set(retry_key, retry_count + 1, ex=3600)
            log.debug("NACK %s:%s (retry %d)", stream, msg_id, retry_count + 1)

    async def send_to_dlq(self, stream: str, msg_id: str, error: str, data: Dict[str, Any]) -> str:
        envelope = {
            "original_stream": stream,
            "original_msg_id": msg_id,
            "error": error,
            "data": json.dumps(data),
        }
        return await self.redis.xadd(STREAM_DLQ, envelope, maxlen=DLQ_MAX_LEN)

    async def claim_stale(
        self,
        stream: str,
        min_idle_ms: int = 30000,
        limit: int = 100,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        try:
            pending = await self.redis.xpending_range(
                stream, self.group, min="-", max="+", count=limit
            )
            stale = [
                p["message_id"]
                for p in pending
                if p["time_since_delivered"] > min_idle_ms
            ]
            if not stale:
                return []

            msgs = await self.redis.xclaim(
                stream, self.group, self.consumer, min_idle_ms, stale
            )
            results: List[Tuple[str, Dict[str, Any]]] = []
            for msg_id, data in msgs:
                try:
                    raw_data_field = data.get("data", "{}")
                    event = json.loads(raw_data_field)
                    envelope: Dict[str, Any] = dict(data)
                    envelope["data"] = raw_data_field
                    envelope["_msg_id"] = msg_id
                    envelope["_stream"] = stream
                    envelope.update(event)
                    results.append((msg_id, envelope))
                except Exception as exc:
                    log.warning("Failed to parse reclaimed msg %s: %s", msg_id, exc)
            return results
        except Exception as exc:
            log.error("Claim stale error on %s: %s", stream, exc)
            return []

    async def get_stream_info(self) -> Dict[str, Dict[str, Any]]:
        info = {}
        for name, stream in self.streams.items():
            try:
                length = await self.redis.xlen(stream)
                groups = await self.redis.xinfo_groups(stream)
                info[name] = {"length": length, "groups": len(groups), "stream": stream}
            except Exception as e:
                log.warning("Failed to get stream info for %s: %s", stream, e)
                info[name] = {"length": 0, "groups": 0, "stream": stream}
        return info
