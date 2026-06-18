"""
CyberNova — Stream Reliability Engine
PEL reclaim, dead consumer recovery, backpressure control, lag monitoring.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import redis.asyncio as aioredis

from cybernova.streaming.streams import (
    STREAM_RAW_EVENTS, STREAM_NORMALIZED, STREAM_ENRICHED,
    STREAM_ALERTS, STREAM_ACTIONS, CONSUMER_GROUPS,
    MAX_STREAM_LEN, STREAM_PREFIX,
)

log = logging.getLogger("cybernova.streaming.reliability")

STALE_CLAIM_MIN_IDLE_MS = 60_000
STALE_CHECK_INTERVAL = 30


class StreamReliabilityEngine:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self._running = False
        self._tasks: set = set()

    async def start(self) -> None:
        self._running = True
        t = asyncio.create_task(self._reclaim_loop())
        self._tasks.add(t)
        t = asyncio.create_task(self._cleanup_loop())
        self._tasks.add(t)
        t = asyncio.create_task(self._lag_monitor_loop())
        self._tasks.add(t)
        log.info("Stream reliability engine started")

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _reclaim_loop(self) -> None:
        """Continuously scan for stuck messages in PEL and reclaim them."""
        recovery_consumer = f"reclaimer-{uuid4().hex[:6]}"

        while self._running:
            try:
                for stream, group in CONSUMER_GROUPS.items():
                    await self._reclaim_from_stream(stream, group, recovery_consumer)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Reclaim loop error: %s", exc)

            await asyncio.sleep(STALE_CHECK_INTERVAL)

    async def _reclaim_from_stream(
        self, stream: str, group: str, consumer: str
    ) -> int:
        """Claim messages that have been pending for too long."""
        try:
            pending = await self.redis.xpending_range(
                stream, group, min="-", max="+", count=100
            )
        except Exception as e:
            log.warning("Failed to query pending messages on %s: %s", stream, e)
            return 0

        if not pending:
            return 0

        stale_msgs = [
            p["message_id"]
            for p in pending
            if p["time_since_delivered"] > STALE_CLAIM_MIN_IDLE_MS
        ]

        if not stale_msgs:
            return 0

        try:
            claimed = await self.redis.xclaim(
                stream, group, consumer, STALE_CLAIM_MIN_IDLE_MS, stale_msgs
            )
            count = 0
            for msg_id, data in claimed:
                try:
                    from cybernova.streaming.consumer import StreamConsumer
                    consumer_obj = StreamConsumer(self.redis, group, consumer, {stream: stream})
                    await consumer_obj.nack(stream, msg_id)
                    count += 1
                except Exception as e:
                    log.warning("Failed to nack reclaimed message %s: %s", msg_id, e)

            if count > 0:
                log.warning("Reclaimed %d stale messages from %s:%s", count, stream, group)
            return count
        except Exception as exc:
            log.error("Claim error on %s:%s — %s", stream, group, exc)
            return 0

    async def _cleanup_loop(self) -> None:
        """Periodically trim streams to MAXLEN to prevent unbounded growth."""
        while self._running:
            try:
                for stream in [STREAM_RAW_EVENTS, STREAM_NORMALIZED, STREAM_ENRICHED]:
                    try:
                        current_len = await self.redis.xlen(stream)
                        if current_len > MAX_STREAM_LEN * 1.5:
                            await self.redis.xtrim(stream, maxlen=MAX_STREAM_LEN, approximate=True)
                            log.info("Trimmed %s from %d to ~%d", stream, current_len, MAX_STREAM_LEN)
                    except Exception as e:
                        log.warning("Failed to trim stream %s: %s", stream, e)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Cleanup loop error: %s", exc)

            await asyncio.sleep(60)

    async def _lag_monitor_loop(self) -> None:
        """Monitor consumer group lag and record as metrics."""
        from cybernova.monitoring.metrics import metrics

        while self._running:
            try:
                for stream, group in CONSUMER_GROUPS.items():
                    try:
                        stream_len = await self.redis.xlen(stream)
                        await self.redis.xpending_range(
                            stream, group, min="-", max="+", count=1
                        )
                        pending_info = await self.redis.xpending(stream, group)
                        pending_count = pending_info.get("pending", 0) if isinstance(pending_info, dict) else (len(pending_info) if isinstance(pending_info, (list, tuple)) else 0)
                        metrics.gauge("stream_lag", float(stream_len), {"stream": stream.replace(f"{STREAM_PREFIX}:", ""), "type": "length"})
                        if pending_count:
                            metrics.gauge("stream_pending", float(pending_count), {"stream": stream.replace(f"{STREAM_PREFIX}:", "")})
                    except Exception as e:
                        log.warning("Failed to check lag on stream %s: %s", stream, e)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Lag monitor error: %s", exc)

            await asyncio.sleep(15)

    async def get_stream_health(self) -> Dict[str, Any]:
        """Return health status of all streams."""
        health = {}
        for stream in [STREAM_RAW_EVENTS, STREAM_NORMALIZED, STREAM_ENRICHED, STREAM_ALERTS, STREAM_ACTIONS]:
            try:
                length = await self.redis.xlen(stream)
                groups = []
                try:
                    group_list = await self.redis.xinfo_groups(stream)
                    for g in group_list:
                        groups.append({
                            "name": g.get("name", ""),
                            "pending": g.get("pending", 0),
                            "consumers": g.get("consumers", 0),
                        })
                except Exception as e:
                    log.warning("Failed to get stream info for %s: %s", stream, e)
                health[stream.replace(f"{STREAM_PREFIX}:", "")] = {
                    "length": length,
                    "groups": groups,
                    "max_len": MAX_STREAM_LEN,
                    "utilization_pct": round(length / MAX_STREAM_LEN * 100, 2) if MAX_STREAM_LEN > 0 else 0,
                }
            except Exception as e:
                health[stream.replace(f"{STREAM_PREFIX}:", "")] = {"error": str(e)}
        return health


class BackpressureController:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self._high_water = MAX_STREAM_LEN
        self._scale_signal_key = f"{STREAM_PREFIX}:scale:signal"

    async def check_backpressure(self, stream: str) -> tuple[bool, str]:
        """Return (blocked, reason) — True means stop ingesting."""
        try:
            length = await self.redis.xlen(stream)
            if length >= self._high_water:
                return True, f"Stream {stream} at {length}/{self._high_water}"
            return False, ""
        except Exception as e:
            log.warning("Failed to check backpressure on %s: %s", stream, e)
            return False, ""

    async def record_scale_signal(self, stream: str, direction: str) -> None:
        """Record when a worker scale event was triggered."""
        signal = {
            "stream": stream,
            "direction": direction,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        import json
        await self.redis.set(self._scale_signal_key, json.dumps(signal), ex=300)

    async def get_scale_signal(self) -> Optional[Dict[str, Any]]:
        import json
        val = await self.redis.get(self._scale_signal_key)
        if val:
            return json.loads(val)
        return None


class IdempotencyManager:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self._ttl = 86400

    async def check_and_set(self, key: str, value: str = "1") -> bool:
        """Return True if already exists (duplicate), False if new."""
        result = await self.redis.set(f"idemp:{key}", value, nx=True, ex=self._ttl)
        return result is None

    async def mark_processed(self, event_id: str, tenant_id: str = "default") -> None:
        key = f"{tenant_id}:{event_id}"
        await self.redis.set(f"idemp:event:{key}", "1", ex=self._ttl)

    async def is_duplicate(self, event_id: str, tenant_id: str = "default") -> bool:
        key = f"{tenant_id}:{event_id}"
        return await self.redis.exists(f"idemp:event:{key}") > 0

    async def mark_alert_processed(self, alert_key: str) -> bool:
        result = await self.redis.set(f"idemp:alert:{alert_key}", "1", nx=True, ex=self._ttl)
        return result is None

    async def mark_action_processed(self, action_key: str) -> bool:
        result = await self.redis.set(f"idemp:action:{action_key}", "1", nx=True, ex=self._ttl)
        return result is None
