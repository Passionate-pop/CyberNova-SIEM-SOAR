"""
CyberNova — Stream Producer
Pushes events into Redis Streams with dead-letter handling.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

import redis.asyncio as aioredis

from cybernova.streaming.streams import (
    STREAM_RAW_EVENTS, STREAM_NORMALIZED, STREAM_ENRICHED,
    STREAM_ALERTS, STREAM_INCIDENTS, STREAM_ACTIONS,
    STREAM_DLQ, MAX_STREAM_LEN, DLQ_MAX_LEN, STREAM_PREFIX,
)

log = logging.getLogger("cybernova.streaming.producer")


class StreamProducer:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self._pubsub = None

    async def xadd(self, stream: str, data: Dict[str, Any], maxlen: int = MAX_STREAM_LEN) -> str:
        msg_id = await self.redis.xadd(stream, data, maxlen=maxlen)
        log.debug("xadd %s -> %s [%s]", stream, msg_id, data.get("event_type", "unknown"))
        return msg_id

    async def produce_raw_event(self, event: Dict[str, Any], tenant_id: str) -> str:
        envelope = {
            "event_id": str(uuid4()),
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event.get("event_type", "unknown"),
            "source": event.get("source", "api"),
            "data": json.dumps(event),
        }
        return await self.xadd(STREAM_RAW_EVENTS, envelope)

    async def produce_normalized_event(self, event: Dict[str, Any], tenant_id: str, raw_event_id: str) -> str:
        envelope = {
            "event_id": event.get("id", str(uuid4())),
            "tenant_id": tenant_id,
            "raw_event_id": raw_event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(event),
        }
        return await self.xadd(STREAM_NORMALIZED, envelope)

    async def produce_enriched_event(self, event: Dict[str, Any], tenant_id: str, normalized_event_id: str) -> str:
        envelope = {
            "event_id": event.get("id", str(uuid4())),
            "tenant_id": tenant_id,
            "normalized_event_id": normalized_event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(event),
        }
        return await self.xadd(STREAM_ENRICHED, envelope)

    async def produce_alert(self, alert: Dict[str, Any], tenant_id: str) -> str:
        envelope = {
            "alert_id": alert.get("id", str(uuid4())),
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(alert),
        }
        msg_id = await self.xadd(STREAM_ALERTS, envelope)
        await self._broadcast_alert(alert, tenant_id)
        return msg_id

    async def produce_incident(self, incident: Dict[str, Any], tenant_id: str) -> str:
        envelope = {
            "incident_id": incident.get("id", str(uuid4())),
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(incident),
        }
        msg_id = await self.xadd(STREAM_INCIDENTS, envelope)
        await self._broadcast_incident(incident, tenant_id)
        return msg_id

    async def produce_response_action(self, action: Dict[str, Any], tenant_id: str) -> str:
        envelope = {
            "action_id": action.get("id", str(uuid4())),
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(action),
        }
        return await self.xadd(STREAM_ACTIONS, envelope)

    async def send_to_dlq(self, original_stream: str, msg_id: str, error: str, data: Dict[str, Any]) -> str:
        envelope = {
            "original_stream": original_stream,
            "original_msg_id": msg_id,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(data),
        }
        return await self.xadd(STREAM_DLQ, envelope, maxlen=DLQ_MAX_LEN)

    async def _broadcast_alert(self, alert: Dict[str, Any], tenant_id: str) -> None:
        channel = f"{STREAM_PREFIX}:ws:{tenant_id}:alerts"
        payload = json.dumps({"type": "alert", "data": alert})
        await self.redis.publish(channel, payload)

    async def _broadcast_incident(self, incident: Dict[str, Any], tenant_id: str) -> None:
        channel = f"{STREAM_PREFIX}:ws:{tenant_id}:incidents"
        payload = json.dumps({"type": "incident", "data": incident})
        await self.redis.publish(channel, payload)

    async def broadcast_metrics(self, tenant_id: str, metrics: Dict[str, Any]) -> None:
        channel = f"{STREAM_PREFIX}:ws:{tenant_id}:metrics"
        payload = json.dumps({"type": "metrics", "data": metrics})
        await self.redis.publish(channel, payload)
