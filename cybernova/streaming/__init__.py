"""
CyberNova — Redis Streams Configuration
Defines stream names, consumer groups, and stream parameters.
"""
from __future__ import annotations


STREAM_PREFIX = "cybernova"

STREAM_RAW_EVENTS = f"{STREAM_PREFIX}:raw_events"
STREAM_NORMALIZED = f"{STREAM_PREFIX}:normalized_events"
STREAM_ENRICHED = f"{STREAM_PREFIX}:enriched_events"
STREAM_ALERTS = f"{STREAM_PREFIX}:alerts"
STREAM_INCIDENTS = f"{STREAM_PREFIX}:incidents"
STREAM_ACTIONS = f"{STREAM_PREFIX}:response_actions"
STREAM_DLQ = f"{STREAM_PREFIX}:dead_letter"
STREAM_WS_ALERTS = f"{STREAM_PREFIX}:ws:alerts"
STREAM_WS_INCIDENTS = f"{STREAM_PREFIX}:ws:incidents"

ALL_STREAMS = [
    STREAM_RAW_EVENTS,
    STREAM_NORMALIZED,
    STREAM_ENRICHED,
    STREAM_ALERTS,
    STREAM_INCIDENTS,
    STREAM_ACTIONS,
    STREAM_DLQ,
]

CONSUMER_GROUPS = {
    STREAM_RAW_EVENTS: "normalizer_group",
    STREAM_NORMALIZED: "enrichment_group",
    STREAM_ENRICHED: "detection_group",
    STREAM_ALERTS: "correlation_group",
    STREAM_ACTIONS: "soar_group",
}

MAX_STREAM_LEN = 100_000
DLQ_MAX_LEN = 10_000
MAX_RETRIES = 3
RETRY_DELAYS = [30, 60, 120]

CHANNELS = {
    "ws_alerts": "ws:alerts",
    "ws_incidents": "ws:incidents",
    "ws_actions": "ws:actions",
    "ws_pipeline": "ws:pipeline",
}

__all__ = [
    "STREAM_PREFIX",
    "STREAM_RAW_EVENTS",
    "STREAM_NORMALIZED",
    "STREAM_ENRICHED",
    "STREAM_ALERTS",
    "STREAM_INCIDENTS",
    "STREAM_ACTIONS",
    "STREAM_DLQ",
    "STREAM_WS_ALERTS",
    "STREAM_WS_INCIDENTS",
    "ALL_STREAMS",
    "CONSUMER_GROUPS",
    "MAX_STREAM_LEN",
    "DLQ_MAX_LEN",
    "MAX_RETRIES",
    "RETRY_DELAYS",
    "CHANNELS",
]
