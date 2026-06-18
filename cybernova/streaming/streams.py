"""
CyberNova — Redis Streams Configuration
Defines all stream names, consumer groups, and processing configuration.
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
STREAM_WS_METRICS = f"{STREAM_PREFIX}:ws:metrics"

# Device Agent Stream (ingested from endpoint agents)
DEVICE_EVENTS_STREAM = f"{STREAM_PREFIX}:device_events"

ALL_STREAMS = [
    STREAM_RAW_EVENTS,
    STREAM_NORMALIZED,
    STREAM_ENRICHED,
    STREAM_ALERTS,
    STREAM_INCIDENTS,
    STREAM_ACTIONS,
    STREAM_DLQ,
    DEVICE_EVENTS_STREAM,
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

PROCESSOR_CONSUMER_NAME = "stream-processor"
