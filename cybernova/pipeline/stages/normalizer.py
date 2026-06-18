"""
CyberNova — Normalization Stage
Converts raw events into a standardized NormalizedEvent format.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.pipeline.stage.normalizer")


class NormalizationStage(PipelineStage):
    """Converts raw event payloads to normalized event schema."""

    def __init__(self):
        super().__init__("normalization")

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        raw = envelope.payload.get("raw_data", {})
        source = envelope.payload.get("source", "unknown")
        source_type = envelope.payload.get("source_type", "unknown")

        normalized = {
            "event_type": self._extract_field(raw, "event_type", source),
            "severity": self._extract_field(raw, "severity", "info"),
            "source_ip": self._extract_field(raw, "source_ip", ""),
            "dest_ip": self._extract_field(raw, "dest_ip", ""),
            "source_port": self._extract_field(raw, "source_port", 0),
            "dest_port": self._extract_field(raw, "dest_port", 0),
            "protocol": self._extract_field(raw, "protocol", ""),
            "user": self._extract_field(raw, "user", ""),
            "message": self._extract_field(raw, "message", ""),
            "device_id": self._extract_field(raw, "device_id", ""),
            "extra_data": self._extract_field(raw, "extra_data", {}),
            "source": source,
            "source_type": source_type,
            "normalized_at": datetime.now(timezone.utc).isoformat(),
        }

        # Handle nested event data
        if "event" in raw and isinstance(raw["event"], dict):
            event_data = raw["event"]
            for key in ("event_type", "severity", "source_ip", "dest_ip", "user", "message"):
                if event_data.get(key):
                    normalized[key] = event_data[key]

        envelope.payload["normalized_data"] = normalized
        envelope.payload["normalized_id"] = new_id()
        envelope.stage = "enrichment"
        return envelope

    def _extract_field(self, raw: Dict[str, Any], field: str, default: Any) -> Any:
        if field in raw:
            return raw[field]
        event = raw.get("event", {})
        if isinstance(event, dict) and field in event:
            return event[field]
        extra = raw.get("extra_data", {})
        if isinstance(extra, dict) and field in extra:
            return extra[field]
        return default


normalization_stage = NormalizationStage()
