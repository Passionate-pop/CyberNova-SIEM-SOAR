"""
CyberNova — Enrichment Stage
Adds GeoIP, threat intel, and risk scoring to normalized events.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.geoip import geoip_service
from cybernova.network.threat_intel import threat_intel_service
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.pipeline.stage.enricher")


class EnrichmentStage(PipelineStage):
    """Enriches events with GeoIP, threat intel, and risk score."""

    def __init__(self):
        super().__init__("enrichment")
        self._semaphore = asyncio.Semaphore(50)

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        normalized = envelope.payload.get("normalized_data", {})
        if not normalized:
            log.warning("Enrichment: no normalized data for %s", envelope.event_id)
            return envelope

        enriched = dict(normalized)
        source_ip = normalized.get("source_ip", "")

        geo_task = asyncio.create_task(self._safe_geoip(source_ip))
        intel_task = asyncio.create_task(self._safe_threat_intel(source_ip))

        async with self._semaphore:
            geo, threat = await asyncio.gather(geo_task, intel_task, return_exceptions=True)

        if isinstance(geo, dict):
            enriched["geo_data"] = geo
        if isinstance(threat, dict):
            enriched["threat_intel"] = threat

        base_risk = {"critical": 80, "high": 60, "medium": 40, "low": 20, "info": 10}.get(
            normalized.get("severity", "info"), 10
        )
        risk_modifier = 0
        if isinstance(threat, dict):
            risk_modifier = threat.get("risk_modifier", 0)
        enriched["risk_score"] = min(base_risk + risk_modifier, 100)
        enriched["enriched_id"] = new_id()
        enriched["enriched_at"] = datetime.now(timezone.utc).isoformat()

        envelope.payload["enriched_data"] = enriched
        envelope.stage = "anomaly"
        return envelope

    async def _safe_geoip(self, ip: str) -> Dict[str, Any]:
        if not ip:
            return {}
        try:
            return await geoip_service.lookup(ip)
        except Exception as e:
            log.debug("GeoIP lookup failed for %s: %s", ip, e)
            return {}

    async def _safe_threat_intel(self, ip: str) -> Dict[str, Any]:
        if not ip:
            return {}
        try:
            return await threat_intel_service.lookup_ip(ip)
        except Exception as e:
            log.debug("Threat intel lookup failed for %s: %s", ip, e)
            return {}


enrichment_stage = EnrichmentStage()
