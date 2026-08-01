"""
CyberNova — Enrichment Stage
Adds GeoIP, threat intel, stego detection, prevention engine, and risk scoring.
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
from cybernova.enrichment.stego_detector import stego_detector
from cybernova.protection import prevention_engine
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.pipeline.stage.enricher")


class EnrichmentStage(PipelineStage):
    """Enriches events with GeoIP, threat intel, stego analysis, prevention engine, and risk score."""

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

        # ── Steganography detection ──
        extra = normalized.get("extra_data", {}) or {}
        stego_result = None
        image_b64 = extra.get("image_data") or extra.get("image_base64")
        if image_b64:
            try:
                import base64
                raw = await asyncio.get_running_loop().run_in_executor(
                    None, base64.b64decode, image_b64
                )
                stego_result = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: stego_detector.analyze(raw, filename=extra.get("filename", "")),
                )
                if stego_result and stego_result.get("stego_suspected"):
                    risk_modifier += stego_result["risk_score"] * 0.4
                    enriched["enrichment_sources"] = enriched.get("enrichment_sources", []) + ["stego_detection"]
            except Exception as exc:
                log.warning("Stego enrichment failed: %s", exc)

        # Publish follow-up stego event if high-confidence
        if stego_result and stego_result.get("stego_suspected") and stego_result.get("risk_score", 0) >= 60:
            stego_event = {
                "source": "stego_detector",
                "event_type": "stego_suspected",
                "severity": "critical" if stego_result["risk_score"] >= 75 else "high",
                "message": f"Steganography suspected in {stego_result.get('filename', 'unknown')}",
                "extra_data": {
                    "filename": stego_result.get("filename", ""),
                    "format": stego_result.get("format"),
                    "risk_score": stego_result["risk_score"],
                    "findings": stego_result.get("findings", []),
                },
                "tenant_id": envelope.tenant_id,
            }
            # Publish back through the event bus for re-ingestion and detection rule matching
            try:
                await event_producer.publish(
                    Topics.RAW_EVENT_INGESTED,
                    stego_event,
                    tenant_id=envelope.tenant_id,
                )
            except Exception as exc:
                log.warning("Failed to publish stego event: %s", exc)

        # ── Prevention Engine ──
        prevention_event = {
            "event_type": normalized.get("event_type", ""),
            "severity": normalized.get("severity", "info"),
            "source_ip": normalized.get("source_ip", ""),
            "dest_ip": normalized.get("dest_ip", ""),
            "source_port": normalized.get("source_port", 0),
            "dest_port": normalized.get("dest_port", 0),
            "protocol": normalized.get("protocol", ""),
            "user": normalized.get("user", ""),
            "message": normalized.get("message", ""),
            "extra_data": extra,
            "extra": extra,
        }
        try:
            protection_result = await prevention_engine.analyze_event(prevention_event)
            if protection_result and protection_result.get("threat_detected"):
                risk_modifier += protection_result["max_risk_score"] * 0.35
                enriched["enrichment_sources"] = enriched.get("enrichment_sources", []) + ["prevention_engine"]
                for threat_data in protection_result.get("threats", []):
                    module = threat_data.get("module", "unknown")
                    findings = threat_data.get("findings", [])
                    thr_risk = threat_data.get("risk_score", 70)
                    mapped_type = {
                        "waf": "waf_block",
                        "webshell": "webshell_detected",
                        "rootkit": "rootkit_detected",
                        "tamper": "tamper_detected",
                        "cryptojacking": "cryptominer_detected",
                        "dlp": "dlp_leak_detected",
                        "config_audit": "misconfiguration_found",
                        "brute_force": "brute_force_detected",
                        "phishing": "phishing_detected",
                    }.get(module, f"{module}_alert")
                    for finding in findings[:3]:
                        try:
                            await event_producer.publish(
                                Topics.RAW_EVENT_INGESTED,
                                {
                                    "source": "prevention_engine",
                                    "event_type": mapped_type,
                                    "severity": "critical" if thr_risk >= 85 else "high" if thr_risk >= 65 else "medium",
                                    "message": finding.get("message", f"{module} threat detected"),
                                    "extra_data": {
                                        "module": module,
                                        "risk_score": thr_risk,
                                        "finding": finding,
                                    },
                                    "tenant_id": envelope.tenant_id,
                                },
                                tenant_id=envelope.tenant_id,
                            )
                        except Exception as exc:
                            log.debug("Prevention event publish failed: %s", exc)
        except Exception as exc:
            log.debug("Prevention engine analysis failed: %s", exc)

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
            return await asyncio.wait_for(geoip_service.lookup(ip), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("GeoIP lookup timed out for %s", ip)
            return {}
        except Exception as e:
            log.debug("GeoIP lookup failed for %s: %s", ip, e)
            return {}

    async def _safe_threat_intel(self, ip: str) -> Dict[str, Any]:
        if not ip:
            return {}
        try:
            return await asyncio.wait_for(threat_intel_service.lookup_ip(ip), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("Threat intel lookup timed out for %s", ip)
            return {}
        except Exception as e:
            log.debug("Threat intel lookup failed for %s: %s", ip, e)
            return {}


enrichment_stage = EnrichmentStage()
