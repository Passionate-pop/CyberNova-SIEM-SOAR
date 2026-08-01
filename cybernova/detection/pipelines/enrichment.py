"""
CyberNova — Enrichment Pipeline
Adds GeoIP and threat intel context to normalized events.
Part of the detection pipeline (runs after normalization, before rule eval).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import NormalizedEvent, EnrichedEvent
from cybernova.database.repository.repositories import EnrichedEventRepository
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics
from cybernova.geoip import geoip_service
from cybernova.network.threat_intel import threat_intel_service
from cybernova.enrichment.stego_detector import stego_detector
from cybernova.protection import prevention_engine

log = logging.getLogger("cybernova.detection.enrichment")


async def geoip_lookup(ip: str) -> Dict[str, Any]:
    """Real GeoIP lookup using ip-api.com with caching."""
    return await geoip_service.lookup(ip)


async def threat_intel_lookup(ip: str) -> Dict[str, Any]:
    """Real threat intel lookup: local blacklist + external APIs (VT/AbuseIPDB)."""
    return await threat_intel_service.lookup_ip(ip)


class EnrichmentService:

    async def enrich_event(
        self, normalized_event_id: str, db: AsyncSession, tenant_id: str,
    ) -> EnrichedEvent:
        result = await db.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.id == normalized_event_id,
                NormalizedEvent.tenant_id == tenant_id,
            )
        )
        event = result.scalar_one_or_none()
        if not event:
            raise ValueError(f"Normalized event {normalized_event_id} not found")

        # Timeout-protected lookups -- external API calls can hang
        geo = {}
        threat = {}
        try:
            geo = await asyncio.wait_for(geoip_lookup(event.source_ip or ""), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("GeoIP lookup timed out for %s", event.source_ip)
        except Exception as exc:
            log.debug("GeoIP lookup failed: %s", exc)
        try:
            threat = await asyncio.wait_for(threat_intel_lookup(event.source_ip or ""), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("Threat intel lookup timed out for %s", event.source_ip)
        except Exception as exc:
            log.debug("Threat intel lookup failed: %s", exc)

        base_risk = {"critical": 80, "high": 60, "medium": 40, "low": 20, "info": 10}.get(
            event.severity or "info", 10
        )
        risk_modifier = threat.get("risk_modifier", 0)

        # Scanner event enrichment — adjust risk from agent-side findings
        extra = event.extra_data or {}
        scan_risk = extra.get("risk_score", 0)
        if scan_risk:
            risk_modifier = max(risk_modifier, scan_risk * 0.3)
        if extra.get("yara_matches"):
            risk_modifier += 20
        if extra.get("entropy", 0) > 7.0:
            risk_modifier += 10
        if extra.get("suspicious"):
            risk_modifier += 5 * min(len(extra["suspicious"]), 5)

        sources = ["geoip", "local_threat_intel"]
        if scan_risk or extra.get("yara_matches"):
            sources.append("scanner_enrichment")

        # Steganography detection — analyze image data from events
        stego_result = None
        image_b64 = extra.get("image_data") or extra.get("image_base64")
        if image_b64:
            try:
                import base64
                loop = asyncio.get_running_loop()
                raw = await loop.run_in_executor(None, base64.b64decode, image_b64)
                loop2 = asyncio.get_running_loop()
                stego_result = await loop2.run_in_executor(
                    None,
                    lambda: stego_detector.analyze(raw, filename=extra.get("filename", "")),
                )
                if stego_result and stego_result.get("stego_suspected"):
                    risk_modifier += stego_result["risk_score"] * 0.4
                    sources.append("stego_detection")
            except Exception as exc:
                log.warning("Stego enrichment failed: %s", exc)

        # If stego detected at high confidence, publish a follow-up event
        if stego_result and stego_result.get("stego_suspected") and stego_result.get("risk_score", 0) >= 60:
            await event_producer.publish(
                Topics.RAW_EVENT_INGESTED,
                {
                    "source": "enrichment",
                    "event_type": "stego_suspected",
                    "severity": "critical" if stego_result["risk_score"] >= 75 else "high",
                    "message": f"Steganography suspected in {stego_result.get('filename', 'unknown')}",
                    "extra_data": {
                        "filename": stego_result.get("filename", ""),
                        "format": stego_result.get("format"),
                        "risk_score": stego_result["risk_score"],
                        "findings": stego_result.get("findings", []),
                        "original_event_id": normalized_event_id,
                    },
                    "tenant_id": tenant_id,
                },
                tenant_id=tenant_id,
            )

        # Prevention Engine — analyze event against all protection modules
        prevention_event = {
            "event_type": event.event_type,
            "severity": event.severity,
            "source_ip": event.source_ip or "",
            "dest_ip": event.dest_ip or "",
            "source_port": event.source_port,
            "dest_port": event.dest_port,
            "protocol": event.protocol,
            "user": event.user or "",
            "message": event.message or "",
            "extra_data": event.extra_data or {},
            "extra": event.extra_data or {},
        }
        protection_result = await prevention_engine.analyze_event(prevention_event)
        if protection_result and protection_result.get("threat_detected"):
            risk_modifier += protection_result["max_risk_score"] * 0.35
            sources.append("prevention_engine")
            for threat in protection_result.get("threats", []):
                module = threat.get("module", "unknown")
                findings = threat.get("findings", [])
                thr_risk = threat.get("risk_score", 70)
                severity = "critical" if thr_risk >= 85 else "high" if thr_risk >= 65 else "medium"
                event_type_map = {
                    "waf": "waf_block",
                    "webshell": "webshell_detected",
                    "rootkit": "rootkit_detected",
                    "tamper": "tamper_detected",
                    "cryptojacking": "cryptominer_detected",
                    "dlp": "dlp_leak_detected",
                    "config_audit": "misconfiguration_found",
                    "brute_force": "brute_force_detected",
                    "phishing": "phishing_detected",
                }
                mapped_type = event_type_map.get(module, f"{module}_alert")
                for finding in findings[:3]:
                    await event_producer.publish(
                        Topics.RAW_EVENT_INGESTED,
                        {
                            "source": "prevention_engine",
                            "event_type": mapped_type,
                            "severity": severity,
                            "message": finding.get("message", f"{module} threat detected"),
                            "extra_data": {
                                "module": module,
                                "risk_score": thr_risk,
                                "finding": finding,
                                "original_event_id": normalized_event_id,
                            },
                            "tenant_id": tenant_id,
                        },
                        tenant_id=tenant_id,
                    )

        risk_score = min(base_risk + risk_modifier, 100)

        repo = EnrichedEventRepository(db, tenant_id)
        enriched = EnrichedEvent(
            id=new_id(), tenant_id=tenant_id,
            normalized_event_id=event.id,
            geo_data=geo, threat_intel=threat,
            risk_score=round(risk_score, 1),
            enrichment_sources=sources,
            enriched_at=utcnow(),
        )
        await repo.create(enriched)

        await event_producer.publish(
            Topics.EVENT_ENRICHED,
            {"event_id": enriched.id, "risk_score": enriched.risk_score},
            tenant_id=tenant_id,
        )

        return enriched

    async def enrich_pending(
        self, db: AsyncSession, tenant_id: str, limit: int = 100,
    ) -> int:
        already_enriched = select(EnrichedEvent.normalized_event_id)
        result = await db.execute(
            select(NormalizedEvent)
            .where(~NormalizedEvent.id.in_(already_enriched),
                   NormalizedEvent.tenant_id == tenant_id)
            .limit(limit)
        )
        events = result.scalars().all()
        count = 0
        for event in events:
            try:
                await self.enrich_event(event.id, db, tenant_id)
                count += 1
            except Exception as exc:
                log.error("Enrichment failed for %s: %s", event.id, exc)
        return count


enrichment_service = EnrichmentService()
