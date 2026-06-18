"""
CyberNova — Ingestion Service
Receives raw events, sanitizes, persists, and emits to event bus.
Uses repository layer — NO direct ORM.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import RawEvent, NormalizedEvent
from cybernova.database.repository.repositories import EventRepository
from cybernova.security.validation.sanitizer import sanitize_dict
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics, SUPPORTED_SOURCE_TYPES

log = logging.getLogger("cybernova.ingestion.service")


class IngestionService:

    async def ingest_batch(
        self, source: str, source_type: str, events: List[Dict[str, Any]],
        db: AsyncSession, tenant_id: str,
    ) -> List[str]:
        if source_type not in SUPPORTED_SOURCE_TYPES:
            source_type = "api"

        repo = EventRepository(db, tenant_id)
        created_ids: List[str] = []

        for raw_payload in events:
            sanitized = sanitize_dict(raw_payload)
            event = RawEvent(
                id=new_id(), tenant_id=tenant_id,
                source=source, source_type=source_type,
                payload=sanitized, received_at=utcnow(),
            )
            await repo.create(event)
            created_ids.append(event.id)

            await event_producer.publish(
                Topics.RAW_EVENT_INGESTED,
                {"event_id": event.id, "source": source, "source_type": source_type},
                tenant_id=tenant_id, event_id=event.id,
            )

        log.info("Ingested %d events from source=%s tenant=%s", len(created_ids), source, tenant_id)
        return created_ids

    async def ingest_single(
        self, source: str, source_type: str, payload: Dict[str, Any],
        db: AsyncSession, tenant_id: str,
    ) -> str:
        ids = await self.ingest_batch(source, source_type, [payload], db, tenant_id)
        return ids[0]

    async def normalize_pending(
        self, db: AsyncSession, tenant_id: str, limit: int = 100,
    ) -> int:
        from cybernova.ingestion.normalizers import normalization_service
        normalized = await normalization_service.normalize_pending(db, tenant_id, limit)
        return len(normalized)

    async def enrich_batch(
        self, db: AsyncSession, tenant_id: str, limit: int = 100,
    ) -> int:
        from cybernova.detection.pipelines.enrichment import enrichment_service
        from cybernova.database.postgres.models import EnrichedEvent
        # Only enrich events that haven't been enriched yet — prevents
        # duplicate EnrichedEvent rows that cause "Multiple rows found" errors.
        already_enriched = select(EnrichedEvent.normalized_event_id)
        result = await db.execute(
            select(NormalizedEvent)
            .where(~NormalizedEvent.id.in_(already_enriched),
                   NormalizedEvent.tenant_id == tenant_id)
            .order_by(NormalizedEvent.timestamp.asc())
            .limit(limit)
        )
        events = result.scalars().all()
        count = 0
        for event in events:
            try:
                await enrichment_service.enrich_event(event.id, db, tenant_id)
                count += 1
            except Exception as e:
                log.error(f"Enrichment failed for {event.id}: {e}")
        return count


ingestion_service = IngestionService()
