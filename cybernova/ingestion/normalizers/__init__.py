"""
CyberNova — Normalization Service
Converts raw events into canonical format. Consumes RAW_EVENT_INGESTED events.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import RawEvent, NormalizedEvent
from cybernova.database.repository.repositories import NormalizedEventRepository
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.core.event_bus.producer import event_producer
from cybernova.security.validation.validators import normalize_severity
from cybernova.ingestion.parsers.registry import ParserRegistry
from cybernova.config.constants import Topics

log = logging.getLogger("cybernova.ingestion.normalization")


def _parse_timestamp(ts_value) -> datetime:
    """Convert timestamp string or datetime to a proper datetime object."""
    if isinstance(ts_value, datetime):
        return ts_value
    if isinstance(ts_value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(ts_value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return utcnow()


class NormalizationService:

    def __init__(self) -> None:
        self.parser_registry = ParserRegistry()

    async def normalize_event(
        self, raw_event: RawEvent, db: AsyncSession, tenant_id: str,
    ) -> NormalizedEvent:
        payload = raw_event.payload or {}
        source_type = raw_event.source_type or "unknown"
        parsed = self.parser_registry.parse(source_type, payload)

        repo = NormalizedEventRepository(db, tenant_id)
        normalized = NormalizedEvent(
            id=new_id(), tenant_id=tenant_id,
            raw_event_id=raw_event.id,
            event_type=parsed.get("event_type", "unknown"),
            severity=normalize_severity(parsed.get("severity", "info")),
            source_ip=parsed.get("source_ip"),
            dest_ip=parsed.get("dest_ip"),
            source_port=parsed.get("source_port"),
            dest_port=parsed.get("dest_port"),
            protocol=parsed.get("protocol"),
            user=parsed.get("user"),
            device_id=parsed.get("device_id"),
            message=parsed.get("message", ""),
            extra_data=parsed.get("metadata", {}),
            timestamp=_parse_timestamp(parsed.get("timestamp")) or raw_event.received_at or utcnow(),
            normalized_at=utcnow(),
        )
        await repo.create(normalized)

        await event_producer.publish(
            Topics.EVENT_NORMALIZED,
            {"event_id": normalized.id, "event_type": normalized.event_type,
             "severity": normalized.severity},
            tenant_id=tenant_id,
        )

        log.info("Normalized event %s → type=%s severity=%s",
                 raw_event.id, normalized.event_type, normalized.severity)
        return normalized

    async def normalize_batch(
        self, raw_event_ids: List[str], db: AsyncSession, tenant_id: str,
    ) -> List[NormalizedEvent]:
        result = await db.execute(
            select(RawEvent).where(RawEvent.id.in_(raw_event_ids),
                                   RawEvent.tenant_id == tenant_id)
        )
        raw_events = result.scalars().all()
        normalized = []
        for raw in raw_events:
            try:
                norm = await self.normalize_event(raw, db, tenant_id)
                normalized.append(norm)
            except Exception as exc:
                log.error("Failed to normalize event %s: %s", raw.id, exc)
        return normalized

    async def normalize_pending(
        self, db: AsyncSession, tenant_id: str, limit: int = 100,
    ) -> List[NormalizedEvent]:
        subq = select(NormalizedEvent.raw_event_id)
        result = await db.execute(
            select(RawEvent)
            .where(~RawEvent.id.in_(subq), RawEvent.tenant_id == tenant_id)
            .order_by(RawEvent.received_at.asc()).limit(limit)
        )
        raw_events = result.scalars().all()
        normalized = []
        for raw in raw_events:
            try:
                norm = await self.normalize_event(raw, db, tenant_id)
                normalized.append(norm)
            except Exception as exc:
                log.error("Failed to normalize event %s: %s", raw.id, exc)
        log.info("Normalized %d pending events for tenant=%s", len(normalized), tenant_id)
        return normalized


normalization_service = NormalizationService()
