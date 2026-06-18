"""
BatchWriter — Accumulates DB objects and flushes them in bulk.

Usage:
    writer = BatchWriter(session, tenant_id, batch_size=100)
    
    async for event in event_stream:
        writer.add_raw_event(event)
        writer.add_normalized_event(event)
        if writer.should_flush():
            await writer.flush()
    
    await writer.flush()  # final flush
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    RawEvent, NormalizedEvent, EnrichedEvent, Alert,
)

log = logging.getLogger("cybernova.database.batch_writer")


class BatchWriter:
    """Accumulates ORM objects and flushes in batches."""

    def __init__(
        self,
        db: AsyncSession,
        tenant_id: str,
        batch_size: int = 100,
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.batch_size = batch_size
        self._raw_events: List[RawEvent] = []
        self._normalized_events: List[NormalizedEvent] = []
        self._enriched_events: List[EnrichedEvent] = []
        self._alerts: List[Alert] = []
        self._total_added = 0
        self._total_flushed = 0

    def add_raw_event(self, **kwargs) -> None:
        kwargs.setdefault("tenant_id", self.tenant_id)
        self._raw_events.append(RawEvent(**kwargs))
        self._total_added += 1

    def add_normalized_event(self, **kwargs) -> None:
        kwargs.setdefault("tenant_id", self.tenant_id)
        self._normalized_events.append(NormalizedEvent(**kwargs))
        self._total_added += 1

    def add_enriched_event(self, **kwargs) -> None:
        kwargs.setdefault("tenant_id", self.tenant_id)
        self._enriched_events.append(EnrichedEvent(**kwargs))
        self._total_added += 1

    def add_alert(self, **kwargs) -> None:
        kwargs.setdefault("tenant_id", self.tenant_id)
        self._alerts.append(Alert(**kwargs))
        self._total_added += 1

    @property
    def total_pending(self) -> int:
        return len(self._raw_events) + len(self._normalized_events) + len(self._enriched_events) + len(self._alerts)

    def should_flush(self) -> bool:
        return self.total_pending >= self.batch_size

    async def flush(self) -> int:
        count = self.total_pending
        if count == 0:
            return 0
        try:
            for entity_list in (self._raw_events, self._normalized_events, self._enriched_events, self._alerts):
                for obj in entity_list:
                    self.db.add(obj)
            await self.db.flush()
            self._total_flushed += count
            log.debug("BatchWriter flushed %d objects (total flushed: %d)", count, self._total_flushed)
        except Exception:
            await self.db.rollback()
            raise
        finally:
            self._raw_events.clear()
            self._normalized_events.clear()
            self._enriched_events.clear()
            self._alerts.clear()
        return count

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_added": self._total_added,
            "total_flushed": self._total_flushed,
            "pending": self.total_pending,
            "batch_size": self.batch_size,
        }
