"""
CyberNova — Pipeline Dead Letter Queue Worker
Processes DeadLetterEvent records from Postgres DLQ table with exponential backoff.
Re-queues failed events to the original queue. Creates alerts when retries exhausted.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, and_

from cybernova.database.postgres.session import get_db_session
from cybernova.database.postgres.models import DeadLetterEvent, Alert
from cybernova.pipeline.queue_manager import queue_manager, QueuedTask, QueueName
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.pipeline.dlq_worker")

CHECK_INTERVAL = 30
RETRY_BASE_DELAY = 30


class DeadLetterWorker:

    def __init__(self):
        self._stop = False

    async def start(self) -> None:
        log.info("DLQ worker started (check interval: %ds)", CHECK_INTERVAL)
        while not self._stop:
            try:
                await self._process_dlq()
            except Exception as e:
                log.error("DLQ processing error: %s", e)
            await asyncio.sleep(CHECK_INTERVAL)

    async def stop(self) -> None:
        self._stop = True
        log.info("DLQ worker stopped")

    @staticmethod
    def _backoff_delay(retry_count: int) -> int:
        return RETRY_BASE_DELAY * (2 ** retry_count)

    async def _process_dlq(self) -> None:
        async for db in get_db_session():
            result = await db.execute(
                select(DeadLetterEvent).order_by(DeadLetterEvent.failed_at.asc())
            )
            records = result.scalars().all()
            if not records:
                return

            now = datetime.now(timezone.utc)
            for record in records:
                if record.retry_count >= record.max_retries:
                    await self._handle_exhausted(db, record)
                elif self._is_due_for_retry(record, now):
                    await self._retry_record(db, record)

            await db.commit()

    def _is_due_for_retry(self, record: DeadLetterEvent, now: datetime) -> bool:
        delay = self._backoff_delay(record.retry_count)
        next_retry_at = record.failed_at + timedelta(seconds=delay)
        return now >= next_retry_at

    async def _retry_record(self, db, record: DeadLetterEvent) -> None:
        try:
            task = QueuedTask.from_json(record.payload)
            await queue_manager.enqueue(
                queue=QueueName(task.queue),
                payload=task.payload,
                priority=task.priority,
                metadata=task.metadata,
            )
            await db.delete(record)
            log.info("DLQ retry OK — event %s re-queued to %s",
                      record.id, record.original_queue)
        except Exception as e:
            record.retry_count += 1
            record.failed_at = datetime.now(timezone.utc)
            log.warning("DLQ retry %d/%d failed for %s: %s",
                        record.retry_count, record.max_retries, record.id, e)
            if record.retry_count >= record.max_retries:
                await self._create_alert(db, record)

    async def _handle_exhausted(self, db, record: DeadLetterEvent) -> None:
        existing = await db.execute(
            select(Alert).where(
                and_(
                    Alert.tenant_id == record.tenant_id,
                    Alert.event_id == record.id,
                    Alert.rule_name == "dlq_retry_exhausted",
                )
            )
        )
        if not existing.scalar_one_or_none():
            await self._create_alert(db, record)

    async def _create_alert(self, db, record: DeadLetterEvent) -> None:
        alert = Alert(
            id=new_id(),
            tenant_id=record.tenant_id,
            event_id=record.id,
            rule_name="dlq_retry_exhausted",
            severity="high",
            risk_score=75.0,
            description=(
                f"DLQ retry exhausted for event {record.id} "
                f"in queue {record.original_queue}: {record.error[:200]}"
            ),
            status="new",
            extra_data={
                "dlq_event_id": record.id,
                "original_queue": record.original_queue,
                "retry_count": record.retry_count,
                "max_retries": record.max_retries,
                "error": record.error[:500],
            },
        )
        db.add(alert)
        log.warning("Alert created for exhausted DLQ event %s", record.id)


dead_letter_worker = DeadLetterWorker()
