"""
Chaos: Pipeline Resilience
Scenario: Kill the pipeline mid-flight; assert events flow to DLQ and are retried.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

import pytest

from cybernova.database.postgres.models import DeadLetterEvent, Alert
from cybernova.pipeline.dead_letter_worker import DeadLetterWorker, RETRY_BASE_DELAY
from cybernova.pipeline.queue_manager import QueuedTask


def make_dlq_record(tenant_id="tenant-1", retry_count=0, max_retries=3,
                     failed_at=None, error="test error"):
    return DeadLetterEvent(
        id="dlq-001",
        tenant_id=tenant_id,
        original_queue="ingestion",
        payload='{"id": "t1", "queue": "ingestion", "payload": {"tenant_id": "t1"}, "priority": 0}',
        error=error,
        retry_count=retry_count,
        max_retries=max_retries,
        failed_at=failed_at or (datetime.now(timezone.utc) - timedelta(hours=1)),
    )


def make_scalars_result(records):
    m = MagicMock()
    m.scalars.return_value.all.return_value = records
    return m


def make_db_mock(records=None):
    db = AsyncMock()
    db.execute = AsyncMock(return_value=make_scalars_result(records or []))
    db.delete = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    return db


def make_get_db_session_mock(db):
    gen = MagicMock()
    gen.__aenter__.return_value = db
    gen.__aiter__.return_value = iter([db])
    return gen


@pytest.mark.asyncio
async def test_dlq_worker_retries_eligible_records():
    """DLQ worker picks up records with retry_count < max_retries and due for retry."""
    worker = DeadLetterWorker()
    record = make_dlq_record(retry_count=0)

    db = make_db_mock([record])
    gen = make_get_db_session_mock(db)

    with patch("cybernova.pipeline.dead_letter_worker.get_db_session",
               return_value=gen), \
         patch.object(worker, "_is_due_for_retry", return_value=True), \
         patch("cybernova.pipeline.dead_letter_worker.QueuedTask.from_json") as mock_deser, \
         patch("cybernova.pipeline.dead_letter_worker.queue_manager.enqueue",
               AsyncMock(return_value="ok")):

        task = MagicMock(spec=QueuedTask)
        task.queue = "cybernova:queue:ingestion"
        task.payload = {"tenant_id": "t1"}
        task.priority = MagicMock()
        task.metadata = {}
        mock_deser.return_value = task

        await worker._process_dlq()
        assert db.delete.called
        assert db.commit.called


@pytest.mark.asyncio
async def test_dlq_worker_creates_alert_when_retries_exhausted():
    """DLQ worker creates an Alert when retry_count >= max_retries and no alert exists."""
    worker = DeadLetterWorker()
    record = make_dlq_record(retry_count=3, max_retries=3)

    db = AsyncMock()

    def execute_side(*a, **kw):
        m = MagicMock()
        m.scalar_one_or_none.return_value = None
        return m

    db.execute = AsyncMock(side_effect=execute_side)
    db.add = MagicMock()

    with patch("cybernova.pipeline.dead_letter_worker.new_id", return_value="alert-001"):
        await worker._handle_exhausted(db, record)

        added_alert = db.add.call_args[0][0]
        assert isinstance(added_alert, Alert)
        assert added_alert.rule_name == "dlq_retry_exhausted"
        assert added_alert.severity == "high"
        assert added_alert.risk_score == 75.0
        assert added_alert.tenant_id == "tenant-1"


@pytest.mark.asyncio
async def test_dlq_worker_skips_already_alerted_records():
    """DLQ worker does not duplicate alerts for already-handled records."""
    worker = DeadLetterWorker()
    record = make_dlq_record(retry_count=3, max_retries=3)

    db = AsyncMock()
    m = MagicMock()
    m.scalar_one_or_none.return_value = MagicMock()
    db.execute = AsyncMock(return_value=m)
    db.add = MagicMock()

    await worker._handle_exhausted(db, record)
    assert not db.add.called


@pytest.mark.asyncio
async def test_exponential_backoff_delay():
    """Exponential backoff: 30, 60, 120 seconds for retries 0, 1, 2."""
    assert DeadLetterWorker._backoff_delay(0) == 30
    assert DeadLetterWorker._backoff_delay(1) == 60
    assert DeadLetterWorker._backoff_delay(2) == 120
    assert DeadLetterWorker._backoff_delay(3) == 240


@pytest.mark.asyncio
async def test_retry_skipped_when_not_due():
    """Records are not retried before their backoff delay has elapsed."""
    worker = DeadLetterWorker()
    now = datetime.now(timezone.utc)

    recent = make_dlq_record(failed_at=now)
    assert worker._is_due_for_retry(recent, now) is False

    old = make_dlq_record(failed_at=now - timedelta(seconds=60))
    assert worker._is_due_for_retry(old, now) is True


@pytest.mark.asyncio
async def test_dlq_worker_increments_retry_on_failure():
    """When re-enqueue fails, worker increments retry_count and updates failed_at."""
    worker = DeadLetterWorker()
    record = make_dlq_record(retry_count=1, max_retries=3)

    db = make_db_mock([record])
    gen = make_get_db_session_mock(db)

    with patch("cybernova.pipeline.dead_letter_worker.get_db_session",
               return_value=gen), \
         patch.object(worker, "_is_due_for_retry", return_value=True), \
         patch("cybernova.pipeline.dead_letter_worker.QueuedTask.from_json") as mock_deser, \
         patch("cybernova.pipeline.dead_letter_worker.queue_manager.enqueue",
               side_effect=Exception("queue full")):

        task = MagicMock(spec=QueuedTask)
        task.queue = "cybernova:queue:ingestion"
        task.payload = {"tenant_id": "t1"}
        task.priority = MagicMock()
        task.metadata = {}
        mock_deser.return_value = task

        await worker._process_dlq()

        assert record.retry_count == 2
        assert not db.delete.called
