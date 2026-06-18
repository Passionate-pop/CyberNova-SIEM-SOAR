"""Tests for event batching — BatchWriter, bulk_insert, pipeline batch accumulation."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.database.batch_writer import BatchWriter
from cybernova.database.repository.base import BaseRepository
from cybernova.database.postgres.models import Alert


# ── BatchWriter ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batch_writer_adds_raw_event():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1", batch_size=10)
    writer.add_raw_event(id="e1", source="test", source_type="json", payload={})
    assert writer.total_pending == 1


@pytest.mark.asyncio
async def test_batch_writer_adds_normalized_event():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1", batch_size=10)
    writer.add_normalized_event(id="e1", event_type="suricata", severity="high")
    assert writer.total_pending == 1


@pytest.mark.asyncio
async def test_batch_writer_adds_alert():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1", batch_size=10)
    writer.add_alert(id="a1", rule_name="test_rule", severity="critical")
    assert writer.total_pending == 1


@pytest.mark.asyncio
async def test_batch_writer_should_flush():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1", batch_size=3)
    writer.add_raw_event(id="e1", source="test", payload={})
    writer.add_raw_event(id="e2", source="test", payload={})
    assert writer.should_flush() is False
    writer.add_raw_event(id="e3", source="test", payload={})
    assert writer.should_flush() is True


@pytest.mark.asyncio
async def test_batch_writer_flush_clears_pending():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    writer = BatchWriter(db, "tenant-1", batch_size=10)
    writer.add_raw_event(id="e1", tenant_id="tenant-1", source="test", payload={})
    count = await writer.flush()
    assert count == 1
    assert writer.total_pending == 0


@pytest.mark.asyncio
async def test_batch_writer_stats():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1", batch_size=10)
    writer.add_raw_event(id="e1", tenant_id="tenant-1", source="test", payload={})
    stats = writer.stats
    assert stats["total_added"] == 1
    assert stats["pending"] == 1
    assert stats["batch_size"] == 10


@pytest.mark.asyncio
async def test_batch_writer_flush_zero_when_empty():
    db = MagicMock()
    writer = BatchWriter(db, "tenant-1")
    count = await writer.flush()
    assert count == 0


@pytest.mark.asyncio
async def test_batch_writer_flush_calls_db_add():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    writer = BatchWriter(db, "tenant-1", batch_size=5)
    writer.add_raw_event(id="e1", tenant_id="tenant-1", source="test", payload={})
    writer.add_normalized_event(id="e1", tenant_id="tenant-1", event_type="suricata", severity="high")
    count = await writer.flush()
    assert count == 2
    assert db.add.call_count == 2


# ── BaseRepository.bulk_insert ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bulk_insert_adds_tenant_id():
    db = AsyncMock()
    db.execute = AsyncMock()
    repo = BaseRepository(Alert, db, "tenant-42")
    await repo.bulk_insert([{"id": "a1", "rule_name": "test", "severity": "high"}])
    assert db.execute.called


@pytest.mark.asyncio
async def test_bulk_insert_empty_list_does_nothing():
    db = AsyncMock()
    repo = BaseRepository(Alert, db, "tenant-42")
    await repo.bulk_insert([])
    db.execute.assert_not_called()


# ── SOARStage batching ──────────────────────────────────────────────────────


def test_soar_stage_initializes_batch_lists():
    from cybernova.pipeline.stages.soar import SOARStage
    stage = SOARStage()
    assert stage._soar_commands == []
    assert stage._soar_blocked_ips == []


@pytest.mark.asyncio
async def test_soar_stage_execute_action_appends_to_batch():
    from cybernova.pipeline.stages.soar import SOARStage
    stage = SOARStage()
    await stage._execute_action({"action": "isolate", "target": "dev-1", "tenant_id": "t1", "alert_id": "a1"})
    assert len(stage._soar_commands) == 1
    assert stage._soar_commands[0]["device_id"] == "dev-1"

    await stage._execute_action({"action": "block_ip", "target": "1.2.3.4", "tenant_id": "t1", "alert_id": "a2"})
    assert len(stage._soar_blocked_ips) == 1
    assert stage._soar_blocked_ips[0]["ip_address"] == "1.2.3.4"
