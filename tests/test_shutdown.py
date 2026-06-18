"""Tests for graceful shutdown — GracefulShutdown, bus drain, pipeline drain."""

import asyncio
import time

import pytest

from cybernova.lifecycle.shutdown import GracefulShutdown


# ── GracefulShutdown ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_remaining_decreases_over_time():
    gs = GracefulShutdown(timeout=1.0)
    gs.trigger()
    r1 = gs.remaining()
    await asyncio.sleep(0.3)
    r2 = gs.remaining()
    assert r2 < r1


@pytest.mark.asyncio
async def test_expired_true_after_timeout():
    gs = GracefulShutdown(timeout=0.1)
    gs.trigger()
    await asyncio.sleep(0.2)
    assert gs.expired


@pytest.mark.asyncio
async def test_expired_false_before_timeout():
    gs = GracefulShutdown(timeout=5.0)
    gs.trigger()
    assert not gs.expired


@pytest.mark.asyncio
async def test_remaining_zero_when_expired():
    gs = GracefulShutdown(timeout=0.01)
    gs.trigger()
    await asyncio.sleep(0.05)
    assert gs.remaining() == 0.0


def test_remaining_returns_timeout_before_trigger():
    gs = GracefulShutdown(timeout=10.0)
    assert gs.remaining() == 10.0


@pytest.mark.asyncio
async def test_elapsed_increases():
    gs = GracefulShutdown(timeout=5.0)
    gs.trigger()
    before = gs.elapsed
    await asyncio.sleep(0.2)
    after = gs.elapsed
    assert after > before


@pytest.mark.asyncio
async def test_elapsed_zero_before_trigger():
    gs = GracefulShutdown(timeout=5.0)
    assert gs.elapsed == 0.0


@pytest.mark.asyncio
async def test_wait_triggered_unblocks_on_trigger():
    gs = GracefulShutdown(timeout=5.0)
    async def trigger_soon():
        await asyncio.sleep(0.05)
        gs.trigger()
    start = time.monotonic()
    async with asyncio.TaskGroup() as tg:
        tg.create_task(trigger_soon())
        await gs.wait_triggered()
    elapsed = time.monotonic() - start
    assert elapsed < 1.0


@pytest.mark.asyncio
async def test_drain_with_timeout_completes_fast_coro():
    gs = GracefulShutdown(timeout=5.0)
    gs.trigger()

    async def fast():
        return 42

    await gs.drain_with_timeout("fast", fast())
    assert gs.remaining() > 0


@pytest.mark.asyncio
async def test_drain_with_timeout_hits_timeout():
    gs = GracefulShutdown(timeout=0.3)
    gs.trigger()

    async def slow():
        await asyncio.sleep(10)

    await gs.drain_with_timeout("slow", slow())
    assert gs.expired


@pytest.mark.asyncio
async def test_async_context_manager_triggers_on_entry():
    async with GracefulShutdown(timeout=5.0) as gs:
        assert gs.elapsed >= 0
        assert gs.remaining() > 0


# ── EventBus drain ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_in_memory_bus_drain_drains_queues():
    from cybernova.pipeline.bus import InMemoryBus, PipelineEnvelope, PartitionConfig

    bus = InMemoryBus(partition_config=PartitionConfig.disabled())
    bus._running = True

    envelope = PipelineEnvelope(
        event_id="e1", tenant_id="t1", stage="test",
        payload={"msg": "hello"},
    )
    q = bus._get_queue("test")
    await q.put(envelope)

    drained = await bus.drain(timeout=2.0)
    assert drained >= 1
    assert q.qsize() == 0


@pytest.mark.asyncio
async def test_in_memory_bus_drain_with_partitioning():
    from cybernova.pipeline.bus import InMemoryBus, PipelineEnvelope, PartitionConfig

    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    bus._running = True

    for tid in ("t1", "t2"):
        envelope = PipelineEnvelope(
            event_id=f"e-{tid}", tenant_id=tid, stage="test",
            payload={"msg": tid},
        )
        q = bus._get_queue("test", tenant_id=tid)
        await q.put(envelope)

    drained = await bus.drain(timeout=2.0)
    assert drained >= 2

    for tid in ("t1", "t2"):
        q = bus._get_queue("test", tenant_id=tid)
        assert q.qsize() == 0


@pytest.mark.asyncio
async def test_bus_drain_empty_returns_zero():
    from cybernova.pipeline.bus import InMemoryBus, PartitionConfig

    bus = InMemoryBus(partition_config=PartitionConfig.disabled())
    bus._running = True
    drained = await bus.drain(timeout=1.0)
    assert drained == 0


@pytest.mark.asyncio
async def test_redis_stream_bus_drain_cancels_consumers():
    from cybernova.pipeline.bus import RedisStreamBus

    bus = RedisStreamBus()
    bus._running = True

    async def dummy_handler(env):
        pass

    await bus.subscribe("test", dummy_handler)
    assert len(bus._consumers) == 1

    drained = await bus.drain(timeout=1.0)
    assert bus._running is False
    assert isinstance(drained, int)


@pytest.mark.asyncio
async def test_kafka_bus_drain_sets_running_false():
    from cybernova.pipeline.bus import KafkaBus

    bus = KafkaBus()
    bus._running = True
    drained = await bus.drain(timeout=1.0)
    assert bus._running is False
    assert isinstance(drained, int)


# ── UnifiedPipeline drain ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unified_pipeline_drain_no_bus():
    from cybernova.pipeline.unified_pipeline import UnifiedPipeline

    pipe = UnifiedPipeline()
    pipe._running = True
    drained = await pipe.drain(timeout=1.0)
    assert drained == 0
    assert pipe._running is False


# ── Settings ──────────────────────────────────────────────────────────────────


def test_shutdown_grace_period_default():
    from cybernova.config.settings import Settings

    s = Settings()
    assert s.shutdown_grace_period == 30


# ── PipelineWorker drain ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_worker_drain_clears_batches():
    from cybernova.streaming.pipeline_worker import PipelineWorker
    from unittest.mock import AsyncMock

    redis = AsyncMock()
    worker = PipelineWorker(redis)
    worker._running = True

    worker._raw_batch.append({"id": "r1", "tenant_id": "t1", "source": "test", "source_type": "json", "payload": {}})
    worker._normalized_batch.append({"id": "n1", "tenant_id": "t1", "event_type": "test", "severity": "low"})
    worker._alert_batch.append({"id": "a1", "tenant_id": "t1", "rule_name": "test", "severity": "low", "risk_score": 10, "description": "test", "status": "new", "extra_data": {}})

    drained = await worker.drain(timeout=2.0)
    assert drained >= 2
    assert not worker._raw_batch
    assert not worker._normalized_batch
    assert not worker._alert_batch


@pytest.mark.asyncio
async def test_pipeline_worker_drain_sets_running_false():
    from cybernova.streaming.pipeline_worker import PipelineWorker
    from unittest.mock import AsyncMock

    redis = AsyncMock()
    worker = PipelineWorker(redis)
    worker._running = True
    await worker.drain(timeout=1.0)
    assert worker._running is False
