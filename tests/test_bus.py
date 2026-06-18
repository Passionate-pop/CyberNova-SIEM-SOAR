"""Tests for pipeline event bus partitioning — verifies tenant-level isolation."""

import pytest
from uuid import uuid4

from cybernova.pipeline.bus import (
    InMemoryBus, PartitionConfig, PipelineEnvelope,
)


def make_envelope(tenant_id: str, stage: str = "normalization") -> PipelineEnvelope:
    return PipelineEnvelope(
        event_id=str(uuid4()),
        tenant_id=tenant_id,
        stage=stage,
        payload={"test": True},
    )


# ── PartitionConfig ──────────────────────────────────────────────────────────


def test_partition_config_disabled():
    cfg = PartitionConfig.disabled()
    assert cfg.partition_by_tenant is False


def test_partition_config_default_enabled():
    cfg = PartitionConfig()
    assert cfg.partition_by_tenant is True
    assert cfg.partition_count == 3
    assert cfg.partition_mode == "key"


# ── PipelineEnvelope partitioning ────────────────────────────────────────────


def test_envelope_partition_key_returns_tenant_id():
    env = make_envelope("tenant-42")
    assert env.partition_key() == "tenant-42"


def test_envelope_to_redis_includes_tenant_id():
    env = make_envelope("tenant-alpha")
    redis_data = env.to_redis()
    assert redis_data["tenant_id"] == "tenant-alpha"
    assert "data" in redis_data


# ── InMemoryBus — no partitioning ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inmemory_no_partition_all_share_queue():
    bus = InMemoryBus(partition_config=PartitionConfig.disabled())
    await bus.publish("detection", make_envelope("tenant-a"))
    await bus.publish("detection", make_envelope("tenant-b"))
    assert bus._queues["detection"].qsize() == 2


@pytest.mark.asyncio
async def test_inmemory_no_partition_stage_isolation():
    bus = InMemoryBus(partition_config=PartitionConfig.disabled())
    await bus.publish("stage-1", make_envelope("t1"))
    await bus.publish("stage-2", make_envelope("t1"))
    assert bus._queues["stage-1"].qsize() == 1
    assert bus._queues["stage-2"].qsize() == 1


# ── InMemoryBus — with partitioning ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_inmemory_partition_isolates_tenants():
    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    await bus.publish("detection", make_envelope("tenant-a"))
    await bus.publish("detection", make_envelope("tenant-b"))
    await bus.publish("detection", make_envelope("tenant-a"))
    assert bus._tenant_queues["detection:tenant-a"].qsize() == 2
    assert bus._tenant_queues["detection:tenant-b"].qsize() == 1


@pytest.mark.asyncio
async def test_inmemory_partition_pending_count():
    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    await bus.publish("detection", make_envelope("t1"))
    await bus.publish("detection", make_envelope("t2"))
    await bus.publish("detection", make_envelope("t1"))
    assert await bus.pending_count("detection") == 3


@pytest.mark.asyncio
async def test_inmemory_partition_count_report():
    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    await bus.publish("detection", make_envelope("t1"))
    await bus.publish("detection", make_envelope("t2"))
    await bus.publish("detection", make_envelope("t1"))
    counts = bus.partition_count("detection")
    assert counts["t1"] == 2
    assert counts["t2"] == 1


@pytest.mark.asyncio
async def test_inmemory_partition_no_cross_tenant_leak():
    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    await bus.publish("enrichment", make_envelope("t1"))
    await bus.publish("detection", make_envelope("t1"))
    assert "enrichment:t1" in bus._tenant_queues
    assert "detection:t1" in bus._tenant_queues


# ── InMemoryBus — consumer dispatch (integration) ────────────────────────────


@pytest.mark.asyncio
async def test_inmemory_partition_dispatches_to_handler():
    bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
    received = []

    async def handler(envelope):
        received.append(envelope.tenant_id)

    await bus.subscribe("test-stage", handler)
    await bus.publish("test-stage", make_envelope("t1"))
    await bus.publish("test-stage", make_envelope("t2"))
    await bus.publish("test-stage", make_envelope("t1"))

    import asyncio
    await asyncio.sleep(0.5)

    assert len(received) == 3
    assert received.count("t1") == 2
    assert received.count("t2") == 1
    await bus.close()


# ── PipelineEnvelope serialization ───────────────────────────────────────────


def test_envelope_json_round_trip():
    env = make_envelope("tenant-x")
    json_str = env.to_json()
    restored = PipelineEnvelope.from_json(json_str)
    assert restored.tenant_id == "tenant-x"
    assert restored.event_id == env.event_id
    assert restored.partition_key() == "tenant-x"


def test_envelope_redis_round_trip():
    env = make_envelope("tenant-redis")
    redis_data = env.to_redis()
    restored = PipelineEnvelope.from_redis(redis_data)
    assert restored.tenant_id == "tenant-redis"
