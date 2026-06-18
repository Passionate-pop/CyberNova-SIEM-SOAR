"""Unit tests for pipeline/ module — targeting 80%+ coverage."""

from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest

from cybernova.pipeline.bus import (
    InMemoryBus, RedisStreamBus, KafkaBus, PipelineEnvelope,
    PartitionConfig, create_bus,
)


class TestPartitionConfig:
    def test_disabled(self):
        pc = PartitionConfig.disabled()
        assert pc.partition_by_tenant is False

    def test_from_settings(self):
        s = MagicMock()
        s.partition_by_tenant = True
        s.partition_mode = "key"
        s.kafka_partitions = 6
        pc = PartitionConfig.from_settings(s)
        assert pc.partition_by_tenant is True
        assert pc.partition_count == 6


class TestPipelineEnvelope:
    def test_partition_key(self):
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        assert e.partition_key() == "t1"

    def test_json_round_trip(self):
        e1 = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={"a": 1})
        raw = e1.to_json()
        e2 = PipelineEnvelope.from_json(raw)
        assert e2.event_id == e1.event_id
        assert e2.tenant_id == e1.tenant_id
        assert e2.payload == e1.payload

    def test_redis_round_trip(self):
        e1 = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={"a": 1})
        rd = e1.to_redis()
        assert rd["tenant_id"] == "t1"
        e2 = PipelineEnvelope.from_redis(rd)
        assert e2.event_id == e1.event_id

    def test_default_timestamp(self):
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        assert e.timestamp is not None


class TestInMemoryBus:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self):
        bus = InMemoryBus(partition_config=PartitionConfig.disabled())
        handler = AsyncMock()
        await bus.subscribe("test", handler)
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        result = await bus.publish("test", e)
        assert result is True
        await asyncio.sleep(0.3)
        handler.assert_called()

    @pytest.mark.asyncio
    async def test_publish_with_tenant_partition(self):
        bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        result = await bus.publish("test", e)
        assert result is True

    @pytest.mark.asyncio
    async def test_pending_count_with_partition(self):
        bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        await bus.publish("test", e)
        count = await bus.pending_count("test")
        assert count >= 1

    @pytest.mark.asyncio
    async def test_pending_count_no_partition(self):
        bus = InMemoryBus(partition_config=PartitionConfig.disabled())
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        await bus.publish("test", e)
        count = await bus.pending_count("test")
        assert count >= 1

    @pytest.mark.asyncio
    async def test_partition_count(self):
        bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        await bus.publish("test", e)
        counts = bus.partition_count("test")
        assert "t1" in counts

    @pytest.mark.asyncio
    async def test_partition_count_disabled(self):
        bus = InMemoryBus(partition_config=PartitionConfig.disabled())
        assert bus.partition_count("test") == {}

    @pytest.mark.asyncio
    async def test_ack_nack_noop(self):
        bus = InMemoryBus()
        await bus.ack("test", "m1")
        await bus.nack("test", "m1")

    @pytest.mark.asyncio
    async def test_queue_put_timeout_returns_false(self):
        bus = InMemoryBus()
        q = asyncio.Queue(maxsize=1)
        bus._queues["test"] = q
        with patch.object(q, "put", side_effect=asyncio.TimeoutError):
            e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
            result = await bus.publish("test", e)
            assert result is False

    @pytest.mark.asyncio
    async def test_drain_stops_consumers(self):
        bus = InMemoryBus()
        bus._running = True
        await bus.drain(timeout=1.0)
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_close(self):
        bus = InMemoryBus()
        handler = AsyncMock()
        await bus.subscribe("test", handler)
        await bus.close()
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_get_queue_creates_on_demand(self):
        bus = InMemoryBus()
        q = bus._get_queue("new_stage")
        assert q is not None
        assert q.maxsize == 10000

    @pytest.mark.asyncio
    async def test_get_queue_tenant_creates_on_demand(self):
        bus = InMemoryBus(partition_config=PartitionConfig(partition_by_tenant=True))
        q = bus._get_queue("test", "t1")
        assert q is not None


class TestRedisStreamBus:
    @pytest.mark.asyncio
    async def test_publish_no_redis_returns_false(self):
        bus = RedisStreamBus()
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        result = await bus.publish("test", e)
        assert result is False

    @pytest.mark.asyncio
    async def test_pending_count_no_redis(self):
        bus = RedisStreamBus()
        count = await bus.pending_count("test")
        assert count == 0

    @pytest.mark.asyncio
    async def test_close(self):
        bus = RedisStreamBus()
        handler = AsyncMock()
        await bus.subscribe("test", handler)
        await bus.close()
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_stream_key_without_partition(self):
        bus = RedisStreamBus()
        key = bus._stream_key("normalization")
        assert key == "cybernova:pipeline:normalization"

    @pytest.mark.asyncio
    async def test_stream_key_with_partition(self):
        bus = RedisStreamBus(partition_config=PartitionConfig(partition_by_tenant=True))
        key = bus._stream_key("normalization", "t1")
        assert key == "cybernova:pipeline:normalization:t1"

    @pytest.mark.asyncio
    async def test_ack_nack_noop(self):
        bus = RedisStreamBus()
        await bus.ack("test", "m1")
        await bus.nack("test", "m1")


class TestKafkaBus:
    @pytest.mark.asyncio
    async def test_publish_no_producer(self):
        bus = KafkaBus()
        e = PipelineEnvelope(event_id="e1", tenant_id="t1", stage="test", payload={})
        with patch.object(bus, "_ensure_producer", side_effect=Exception("no kafka")):
            result = await bus.publish("test", e)
            assert result is False

    @pytest.mark.asyncio
    async def test_pending_count(self):
        bus = KafkaBus()
        assert await bus.pending_count("test") == 0

    @pytest.mark.asyncio
    async def test_topic(self):
        bus = KafkaBus()
        assert bus._topic("normalization") == "cybernova.pipeline.normalization"

    @pytest.mark.asyncio
    async def test_partitioner_with_key(self):
        key = b"tenant-1"
        result = KafkaBus._partitioner(key, [0, 1, 2], [0, 1])
        assert result in (0, 1, 2)

    @pytest.mark.asyncio
    async def test_partitioner_no_key(self):
        result = KafkaBus._partitioner(None, [0, 1, 2], [0, 1])
        assert result in (0, 1, 2)

    @pytest.mark.asyncio
    async def test_sasl_config_empty(self):
        bus = KafkaBus()
        assert bus._sasl_config() == {}

    @pytest.mark.asyncio
    async def test_close(self):
        bus = KafkaBus()
        await bus.close()
        assert bus._running is False


class TestCreateBus:
    def test_no_settings_no_redis_returns_in_memory(self):
        bus = create_bus()
        assert isinstance(bus, InMemoryBus)

    def test_with_redis_returns_redis_stream(self):
        redis = MagicMock()
        bus = create_bus(redis=redis)
        assert isinstance(bus, RedisStreamBus)

    def test_with_kafka_settings(self):
        s = MagicMock()
        s.kafka_bootstrap_servers = "localhost:9092"
        s.kafka_security_protocol = "PLAINTEXT"
        s.kafka_sasl_mechanism = ""
        s.kafka_sasl_username = ""
        s.kafka_sasl_password = ""
        s.kafka_group_id = "test"
        s.kafka_max_batch_size = 100
        s.kafka_retry_backoff_ms = 500
        s.kafka_commit_interval_ms = 5000
        s.kafka_partitions = 3

        bus = create_bus(settings=s)
        assert isinstance(bus, KafkaBus)

    def test_partition_config_propagation(self):
        pc = PartitionConfig(partition_by_tenant=True, partition_count=6)
        bus = create_bus(partition_config=pc)
        assert isinstance(bus, InMemoryBus)
        assert bus._partition.partition_count == 6


import asyncio
