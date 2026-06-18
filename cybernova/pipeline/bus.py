"""
CyberNova — Pipeline Event Bus
Abstract interface for inter-stage communication.
Supports Kafka/Redpanda (primary), Redis Streams, and in-memory (fallback).

Partitioning: when partition_by_tenant is enabled, each bus routes events
by tenant_id so each tenant's events process independently:
  - KafkaBus: tenant_id as the Kafka message key (same partition per tenant)
  - RedisStreamBus: per-tenant stream keys ({prefix}:{stage}:{tenant_id})
  - InMemoryBus: per-tenant asyncio.Queue instances
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

log = logging.getLogger("cybernova.pipeline.bus")


@dataclass
class PartitionConfig:
    partition_by_tenant: bool = True
    partition_mode: str = "key"
    partition_count: int = 3

    @classmethod
    def from_settings(cls, settings) -> "PartitionConfig":
        return cls(
            partition_by_tenant=getattr(settings, "partition_by_tenant", True),
            partition_mode=getattr(settings, "partition_mode", "key"),
            partition_count=getattr(settings, "kafka_partitions", 3),
        )

    @classmethod
    def disabled(cls) -> "PartitionConfig":
        return cls(partition_by_tenant=False)


@dataclass
class PipelineEnvelope:
    """Event envelope passed between pipeline stages."""
    event_id: str
    tenant_id: str
    stage: str
    payload: Dict[str, Any]
    previous_stage: Optional[str] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def partition_key(self) -> str:
        return self.tenant_id

    def to_json(self) -> str:
        return json.dumps({
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "stage": self.stage,
            "payload": self.payload,
            "previous_stage": self.previous_stage,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timestamp": self.timestamp,
        })

    @classmethod
    def from_json(cls, raw: str) -> "PipelineEnvelope":
        return cls(**json.loads(raw))

    def to_redis(self) -> dict:
        return {"data": self.to_json(), "tenant_id": self.tenant_id}

    @classmethod
    def from_redis(cls, raw: dict) -> "PipelineEnvelope":
        return cls.from_json(raw["data"])


class EventBus(ABC):
    @abstractmethod
    async def publish(self, stage: str, envelope: PipelineEnvelope) -> bool:
        ...
    @abstractmethod
    async def subscribe(self, stage: str, handler: Callable, consumer_group: str = "") -> None:
        ...
    @abstractmethod
    async def ack(self, stage: str, message_id: str) -> None:
        ...
    @abstractmethod
    async def nack(self, stage: str, message_id: str) -> None:
        ...
    @abstractmethod
    async def pending_count(self, stage: str) -> int:
        ...
    @abstractmethod
    async def drain(self, timeout: float = 5.0) -> int:
        """Stop accepting new work and complete in-flight messages. Returns count of drained items."""
        ...
    @abstractmethod
    async def close(self) -> None:
        ...


class InMemoryBus(EventBus):
    """In-memory event bus. With partitioning, each tenant gets its own queue."""

    def __init__(self, partition_config: Optional[PartitionConfig] = None):
        self._partition = partition_config or PartitionConfig.disabled()
        self._queues: Dict[str, asyncio.Queue] = {}
        self._tenant_queues: Dict[str, Dict[str, asyncio.Queue]] = {}
        self._handlers: Dict[str, List[Callable]] = {}
        self._consumers: Dict[str, asyncio.Task] = {}
        self._running = False

    def _get_queue(self, stage: str, tenant_id: str = "") -> asyncio.Queue:
        if self._partition.partition_by_tenant and tenant_id:
            key = f"{stage}:{tenant_id}"
            queues = self._tenant_queues
        else:
            key = stage
            queues = self._queues
        if key not in queues:
            queues[key] = asyncio.Queue(maxsize=10000)
        return queues[key]

    async def publish(self, stage: str, envelope: PipelineEnvelope) -> bool:
        try:
            q = self._get_queue(stage, envelope.tenant_id if self._partition.partition_by_tenant else "")
            await asyncio.wait_for(q.put(envelope), timeout=5.0)
            return True
        except asyncio.TimeoutError:
            log.warning("InMemoryBus: queue full, dropping event %s", envelope.event_id)
            return False

    async def subscribe(self, stage: str, handler: Callable, consumer_group: str = "") -> None:
        if stage not in self._handlers:
            self._handlers[stage] = []
        self._handlers[stage].append(handler)
        if stage not in self._consumers:
            self._consumers[stage] = asyncio.create_task(self._consumer_loop(stage))

    async def _consumer_loop(self, stage: str) -> None:
        self._running = True
        while self._running:
            try:
                if self._partition.partition_by_tenant:
                    await self._drain_tenant_queues(stage)
                else:
                    await self._drain_flat_queue(stage)
            except asyncio.CancelledError:
                break

    async def _drain_flat_queue(self, stage: str) -> None:
        q = self._queues.get(stage)
        if not q:
            await asyncio.sleep(0.1)
            return
        try:
            envelope = await asyncio.wait_for(q.get(), timeout=1.0)
            await self._dispatch(stage, envelope)
        except asyncio.TimeoutError:
            pass

    async def _drain_tenant_queues(self, stage: str) -> None:
        prefix = f"{stage}:"
        candidates = [k for k in self._tenant_queues if k.startswith(prefix)]
        for key in candidates:
            q = self._tenant_queues[key]
            if q.empty():
                continue
            try:
                envelope = await asyncio.wait_for(q.get(), timeout=1.0)
                await self._dispatch(stage, envelope)
                return
            except asyncio.TimeoutError:
                continue
        await asyncio.sleep(0.1)

    async def _dispatch(self, stage: str, envelope: PipelineEnvelope) -> None:
        for handler in self._handlers.get(stage, []):
            try:
                await handler(envelope)
            except Exception as e:
                log.error("InMemoryBus: handler failed for stage %s: %s", stage, e)

    async def ack(self, stage: str, message_id: str) -> None:
        pass
    async def nack(self, stage: str, message_id: str) -> None:
        pass

    async def pending_count(self, stage: str) -> int:
        if self._partition.partition_by_tenant:
            prefix = f"{stage}:"
            return sum(q.qsize() for k, q in self._tenant_queues.items() if k.startswith(prefix))
        q = self._queues.get(stage)
        return q.qsize() if q else 0

    def partition_count(self, stage: str) -> Dict[str, int]:
        if not self._partition.partition_by_tenant:
            return {}
        prefix = f"{stage}:"
        return {k.split(":", 1)[1]: q.qsize() for k, q in self._tenant_queues.items() if k.startswith(prefix)}

    async def drain(self, timeout: float = 5.0) -> int:
        self._running = False
        deadline = time.monotonic() + timeout
        drained = 0
        while time.monotonic() < deadline:
            for stage, q in self._queues.items():
                while not q.empty():
                    try:
                        envelope = q.get_nowait()
                        await self._dispatch(stage, envelope)
                        drained += 1
                    except asyncio.QueueEmpty:
                        break
            for key, q in self._tenant_queues.items():
                while not q.empty():
                    try:
                        envelope = q.get_nowait()
                        stage = key.split(":", 1)[0] if ":" in key else key
                        await self._dispatch(stage, envelope)
                        drained += 1
                    except asyncio.QueueEmpty:
                        break
            total = sum(q.qsize() for q in self._queues.values())
            total += sum(q.qsize() for q in self._tenant_queues.values())
            if total == 0:
                break
            await asyncio.sleep(0.05)
        return drained

    async def close(self) -> None:
        self._running = False
        for t in self._consumers.values():
            t.cancel()
        if self._consumers:
            await asyncio.gather(*self._consumers.values(), return_exceptions=True)


class RedisStreamBus(EventBus):
    """Redis Streams-backed event bus. With partitioning, per-tenant streams."""

    def __init__(self, redis=None, partition_config: Optional[PartitionConfig] = None):
        self._redis = redis
        self._partition = partition_config or PartitionConfig.disabled()
        self._consumers: Dict[str, asyncio.Task] = {}
        self._handlers: Dict[str, List[Callable]] = {}
        self._stream_prefix = "cybernova:pipeline"
        self._running = False

    def _stream_key(self, stage: str, tenant_id: str = "") -> str:
        base = f"{self._stream_prefix}:{stage}"
        if self._partition.partition_by_tenant and tenant_id:
            return f"{base}:{tenant_id}"
        return base

    async def publish(self, stage: str, envelope: PipelineEnvelope) -> bool:
        if not self._redis:
            return False
        try:
            stream = self._stream_key(stage, envelope.tenant_id if self._partition.partition_by_tenant else "")
            await self._redis.xadd(stream, envelope.to_redis(), maxlen=100000)
            return True
        except Exception as e:
            log.warning("RedisStreamBus: publish to %s failed: %s", stage, e)
            return False

    async def subscribe(self, stage: str, handler: Callable, consumer_group: str = "pipeline") -> None:
        if stage not in self._handlers:
            self._handlers[stage] = []
        self._handlers[stage].append(handler)
        ck = f"{stage}:{consumer_group}"
        if ck not in self._consumers:
            self._consumers[ck] = asyncio.create_task(self._consumer_loop(stage, consumer_group))

    async def _consumer_loop(self, stage: str, group: str) -> None:
        self._running = True
        consumer = f"pipeline-{stage}-{uuid4().hex[:6]}"

        if not self._partition.partition_by_tenant:
            stream = self._stream_key(stage)
            try:
                await self._redis.xgroup_create(stream, group, id="0", mkstream=True)
            except Exception as e:
                log.debug("RedisStreamBus: xgroup_create for %s: %s", stream, e)
            while self._running:
                try:
                    msgs = await self._redis.xreadgroup(group, consumer, {stream: ">"}, count=10, block=2000)
                    if msgs:
                        for _, mlist in msgs:
                            for mid, mdata in mlist:
                                await self._handle(stage, group, stream, mid, mdata)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    log.error("RedisStreamBus: consumer error: %s", e)
                    await asyncio.sleep(1)
            return

        known_streams: Dict[str, str] = {}
        while self._running:
            try:
                cursor = 0
                pattern = f"{self._stream_prefix}:{stage}:*"
                cursor, keys = await self._redis.scan(cursor=cursor, match=pattern, count=50)
                for key in keys:
                    ks = key if isinstance(key, str) else key.decode("utf-8")
                    if ks not in known_streams:
                        try:
                            await self._redis.xgroup_create(ks, group, id="0", mkstream=True)
                        except Exception as e:
                            log.debug("RedisStreamBus: xgroup_create tenant %s: %s", ks, e)
                        known_streams[ks] = group
                if known_streams:
                    read_map = {s: ">" for s in known_streams}
                    results = await self._redis.xreadgroup(group, consumer, read_map, count=10, block=2000)
                    if results:
                        for stream, mlist in results:
                            for mid, mdata in mlist:
                                await self._handle(stage, group, stream, mid, mdata)
                else:
                    # No tenant streams exist yet — avoid tight SCAN loop
                    await asyncio.sleep(2)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("RedisStreamBus: tenant consumer error: %s", e)
                await asyncio.sleep(1)

    async def _handle(self, stage: str, group: str, stream: str, msg_id: str, msg_data: dict) -> None:
        try:
            envelope = PipelineEnvelope.from_redis(msg_data)
            for h in self._handlers.get(stage, []):
                await h(envelope)
            await self._redis.xack(stream, group, msg_id)
        except Exception:
            log.exception("RedisStreamBus: handler failed %s/%s", stage, msg_id)
            try:
                await self._redis.xack(stream, group, msg_id)
            except Exception as e:
                log.debug("RedisStreamBus: xack fallback failed %s/%s: %s", stage, msg_id, e)

    async def ack(self, stage: str, message_id: str) -> None:
        pass
    async def nack(self, stage: str, message_id: str) -> None:
        pass

    async def pending_count(self, stage: str) -> int:
        if not self._redis:
            return 0
        if self._partition.partition_by_tenant:
            total = 0
            cursor = 0
            pattern = f"{self._stream_prefix}:{stage}:*"
            try:
                cursor, keys = await self._redis.scan(cursor=cursor, match=pattern, count=50)
                for key in keys:
                    ks = key if isinstance(key, str) else key.decode("utf-8")
                    try:
                        info = await self._redis.xpending(ks, "pipeline")
                        total += info.get("pending", 0) if isinstance(info, dict) else 0
                    except Exception as e:
                        log.debug("RedisStreamBus: xpending scan error: %s", e)
            except Exception as e:
                log.debug("RedisStreamBus: pending_count outer error: %s", e)
            return total
        try:
            info = await self._redis.xpending(self._stream_key(stage), "pipeline")
            return info.get("pending", 0) if isinstance(info, dict) else 0
        except Exception:
            return 0

    async def drain(self, timeout: float = 5.0) -> int:
        self._running = False
        deadline = time.monotonic() + timeout
        drained = 0
        while time.monotonic() < deadline:
            total_pending = 0
            for stage in self._handlers:
                try:
                    total_pending += await self.pending_count(stage)
                except Exception as e:
                    log.debug("RedisStreamBus: drain pending_count error for %s: %s", stage, e)
            if total_pending == 0:
                break
            await asyncio.sleep(0.5)
        return drained

    async def close(self) -> None:
        self._running = False
        for t in self._consumers.values():
            t.cancel()
        if self._consumers:
            await asyncio.gather(*self._consumers.values(), return_exceptions=True)


class KafkaBus(EventBus):
    """Kafka-backed event bus. With partitioning, tenant_id is the message key."""

    def __init__(self, bootstrap_servers: str = "localhost:9092",
                 partition_config: Optional[PartitionConfig] = None, **kwargs):
        self._bootstrap_servers = bootstrap_servers
        self._partition = partition_config or PartitionConfig.disabled()
        self._security_protocol = kwargs.get("security_protocol", "PLAINTEXT")
        self._sasl_mechanism = kwargs.get("sasl_mechanism", "")
        self._sasl_username = kwargs.get("sasl_username", "")
        self._sasl_password = kwargs.get("sasl_password", "")
        self._group_id = kwargs.get("group_id", "cybernova-pipeline")
        self._max_batch_size = kwargs.get("max_batch_size", 1000)
        self._retry_backoff_ms = kwargs.get("retry_backoff_ms", 500)
        self._commit_interval_ms = kwargs.get("commit_interval_ms", 5000)
        self._topic_prefix = "cybernova.pipeline"
        self._producer = None
        self._consumers: Dict[str, Any] = {}
        self._handlers: Dict[str, List[Callable]] = {}
        self._consumer_tasks: Dict[str, asyncio.Task] = {}
        self._running = False

    def _topic(self, stage: str) -> str:
        return f"{self._topic_prefix}.{stage}"

    def _sasl_config(self) -> dict:
        if not self._sasl_mechanism:
            return {}
        return {
            "security_protocol": self._security_protocol,
            "sasl_mechanism": self._sasl_mechanism,
            "sasl_plain_username": self._sasl_username,
            "sasl_plain_password": self._sasl_password,
        }

    @staticmethod
    def _partitioner(key: bytes, all_partitions: List[int], available: List[int]) -> int:
        if key is None:
            import random  # nosec - non-security partition selection
            return random.choice(all_partitions)  # nosec - non-security partition selection
        return hash(key) % len(all_partitions)

    async def _ensure_producer(self) -> Any:
        if self._producer is not None:
            return self._producer
        try:
            from aiokafka import AIOKafkaProducer
            kw = dict(
                bootstrap_servers=self._bootstrap_servers,
                max_batch_size=self._max_batch_size,
                retry_backoff_ms=self._retry_backoff_ms,
                **self._sasl_config(),
            )
            if self._partition.partition_by_tenant:
                kw["partitioner"] = self._partitioner
            self._producer = AIOKafkaProducer(**kw)
            await self._producer.start()
            log.info("KafkaBus: producer connected (partitioning=%s)", self._partition.partition_by_tenant)
        except ImportError:
            log.error("KafkaBus: aiokafka not installed")
            raise
        except Exception as e:
            log.error("KafkaBus: producer start failed: %s", e)
            raise
        return self._producer

    async def publish(self, stage: str, envelope: PipelineEnvelope) -> bool:
        try:
            producer = await self._ensure_producer()
            topic = self._topic(stage)
            value = envelope.to_json().encode("utf-8")
            if self._partition.partition_by_tenant:
                key = envelope.partition_key().encode("utf-8")
                await producer.send_and_wait(topic, value, key=key)
            else:
                await producer.send_and_wait(topic, value)
            return True
        except Exception as e:
            log.warning("KafkaBus: publish to %s failed: %s", stage, e)
            return False

    async def subscribe(self, stage: str, handler: Callable, consumer_group: str = "") -> None:
        group = consumer_group or self._group_id
        if stage not in self._handlers:
            self._handlers[stage] = []
        self._handlers[stage].append(handler)
        ck = f"{stage}:{group}"
        if ck not in self._consumer_tasks:
            self._consumer_tasks[ck] = asyncio.create_task(self._consumer_loop(stage, group))

    async def _consumer_loop(self, stage: str, group: str) -> None:
        self._running = True
        consumer = None
        try:
            from aiokafka import AIOKafkaConsumer
            consumer = AIOKafkaConsumer(
                self._topic(stage),
                bootstrap_servers=self._bootstrap_servers,
                group_id=group,
                enable_auto_commit=True,
                auto_commit_interval_ms=self._commit_interval_ms,
                max_poll_records=10,
                **self._sasl_config(),
            )
            await consumer.start()
            log.info("KafkaBus: consumer started for %s", stage)
        except ImportError:
            log.error("KafkaBus: aiokafka not installed")
            return
        except Exception as e:
            log.error("KafkaBus: consumer start failed for %s: %s", stage, e)
            return
        try:
            while self._running:
                try:
                    msgs = await consumer.getmany(timeout_ms=2000, max_records=10)
                    for _, messages in msgs.items():
                        for msg in messages:
                            try:
                                envelope = PipelineEnvelope.from_json(msg.value.decode("utf-8"))
                                for h in self._handlers.get(stage, []):
                                    await h(envelope)
                            except Exception as e:
                                log.error("KafkaBus: handler failed for %s: %s", stage, e)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            pass
        finally:
            if consumer:
                await consumer.stop()

    async def ack(self, stage: str, message_id: str) -> None:
        pass
    async def nack(self, stage: str, message_id: str) -> None:
        pass
    async def pending_count(self, stage: str) -> int:
        return 0

    async def drain(self, timeout: float = 5.0) -> int:
        self._running = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._consumer_tasks:
                break
            all_done = all(t.done() for t in self._consumer_tasks.values())
            if all_done:
                break
            await asyncio.sleep(0.1)
        return 0

    async def close(self) -> None:
        self._running = False
        for t in self._consumer_tasks.values():
            t.cancel()
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks.values(), return_exceptions=True)
        if self._producer:
            try:
                await self._producer.stop()
            except Exception as e:
                log.warning("KafkaBus: producer stop error: %s", e)


def create_bus(redis=None, settings=None,
               partition_config: Optional[PartitionConfig] = None) -> EventBus:
    if partition_config is None and settings:
        partition_config = PartitionConfig.from_settings(settings)
    if partition_config is None:
        partition_config = PartitionConfig.disabled()

    if settings:
        ks = getattr(settings, "kafka_bootstrap_servers", "")
        if ks:
            try:
                bus = KafkaBus(
                    bootstrap_servers=ks,
                    partition_config=partition_config,
                    security_protocol=getattr(settings, "kafka_security_protocol", "PLAINTEXT"),
                    sasl_mechanism=getattr(settings, "kafka_sasl_mechanism", ""),
                    sasl_username=getattr(settings, "kafka_sasl_username", ""),
                    sasl_password=getattr(settings, "kafka_sasl_password", ""),
                    group_id=getattr(settings, "kafka_group_id", "cybernova-pipeline"),
                    max_batch_size=getattr(settings, "kafka_max_batch_size", 1000),
                    retry_backoff_ms=getattr(settings, "kafka_retry_backoff_ms", 500),
                    commit_interval_ms=getattr(settings, "kafka_commit_interval_ms", 5000),
                )
                log.info("KafkaBus selected (partitioning=%s)", partition_config.partition_by_tenant)
                return bus
            except Exception as e:
                log.warning("KafkaBus failed, fallback: %s", e)
    if redis:
        return RedisStreamBus(redis, partition_config=partition_config)
    return InMemoryBus(partition_config=partition_config)
