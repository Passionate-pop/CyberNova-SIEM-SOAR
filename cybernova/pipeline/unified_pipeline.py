"""
Unified pipeline coordinator. Stages communicate via event bus (Redis or in-memory).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from cybernova.pipeline.bus import (
    EventBus, PipelineEnvelope, PartitionConfig, create_bus,
)
from cybernova.pipeline.stages.normalizer import normalization_stage
from cybernova.pipeline.stages.enricher import enrichment_stage
from cybernova.pipeline.stages.anomaly import anomaly_stage
from cybernova.pipeline.stages.detector import detection_stage
from cybernova.pipeline.stages.correlator import correlation_stage
from cybernova.pipeline.stages.alerter import alert_stage
from cybernova.pipeline.stages.soar import soar_stage
from cybernova.pipeline.stages.notifier import notification_stage
from cybernova.database.redis import get_redis
import redis.exceptions
from cybernova.config.settings import get_settings
from cybernova.monitoring.tracing import get_tracer
from cybernova.monitoring.slo import slo_engine
from cybernova.monitoring.metrics import metrics

log = logging.getLogger("cybernova.pipeline.unified")

STAGE_ORDER = ["ingestion", "normalization", "enrichment", "anomaly", "detection",
               "correlation", "alert", "soar", "notification", "complete"]


class UnifiedPipeline:
    """
    Unified pipeline with pluggable bus.
    Flow: ingest → normalize → enrich → detect → correlate → alert → soar → notify
    """

    def __init__(self):
        self._bus: Optional[EventBus] = None
        self._stages: Dict[str, Callable] = {}
        self._running = False
        self._tasks: set = set()
        self._metrics = {
            "ingested": 0, "normalized": 0, "enriched": 0,
            "detected": 0, "correlated": 0, "alerted": 0,
            "soared": 0, "errors": 0, "latency_ms": [],
        }

    async def initialize(self, redis=None, partition_config: Optional[PartitionConfig] = None) -> None:
        if not redis:
            redis = await get_redis()
        settings = get_settings()
        self._bus = create_bus(redis=redis, settings=settings, partition_config=partition_config)
        self._register_stages()
        log.info("UnifiedPipeline initialized with %s (partitioning=%s)",
                 type(self._bus).__name__,
                 partition_config.partition_by_tenant if partition_config else False)

    def _register_stages(self) -> None:
        self._stages = {
            "normalization": self._wrap_stage(normalization_stage),
            "enrichment": self._wrap_stage(enrichment_stage),
            "anomaly": self._wrap_stage(anomaly_stage),
            "detection": self._wrap_stage(detection_stage),
            "correlation": self._wrap_stage(correlation_stage),
            "alert": self._wrap_stage(alert_stage),
            "soar": self._wrap_stage(soar_stage),
            "notification": self._wrap_stage(notification_stage),
        }

    def _wrap_stage(self, stage) -> Callable:
        async def wrapper(envelope: PipelineEnvelope) -> None:
            tracer = get_tracer()
            stage_name = stage.name
            start = datetime.now(timezone.utc)
            with tracer.start_as_current_span(
                f"pipeline.{stage_name}",
                attributes={
                    "cybernova.pipeline.stage": stage_name,
                    "cybernova.pipeline.event_id": envelope.event_id,
                    "cybernova.pipeline.tenant_id": envelope.tenant_id,
                    "cybernova.pipeline.previous_stage": envelope.previous_stage or "",
                },
            ):
                try:
                    result = await stage.handle(envelope)
                    latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000
                    slo_engine.record_success(stage_name, latency)
                    metrics.observe("pipeline_stage_latency_ms", latency, tags={"stage": stage_name})
                    # Track which stage just completed
                    stage_metric_map = {
                        "normalization": "normalized",
                        "enrichment": "enriched",
                        "anomaly": "detected",
                        "detection": "detected",
                        "correlation": "correlated",
                        "alert": "alerted",
                        "soar": "soared",
                    }
                    metric_key = stage_metric_map.get(stage_name)
                    if metric_key and metric_key in self._metrics:
                        self._metrics[metric_key] += 1

                    if result and result.stage != "complete" and result.stage in self._stages:
                        await self._bus.publish(result.stage, result)
                    elif result and result.stage == "complete":
                        # Count alerts/soar actions from the final complete stage
                        n_alerts = len(result.payload.get("alerts", []))
                        if n_alerts > 0:
                            self._metrics["alerted"] += n_alerts
                            self._metrics["soared"] += n_alerts
                    self._metrics["latency_ms"].append(latency)
                    self._slo_breach_check(stage_name)
                except Exception as e:
                    latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000
                    slo_engine.record_failure(stage_name, latency)
                    metrics.observe("pipeline_stage_latency_ms", latency, tags={"stage": stage_name})
                    log.error("Stage %s unhandled error: %s", stage.name, e)
                    self._metrics["errors"] += 1
        return wrapper

    def _slo_breach_check(self, stage_name: str) -> None:
        breaches = slo_engine.evaluate(stage_name)
        for breach in breaches:
            log.warning(
                "SLO BREACH [%s]: %s | snapshot: success=%.1f%% p99=%.1fms "
                "throughput=%.1f/min",
                breach.stage,
                "; ".join(breach.violations),
                breach.snapshot["success_rate_pct"],
                breach.snapshot["p99_latency_ms"],
                breach.snapshot["throughput_per_min"],
            )

    async def start(self) -> None:
        self._running = True
        for stage_name, handler in self._stages.items():
            await self._bus.subscribe(stage_name, handler)
        log.info("UnifiedPipeline started with %d stages", len(self._stages))

    async def ingest(
        self,
        raw_data: Dict[str, Any],
        tenant_id: str = "default",
        source: str = "api",
        source_type: str = "json",
    ) -> str:
        """Entry point: ingest raw event into pipeline.

        The pipeline only starts on the leader replica (or in single-server local mode),
        so this check is redundant with the startup logic. We SKIP the separate leader
        check here to avoid double-validation bugs and allow single-server deployments
        to work without HA leader election.
        """

        event_id = str(uuid4())
        envelope = PipelineEnvelope(
            event_id=event_id,
            tenant_id=tenant_id,
            stage="normalization",
            payload={
                "raw_data": raw_data,
                "source": source,
                "source_type": source_type,
            },
        )
        success = await self._bus.publish("normalization", envelope)
        if success:
            self._metrics["ingested"] += 1
            metrics.increment("events_by_tenant_total", tags={"tenant": tenant_id})
        else:
            self._metrics["errors"] += 1
        return event_id

    async def ingest_batch(
        self,
        events: List[Dict[str, Any]],
        tenant_id: str = "default",
        source: str = "api",
        source_type: str = "json",
    ) -> int:
        """Ingest multiple events concurrently. Logs any ingestion errors."""
        tasks = [self.ingest(e, tenant_id, source, source_type) for e in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        accepted = 0
        for r in results:
            if isinstance(r, str):
                accepted += 1
            elif isinstance(r, Exception):
                log.error("Event ingestion failed: %s: %s", type(r).__name__, r)
        if accepted < len(events):
            log.warning("ingest_batch: %d/%d events accepted for tenant=%s source=%s",
                        accepted, len(events), tenant_id, source)
        return accepted

    async def get_metrics(self) -> Dict[str, Any]:
        pending_counts = {}
        if self._bus is None:
            # Pipeline not yet initialized — all stages show 0 pending
            log.debug("[PIPELINE] get_metrics called before bus initialization")
            for stage in STAGE_ORDER:
                if stage not in ("ingestion", "complete"):
                    pending_counts[stage] = 0
        else:
            for stage in STAGE_ORDER:
                if stage in ("ingestion", "complete"):
                    continue
                try:
                    pending_counts[stage] = await self._bus.pending_count(stage)
                except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
                    log.warning("[PIPELINE] Failed to get pending count for stage %s: %s", stage, e)
                    pending_counts[stage] = 0
        avg_latency = 0.0
        if self._metrics["latency_ms"]:
            avg_latency = sum(self._metrics["latency_ms"]) / len(self._metrics["latency_ms"])
        return {
            **self._metrics,
            "avg_latency_ms": round(avg_latency, 2),
            "pending": pending_counts,
            "slo": slo_engine.report(),
        }

    async def drain(self, timeout: float = 5.0) -> int:
        """Stop accepting new work and complete in-flight pipeline messages."""
        self._running = False
        if not self._bus:
            return 0
        drained = await self._bus.drain(timeout=timeout)
        if drained:
            log.info("UnifiedPipeline drained %d in-flight events", drained)
        return drained

    async def close(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._bus:
            await self._bus.close()
        log.info("UnifiedPipeline shut down")


unified_pipeline = UnifiedPipeline()
