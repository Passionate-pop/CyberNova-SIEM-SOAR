"""
CyberNova — SLA Monitoring Service
Real-time metrics for P99 latency, queue depths, error rates.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

import redis.asyncio as aioredis

from cybernova.config.settings import get_settings
from cybernova.resilience.circuit_breaker import get_all_circuit_breakers_status

log = logging.getLogger("cybernova.sla")


class MetricType(str, Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class SLAMetric:
    name: str
    metric_type: MetricType
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class SLAThresholds:
    availability: float = 99.9
    p99_latency_ms: float = 500
    error_rate_percent: float = 1.0
    queue_depth_max: int = 10000


class SLAMetricsCollector:
    """Collects and aggregates SLA metrics."""
    
    def __init__(self):
        self._metrics: Dict[str, List[float]] = defaultdict(list)
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._start_time = time.time()
        self._thresholds = SLAThresholds()
    
    def record_latency(self, operation: str, latency_ms: float):
        """Record operation latency."""
        self._metrics[f"latency.{operation}"].append(latency_ms)
    
    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric."""
        self._counters[name] += value
    
    def set_gauge(self, name: str, value: float):
        """Set a gauge metric."""
        self._gauges[name] = value
    
    def get_p50(self, metric_name: str) -> float:
        """Get 50th percentile (median)."""
        values = sorted(self._metrics.get(metric_name, []))
        if not values:
            return 0.0
        idx = len(values) // 2
        return values[idx]
    
    def get_p90(self, metric_name: str) -> float:
        """Get 90th percentile."""
        values = sorted(self._metrics.get(metric_name, []))
        if not values:
            return 0.0
        idx = int(len(values) * 0.9)
        return values[idx]
    
    def get_p99(self, metric_name: str) -> float:
        """Get 99th percentile."""
        values = sorted(self._metrics.get(metric_name, []))
        if not values:
            return 0.0
        idx = int(len(values) * 0.99)
        return values[idx]
    
    def get_sla_status(self) -> Dict[str, Any]:
        """Calculate overall SLA status."""
        uptime_seconds = time.time() - self._start_time
        uptime_hours = uptime_seconds / 3600
        
        total_requests = sum(
            self._counters.get(f"requests.{op}", 0) 
            for op in ["ingest", "query", "alert", "pipeline"]
        )
        total_errors = sum(
            self._counters.get(f"errors.{op}", 0) 
            for op in ["ingest", "query", "alert", "pipeline"]
        )
        
        availability = ((total_requests - total_errors) / max(total_requests, 1)) * 100
        
        return {
            "uptime_seconds": uptime_seconds,
            "uptime_hours": round(uptime_hours, 2),
            "availability_percent": round(availability, 3),
            "total_requests": total_requests,
            "total_errors": total_errors,
            "error_rate_percent": round((total_errors / max(total_requests, 1)) * 100, 3),
            "thresholds": {
                "availability": self._thresholds.availability,
                "p99_latency_ms": self._thresholds.p99_latency_ms,
                "error_rate_percent": self._thresholds.error_rate_percent,
            },
            "status": "healthy" if availability >= 99.0 else "degraded",
        }
    
    def get_latency_sla(self, operation: str) -> Dict[str, Any]:
        """Get SLA metrics for an operation."""
        metric_name = f"latency.{operation}"
        p50 = self.get_p50(metric_name)
        p90 = self.get_p90(metric_name)
        p99 = self.get_p99(metric_name)
        
        return {
            "operation": operation,
            "p50_ms": round(p50, 2),
            "p90_ms": round(p90, 2),
            "p99_ms": round(p99, 2),
            "samples": len(self._metrics.get(metric_name, [])),
            "status": "healthy" if p99 < self._thresholds.p99_latency_ms else "degraded",
        }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metrics."""
        return {
            "sla_status": self.get_sla_status(),
            "latency": {
                op: self.get_latency_sla(op) 
                for op in ["ingest", "normalize", "enrich", "detect", "alert"]
            },
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }


class RedisMetricsStore:
    """Stores metrics in Redis for persistence across restarts."""
    
    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        self._redis = redis_client
        self._local = SLAMetricsCollector()
    
    async def record_latency(self, operation: str, latency_ms: float):
        """Record operation latency."""
        self._local.record_latency(operation, latency_ms)
        if self._redis:
            await self._redis.lpush(f"metrics:latency:{operation}", latency_ms)
            await self._redis.ltrim(f"metrics:latency:{operation}", 0, 999)
    
    async def increment_counter(self, name: str, value: int = 1):
        """Increment a counter."""
        self._local.increment_counter(name, value)
        if self._redis:
            await self._redis.incrby(f"metrics:counter:{name}", value)
    
    async def set_gauge(self, name: str, value: float):
        """Set a gauge value."""
        self._local.set_gauge(name, value)
        if self._redis:
            await self._redis.set(f"metrics:gauge:{name}", value)
    
    async def get_sla_report(self) -> Dict[str, Any]:
        """Generate comprehensive SLA report."""
        base_metrics = self._local.get_all_metrics()
        
        if self._redis:
            try:
                pipeline = self._redis.pipeline()
                pipeline.xlen("cybernova:raw_events")
                pipeline.xlen("cybernova:normalized_events")
                pipeline.xlen("cybernova:enriched_events")
                pipeline.xlen("cybernova:alerts")
                results = await pipeline.execute()
                
                base_metrics["queue_depths"] = {
                    "raw_events": results[0],
                    "normalized_events": results[1],
                    "enriched_events": results[2],
                    "alerts": results[3],
                }
            except Exception as e:
                log.warning(f"Failed to get Redis queue depths: {e}")
                base_metrics["queue_depths"] = {}
        
        base_metrics["circuit_breakers"] = await get_all_circuit_breakers_status()
        
        return base_metrics


_sla_metrics: Optional[SLAMetricsCollector] = None
_redis_metrics: Optional[RedisMetricsStore] = None


def get_sla_metrics() -> SLAMetricsCollector:
    """Get the global SLA metrics collector."""
    global _sla_metrics
    if _sla_metrics is None:
        _sla_metrics = SLAMetricsCollector()
    return _sla_metrics


async def get_redis_metrics() -> RedisMetricsStore:
    """Get the global Redis metrics store."""
    global _redis_metrics
    if _redis_metrics is None:
        settings = get_settings()
        try:
            redis = aioredis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password,
                protocol=2,  # RESP2 — works with --requirepass
                decode_responses=True,
            )
            await redis.ping()
            _redis_metrics = RedisMetricsStore(redis)
        except (ConnectionError, TimeoutError, OSError):
            _redis_metrics = RedisMetricsStore()
    return _redis_metrics
