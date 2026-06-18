"""
Redis Memory Monitor
====================
Periodically checks Redis memory usage, tracks memory per key prefix,
and alerts if state:* keys exceed configured threshold of allocated memory.

Usage:
    monitor = RedisMemoryMonitor(redis_client)
    await monitor.start()  # launches background task
    await monitor.check()  # one-shot check
    await monitor.stop()
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.monitoring.redis_memory")

PREFIXES_OF_INTEREST = [
    "state:*",
    "idemp:*",
    "dedup:*",
    "lock:*",
    "metrics:*",
    "quota:*",
    "ueba:*",
    "audit:*",
    "cybernova:state:*",
    "cybernova:ratelimit:*",
    "cybernova:anomaly:*",
    "cybernova:ml:*",
    "cybernova:ha:*",
]

STATE_PREFIXES = ["state:*", "cybernova:state:*"]


@dataclass
class RedisMemoryInfo:
    used_memory: int = 0
    used_memory_human: str = ""
    maxmemory: int = 0
    maxmemory_human: str = ""
    total_system_memory: int = 0
    used_memory_rss: int = 0
    used_memory_peak: int = 0
    used_memory_lua: int = 0
    mem_fragmentation_ratio: float = 0.0
    evicted_keys: int = 0
    keys_total: int = 0
    uptime_in_seconds: int = 0

    @property
    def usage_pct(self) -> float:
        if self.maxmemory > 0:
            return round(self.used_memory / self.maxmemory * 100, 1)
        return 0.0

    @property
    def is_near_limit(self) -> bool:
        return self.usage_pct >= 80

    @classmethod
    def from_info(cls, info: Dict[str, Any]) -> "RedisMemoryInfo":
        return cls(
            used_memory=int(info.get("used_memory", 0)),
            used_memory_human=info.get("used_memory_human", ""),
            maxmemory=int(info.get("maxmemory", 0)),
            maxmemory_human=info.get("maxmemory_human", ""),
            total_system_memory=int(info.get("total_system_memory", 0)),
            used_memory_rss=int(info.get("used_memory_rss", 0)),
            used_memory_peak=int(info.get("used_memory_peak", 0)),
            used_memory_lua=int(info.get("used_memory_lua", 0)),
            mem_fragmentation_ratio=float(info.get("mem_fragmentation_ratio", 0.0)),
            evicted_keys=int(info.get("evicted_keys", 0)),
            keys_total=int(info.get("keys_total", 0)),
            uptime_in_seconds=int(info.get("uptime_in_seconds", 0)),
        )


@dataclass
class PrefixMemoryEstimate:
    prefix: str
    key_count: int
    estimated_bytes: int = 0

    @property
    def estimated_human(self) -> str:
        if self.estimated_bytes < 1024:
            return f"{self.estimated_bytes} B"
        elif self.estimated_bytes < 1024 * 1024:
            return f"{self.estimated_bytes / 1024:.1f} KB"
        else:
            return f"{self.estimated_bytes / (1024 * 1024):.1f} MB"


@dataclass
class MemoryAlert:
    prefix: str
    key_count: int
    estimated_bytes: int
    threshold_pct: int
    actual_pct: float
    message: str


@dataclass
class MemoryReport:
    info: RedisMemoryInfo
    prefixes: List[PrefixMemoryEstimate] = field(default_factory=list)
    alerts: List[MemoryAlert] = field(default_factory=list)
    state_usage_pct: float = 0.0
    state_alert: bool = False

    def to_dict(self) -> Dict:
        return {
            "info": {
                "used_memory_human": self.info.used_memory_human,
                "maxmemory_human": self.info.maxmemory_human,
                "usage_pct": self.info.usage_pct,
                "evicted_keys": self.info.evicted_keys,
                "keys_total": self.info.keys_total,
                "mem_fragmentation_ratio": self.info.mem_fragmentation_ratio,
            },
            "prefixes": [
                {"prefix": p.prefix, "key_count": p.key_count, "estimated": p.estimated_human}
                for p in self.prefixes
            ],
            "alerts": [a.message for a in self.alerts],
            "state_usage_pct": self.state_usage_pct,
            "state_alert": self.state_alert,
        }


class RedisMemoryMonitor:
    """Periodically checks Redis memory and alerts on state:* pressure."""

    def __init__(self, redis, settings=None):
        self._redis = redis
        self._settings = settings or get_settings()
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_report: Optional[MemoryReport] = None
        self._warn_pct = self._settings.redis_memory_warn_pct
        self._check_interval = self._settings.redis_memory_check_interval

    async def start(self) -> None:
        if self._task is not None:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        log.info("RedisMemoryMonitor started (interval=%ds, state_warn=%d%%)",
                 self._check_interval, self._warn_pct)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        log.info("RedisMemoryMonitor stopped")

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await self.check()
            except Exception as e:
                log.warning("RedisMemoryMonitor check failed: %s", e)
            await asyncio.sleep(self._check_interval)

    async def check(self) -> MemoryReport:
        if not self._redis:
            return MemoryReport(info=RedisMemoryInfo())

        info_raw = await self._redis.info("memory")
        info = RedisMemoryInfo.from_info(info_raw)

        db_raw = await self._redis.info("keyspace")
        total_keys = 0
        for db_stat in db_raw.values():
            if isinstance(db_stat, str):
                parts = db_stat.split(",")
                for p in parts:
                    if "keys=" in p:
                        try:
                            total_keys += int(p.split("=")[1])
                        except (ValueError, IndexError):
                            pass
        info.keys_total = total_keys

        prefixes = await self._estimate_prefix_memory()
        state_estimate = self._sum_prefixes(prefixes, STATE_PREFIXES)
        state_usage_pct = 0.0
        if info.maxmemory > 0:
            state_usage_pct = round(state_estimate.estimated_bytes / info.maxmemory * 100, 1)

        alerts = []
        if info.is_near_limit:
            alerts.append(MemoryAlert(
                prefix="*", key_count=info.keys_total,
                estimated_bytes=info.used_memory,
                threshold_pct=80, actual_pct=info.usage_pct,
                message=f"Redis overall memory at {info.usage_pct}% (>=80%) — configured max: {info.maxmemory_human}",
            ))
        if state_usage_pct >= self._warn_pct:
            alerts.append(MemoryAlert(
                prefix="state:*", key_count=state_estimate.key_count,
                estimated_bytes=state_estimate.estimated_bytes,
                threshold_pct=self._warn_pct, actual_pct=state_usage_pct,
                message=f"state:* keys use {state_usage_pct}% of maxmemory "
                        f"({state_estimate.estimated_human}) — exceeds {self._warn_pct}% threshold",
            ))

        for alert in alerts:
            log.warning("REDIS MEMORY ALERT: %s", alert.message)

        self._last_report = MemoryReport(
            info=info,
            prefixes=prefixes,
            alerts=alerts,
            state_usage_pct=state_usage_pct,
            state_alert=state_usage_pct >= self._warn_pct,
        )
        return self._last_report

    async def _estimate_prefix_memory(self) -> List[PrefixMemoryEstimate]:
        estimates = []
        for prefix in PREFIXES_OF_INTEREST:
            pattern = prefix.replace("*", "")
            keys = []
            cursor = 0
            try:
                while True:
                    cursor, batch = await self._redis.scan(
                        cursor=cursor, match=pattern, count=500
                    )
                    keys.extend(batch)
                    if cursor == 0:
                        break
            except Exception as e:
                log.debug("Redis scan error for prefix %s: %s", prefix, e)
            if keys:
                sample_keys = keys[:20]
                sizes = []
                for sk in sample_keys:
                    try:
                        sz = await self._redis.memory_usage(sk, samples=3)
                        if sz:
                            sizes.append(sz)
                    except Exception as e:
                        log.debug("Redis memory_usage error for key %s: %s", sk, e)
                avg_size = int(sum(sizes) / len(sizes)) if sizes else 256
                estimated = max(len(keys) * avg_size, len(keys) * 128)
                estimates.append(PrefixMemoryEstimate(
                    prefix=prefix, key_count=len(keys), estimated_bytes=estimated,
                ))
            else:
                estimates.append(PrefixMemoryEstimate(prefix=prefix, key_count=0))
        return estimates

    @staticmethod
    def _sum_prefixes(estimates: List[PrefixMemoryEstimate], prefixes: List[str]) -> PrefixMemoryEstimate:
        total_keys = 0
        total_bytes = 0
        seen = set()
        for prefix in prefixes:
            for est in estimates:
                if est.prefix == prefix and prefix not in seen:
                    total_keys += est.key_count
                    total_bytes += est.estimated_bytes
                    seen.add(prefix)
        return PrefixMemoryEstimate(
            prefix="+".join(prefixes),
            key_count=total_keys,
            estimated_bytes=total_bytes,
        )

    @property
    def last_report(self) -> Optional[MemoryReport]:
        return self._last_report
