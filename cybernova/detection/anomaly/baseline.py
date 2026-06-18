from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

log = logging.getLogger("cybernova.detection.anomaly.baseline")

_REDIS_PREFIX = "cybernova:anomaly"


def _get_sync_redis():
    try:
        import redis as sync_redis
        from cybernova.config.settings import get_settings
        s = get_settings()
        url = s.resolved_redis_url
        return sync_redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
    except Exception:
        return None


class EventBaseline:
    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self._event_counts: Dict[str, List[float]] = defaultdict(list)
        self._timestamps: Dict[str, List[float]] = defaultdict(list)
        self._source_ips: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._event_types: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._hourly_volume: Dict[str, List[int]] = defaultdict(lambda: [0] * 24)
        self._lock = asyncio.Lock()
        self._redis = _get_sync_redis()

    def _rate_key(self, tenant_id: str, event_type: str) -> str:
        return f"{_REDIS_PREFIX}:rate:{tenant_id}:{event_type}"

    def _ip_key(self, tenant_id: str) -> str:
        return f"{_REDIS_PREFIX}:ip:{tenant_id}"

    def _type_key(self, tenant_id: str) -> str:
        return f"{_REDIS_PREFIX}:type:{tenant_id}"

    def _hourly_key(self, tenant_id: str) -> str:
        return f"{_REDIS_PREFIX}:hourly:{tenant_id}"

    def _increment_redis_rate(self, key: str, now: float) -> None:
        if not self._redis:
            return
        try:
            minute_bucket = int(now / 60)
            slot = str(minute_bucket)
            self._redis.zincrby(key, 1, slot)
            cutoff = minute_bucket - int(self.window_seconds / 60)
            self._redis.zremrangebyscore(key, "-inf", cutoff)
            self._redis.expire(key, self.window_seconds + 300)
        except Exception as e:
            log.warning("Redis anomaly rate error: %s", e)

    def _get_redis_rate_stats(self, key: str) -> Tuple[float, float]:
        if not self._redis:
            return 0.0, 0.0
        try:
            scores = self._redis.zrange(key, 0, -1, withscores=False)
            if not scores:
                return 0.0, 0.0
            counts = [int(self._redis.zscore(key, s) or 0) for s in scores]
            n = len(counts)
            if n < 2:
                return float(sum(counts)), 0.0
            mean = sum(counts) / n
            variance = sum((c - mean) ** 2 for c in counts) / n
            std = variance ** 0.5 if variance > 0 else 1.0
            return mean, std
        except Exception as e:
            log.warning("Redis anomaly rate read error: %s", e)
            return 0.0, 0.0

    async def record_event(self, tenant_id: str, event_data: Dict[str, Any]) -> None:
        async with self._lock:
            now = time.time()
            event_type = event_data.get("event_type", "unknown")
            source_ip = event_data.get("source_ip", "")

            key = f"{tenant_id}:{event_type}"
            self._event_counts[key].append(1)
            self._timestamps[key].append(now)

            if source_ip:
                self._source_ips[tenant_id][source_ip] += 1

            self._event_types[tenant_id][event_type] += 1

            hour = datetime.now(timezone.utc).hour
            self._hourly_volume[tenant_id][hour] += 1

            await self._prune(key)

            rkey = self._rate_key(tenant_id, event_type)
            self._increment_redis_rate(rkey, now)

            if self._redis:
                try:
                    ip_key = self._ip_key(tenant_id)
                    self._redis.hincrby(ip_key, source_ip, 1) if source_ip else None
                    self._redis.expire(ip_key, self.window_seconds + 300)

                    type_key = self._type_key(tenant_id)
                    self._redis.hincrby(type_key, event_type, 1)
                    self._redis.expire(type_key, self.window_seconds + 300)

                    hourly_key = self._hourly_key(tenant_id)
                    self._redis.hset(hourly_key, str(hour), int(self._hourly_volume[tenant_id][hour]))
                    self._redis.expire(hourly_key, self.window_seconds + 300)
                except Exception as e:
                    log.warning("Redis anomaly metadata error: %s", e)

    async def _prune(self, key: str) -> None:
        cutoff = time.time() - self.window_seconds
        timestamps = self._timestamps.get(key, [])
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
            counts = self._event_counts.get(key, [])
            if counts:
                counts.pop(0)

    async def get_event_rate(self, tenant_id: str, event_type: str) -> float:
        async with self._lock:
            key = f"{tenant_id}:{event_type}"
            counts = self._event_counts.get(key, [])
            if not counts:
                return 0.0
            ts_list = self._timestamps.get(key, [time.time()])
            elapsed = min(self.window_seconds, time.time() - ts_list[0] if ts_list else 1)
            if elapsed < 1:
                return float(len(counts))
            return len(counts) / (elapsed / 60)

    async def get_mean_rate(self, tenant_id: str, event_type: str) -> float:
        rkey = self._rate_key(tenant_id, event_type)
        mean, _ = self._get_redis_rate_stats(rkey)
        if mean > 0:
            return mean

        async with self._lock:
            key = f"{tenant_id}:{event_type}"
            counts = self._event_counts.get(key, [])
            if len(counts) < 10:
                return 0.0
            return sum(counts) / len(counts)

    async def get_rate_std(self, tenant_id: str, event_type: str) -> float:
        rkey = self._rate_key(tenant_id, event_type)
        _, std = self._get_redis_rate_stats(rkey)
        if std > 0:
            return std

        async with self._lock:
            key = f"{tenant_id}:{event_type}"
            counts = self._event_counts.get(key, [])
            if len(counts) < 10:
                return 1.0
            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            return variance ** 0.5 if variance > 0 else 1.0

    async def get_top_source_ips(self, tenant_id: str, limit: int = 10) -> List[Tuple[str, int]]:
        if self._redis:
            try:
                ip_key = self._ip_key(tenant_id)
                items = self._redis.hgetall(ip_key)
                if items:
                    parsed = [(k.decode() if isinstance(k, bytes) else k, int(v.decode() if isinstance(v, bytes) else v)) for k, v in items.items()]
                    return sorted(parsed, key=lambda x: -x[1])[:limit]
            except Exception as e:
                log.warning("Redis anomaly IP read error: %s", e)

        async with self._lock:
            ips = self._source_ips.get(tenant_id, {})
            return sorted(ips.items(), key=lambda x: -x[1])[:limit]

    async def get_unusual_source_ips(self, tenant_id: str, threshold: float = 3.0) -> List[str]:
        async with self._lock:
            ips = self._source_ips.get(tenant_id, {})
            if not ips:
                if self._redis:
                    try:
                        ip_key = self._ip_key(tenant_id)
                        items = self._redis.hgetall(ip_key)
                        if items:
                            ips = {k.decode() if isinstance(k, bytes) else k: int(v.decode() if isinstance(v, bytes) else v) for k, v in items.items()}
                    except Exception as e:
                        log.debug("Redis anomaly IP read in get_unusual_source_ips: %s", e)
            if not ips:
                return []
            counts = list(ips.values())
            mean = sum(counts) / len(counts)
            std = (sum((c - mean) ** 2 for c in counts) / len(counts)) ** 0.5
            if std < 1:
                return []
            return [ip for ip, c in ips.items() if c > mean + threshold * std]

    async def get_hourly_anomaly(self, tenant_id: str) -> List[int]:
        async with self._lock:
            hist = self._hourly_volume.get(tenant_id, [0] * 24)
            if not hist or sum(hist) < 24:
                if self._redis:
                    try:
                        hourly_key = self._hourly_key(tenant_id)
                        items = self._redis.hgetall(hourly_key)
                        if items:
                            hist = [0] * 24
                            for k, v in items.items():
                                h = int(k.decode() if isinstance(k, bytes) else k)
                                if 0 <= h < 24:
                                    hist[h] = int(v.decode() if isinstance(v, bytes) else v)
                    except Exception as e:
                        log.debug("Redis hourly anomaly read error: %s", e)
            if sum(hist) < 24:
                return hist
            mean = sum(hist) / 24
            std = (sum((v - mean) ** 2 for v in hist) / 24) ** 0.5
            if std < 1:
                return [1 if v > mean * 2 else 0 for v in hist]
            return [1 if v > mean + 2 * std else 0 for v in hist]

    async def get_stats(self, tenant_id: str) -> Dict[str, Any]:
        async with self._lock:
            return {
                "total_events": sum(self._event_counts.values()),
                "unique_source_ips": len(self._source_ips.get(tenant_id, {})),
                "event_type_distribution": dict(self._event_types.get(tenant_id, {})),
                "hourly_volume": self._hourly_volume.get(tenant_id, [0] * 24),
            }


event_baseline = EventBaseline()
