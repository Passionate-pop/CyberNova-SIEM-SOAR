from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, Optional


log = logging.getLogger("cybernova.api_versioning.tier_limiter")

TIER_LIMITS: Dict[str, Dict[str, int]] = {
    "free": {
        "requests_per_minute": 60,
        "events_per_day": 10000,
        "concurrent_sessions": 5,
        "search_limit": 100,
        "api_rate": 60,
    },
    "pro": {
        "requests_per_minute": 600,
        "events_per_day": 100000,
        "concurrent_sessions": 50,
        "search_limit": 1000,
        "api_rate": 600,
    },
    "enterprise": {
        "requests_per_minute": 6000,
        "events_per_day": 10000000,
        "concurrent_sessions": 500,
        "search_limit": 10000,
        "api_rate": 6000,
    },
}

FREE_LIMITS = TIER_LIMITS["free"]


class TieredRateLimiter:
    """
    Redis-backed rate limiter with per-tier limits.
    Tracks usage via sliding window counters in Redis.
    Falls back to in-memory when Redis is unavailable.
    """

    def __init__(self):
        self._redis = None
        self._memory_store: Dict[str, list] = {}
        self._lock = asyncio.Lock()

    async def _get_redis(self):
        if self._redis is None:
            from cybernova.database.redis import get_redis
            self._redis = await get_redis()
        return self._redis

    def get_tier_limits(self, tier: str = "free") -> Dict[str, int]:
        return TIER_LIMITS.get(tier, FREE_LIMITS)

    async def check_rate_limit(
        self, key: str, tier: str = "free", window: int = 60
    ) -> tuple[bool, int, int]:
        limits = self.get_tier_limits(tier)
        max_requests = limits.get("requests_per_minute", 60)

        redis = await self._get_redis()
        if redis:
            return await self._check_redis(redis, key, max_requests, window)
        return await self._check_memory(key, max_requests, window)

    async def _check_redis(
        self, redis, key: str, limit: int, window: int
    ) -> tuple[bool, int, int]:
        now = time.time()
        window_start = now - window
        rate_key = f"tier_ratelimit:{key}"

        pipe = redis.pipeline()
        pipe.zremrangebyscore(rate_key, 0, window_start)
        pipe.zcard(rate_key)
        pipe.zadd(rate_key, {str(now): now})
        pipe.expire(rate_key, window + 1)
        results = await pipe.execute()

        current_count = results[1]
        remaining = max(0, limit - current_count - 1)

        if current_count >= limit:
            return False, current_count, 0
        return True, current_count + 1, remaining

    async def _check_memory(
        self, key: str, limit: int, window: int
    ) -> tuple[bool, int, int]:
        now = time.time()
        async with self._lock:
            timestamps = self._memory_store.get(key, [])
            cutoff = now - window
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                return False, len(timestamps), 0
            timestamps.append(now)
            self._memory_store[key] = timestamps
            return True, len(timestamps), max(0, limit - len(timestamps))

    def get_headers(
        self, limit: int, remaining: int, reset: Optional[int] = None
    ) -> Dict[str, str]:
        reset_time = reset or int(time.time()) + 60
        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
        }


tiered_rate_limiter = TieredRateLimiter()
