"""
CyberNova — API Key Rate Limiter
Redis-based sliding window per API key.  Reads APIKey.rate_limit from the DB
and enforces it via sorted-set timestamps.  Falls back to in-memory when Redis is unavailable.
"""
import asyncio
import hashlib
import logging
import time
from typing import Dict, Tuple

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select

from cybernova.database.postgres.models import APIKey
from cybernova.database.postgres.session import get_db

log = logging.getLogger(__name__)

WINDOW_SECONDS = 60
KEY_CACHE_TTL = 300


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class APIKeyRateLimiter:
    """Sliding-window rate limiter keyed by API key hash.

    * Counts requests in the last *WINDOW_SECONDS* via a Redis sorted set.
    * Reads each key's ``rate_limit`` from the ``APIKey`` model (with TTL cache).
    * Falls back to an in-memory dict when Redis is absent.
    """

    def __init__(self) -> None:
        self._redis = None
        self._memory_store: Dict[str, list] = {}
        self._lock = asyncio.Lock()
        self._key_cache: Dict[str, int] = {}
        self._cache_ts: Dict[str, float] = {}

    async def _get_redis(self):
        if self._redis is None:
            from cybernova.database.redis import get_redis
            self._redis = await get_redis()
        return self._redis

    _CACHE_MAX = 10_000  # prevent unbounded growth under DDoS

    async def _fetch_key_limit(self, key_hash: str) -> int:
        now = time.time()
        if key_hash in self._key_cache:
            if now - self._cache_ts.get(key_hash, 0) < KEY_CACHE_TTL:
                return self._key_cache[key_hash]

        limit = None
        try:
            from cybernova.database.postgres.session import async_session_factory
            async with async_session_factory() as db:
                result = await db.execute(
                    select(APIKey.rate_limit).where(APIKey.key_hash == key_hash)
                )
                limit = result.scalar_one_or_none()
        except Exception as e:
            log.debug("Failed to fetch API key rate limit for %s...: %s", key_hash[:12], e)

        # Evict stale cache entries when it grows too large
        if len(self._key_cache) > self._CACHE_MAX:
            stale = [k for k, ts in self._cache_ts.items() if now - ts > KEY_CACHE_TTL]
            for k in stale:
                self._key_cache.pop(k, None)
                self._cache_ts.pop(k, None)

        if limit is not None:
            self._key_cache[key_hash] = limit
            self._cache_ts[key_hash] = now
            return limit
        return 60

    async def check(self, raw_key: str) -> Tuple[bool, int, int, int]:
        """Return ``(allowed, current, limit, remaining)``."""
        kh = hash_api_key(raw_key)
        limit = await self._fetch_key_limit(kh)
        key = f"apikey_ratelimit:{kh}"

        redis = await self._get_redis()
        if redis:
            allowed, current = await self._check_redis(redis, key, limit)
        else:
            allowed, current = await self._check_memory(kh, limit)

        remaining = max(0, limit - current)
        return allowed, current, limit, remaining

    async def _check_redis(self, redis, key: str, limit: int) -> Tuple[bool, int]:
        now = time.time()
        window_start = now - WINDOW_SECONDS

        await redis.zremrangebyscore(key, 0, window_start)
        current = await redis.zcard(key)

        if current >= limit:
            return False, current

        await redis.zadd(key, {str(now): now})
        await redis.expire(key, WINDOW_SECONDS + 1)
        return True, current + 1

    async def _check_memory(self, key: str, limit: int) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - WINDOW_SECONDS
        async with self._lock:
            timestamps = self._memory_store.get(key, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                return False, len(timestamps)
            timestamps.append(now)
            self._memory_store[key] = timestamps
            return True, len(timestamps)

    def invalidate_cache(self, key_hash: str) -> None:
        self._key_cache.pop(key_hash, None)
        self._cache_ts.pop(key_hash, None)


api_key_limiter = APIKeyRateLimiter()


def register_api_key_rate_limiter(app: FastAPI) -> None:
    """Inject the middleware that enforces per-API-key rate limits."""
    @app.middleware("http")
    async def _enforce_api_key_limit(request: Request, call_next):
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            return await call_next(request)

        allowed, current, limit, remaining = await api_key_limiter.check(raw_key)

        if not allowed:
            log.warning("API key rate limit hit: %s (%d/%d)",
                        hash_api_key(raw_key)[:12], current, limit)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "API key rate limit exceeded",
                    "rate_limit": {
                        "limit": limit,
                        "current": current,
                        "remaining": 0,
                    },
                },
                headers={
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + WINDOW_SECONDS),
                    "Retry-After": str(WINDOW_SECONDS),
                },
            )

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + WINDOW_SECONDS)
        return response

    log.info("API key rate limiter middleware registered")
