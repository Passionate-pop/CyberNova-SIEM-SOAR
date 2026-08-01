"""
CyberNova — Unified Rate Limit Middleware
Consolidates:
  - PlanRateLimitMiddleware (per-category plan-based buckets)
  - RateLimitMiddleware (Redis-backed sliding window)
  - TieredRateLimiter (per-tier limits from api_versioning)

Features:
  - Unified path exclusion list (docs, health, metrics, static, WS)
  - Per-route-category rate limit buckets (dashboard reads get higher limit)
  - Redis-backed sliding window with in-memory fallback
  - Plan-aware limits with 30s TTL cache
  - Per-tenant and per-IP rate limiting
  - Stats endpoint for rate limit dashboard UI
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, Optional, Set, Tuple

from fastapi import Request
from jose import JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.middleware.rate_limit")
settings = get_settings()

# =============================================================================
# Tier limit configuration (from api_versioning/tier_limiter.py)
# =============================================================================
TIER_LIMITS: Dict[str, Dict[str, int]] = {
    "free": {
        "requests_per_minute": 300,
        "events_per_day": 10000,
        "concurrent_sessions": 5,
        "search_limit": 100,
        "api_rate": 300,
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

# =============================================================================
# Plan limit cache (refreshes every 30s)
# =============================================================================
_plan_limit_cache: Dict[str, Tuple[int, float]] = {}
_PLAN_CACHE_MAX = 10_000  # evict oldest entries when exceeded

# =============================================================================
# Rate limit stats collector (for dashboard UI)
# =============================================================================
_rate_limit_stats: Dict[str, dict] = {}
_stats_lock = asyncio.Lock()


async def record_rate_limit_hit(
    tenant_id: str,
    category: str,
    path: str,
    limit: int,
    current_count: int,
    blocked: bool,
) -> None:
    """Record rate limit hit for dashboard display."""
    async with _stats_lock:
        key = f"{tenant_id}:{category}"
        now = time.time()
        if key not in _rate_limit_stats or now - _rate_limit_stats[key].get("window_start", 0) > 60:
            _rate_limit_stats[key] = {
                "category": category,
                "tenant_id": tenant_id,
                "limit": limit,
                "current_count": 0,
                "blocked_count": 0,
                "window_start": now,
                "last_path": "",
            }
        stats = _rate_limit_stats[key]
        stats["current_count"] = current_count
        stats["limit"] = limit
        stats["last_path"] = path
        if blocked:
            stats["blocked_count"] = stats.get("blocked_count", 0) + 1


async def get_rate_limit_stats() -> list[dict]:
    """Get current rate limit stats for dashboard display."""
    async with _stats_lock:
        now = time.time()
        result = []
        for key, stats in list(_rate_limit_stats.items()):
            if now - stats.get("window_start", 0) > 120:
                continue  # Skip stale entries
            result.append({
                "category": stats["category"],
                "tenant_id": stats["tenant_id"],
                "limit": stats["limit"],
                "current_count": stats["current_count"],
                "blocked_count": stats.get("blocked_count", 0),
                "remaining": max(0, stats["limit"] - stats["current_count"]),
                "utilization_pct": round((stats["current_count"] / max(stats["limit"], 1)) * 100, 1),
                "last_path": stats.get("last_path", ""),
                "window_start": stats.get("window_start", now),
            })
        return sorted(result, key=lambda x: x["utilization_pct"], reverse=True)


# =============================================================================
# Unified path exclusion list — all rate limiters share this
# =============================================================================
EXCLUDED_PATHS: Set[str] = {
    "/health", "/ready", "/docs", "/redoc", "/openapi.json",
    "/metrics", "/favicon.ico",
}

EXCLUDED_PATH_PREFIXES: tuple = (
    "/ws", "/static", "/agent.ps1",
)

# Dashboard read endpoints — higher rate limit to prevent throttling
# of UI dashboard pages that make many API calls on load
DASHBOARD_READ_PREFIXES: tuple = (
    "/api/v1/dashboard/",
    "/api/v1/detect/rules",
    "/api/v1/search/",
    "/api/v1/notifications",
    "/api/v1/audit/",
)


def _get_route_category(path: str) -> str:
    """Categorize request path for rate limit bucket assignment."""
    if path.startswith(DASHBOARD_READ_PREFIXES):
        return "dashboard_read"
    if "/auth" in path:
        return "auth"
    if "/ingest" in path or "/pipeline/ingest" in path:
        return "ingestion"
    if "/search" in path or "/query" in path:
        return "search"
    if "/v1/admin/" in path or "/v1/soar/" in path:
        return "admin"
    # Rate limit dashboard endpoint itself
    if "/rate-limits" in path or "/ratelimit" in path.lower():
        return "stats"
    return "default"


def _should_exclude(path: str) -> bool:
    """Check if path should be excluded from rate limiting entirely."""
    if path in EXCLUDED_PATHS:
        return True
    for prefix in EXCLUDED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _get_rate_limit(category: str, plan_default: int = 300) -> int:
    """Get per-category rate limit."""
    limits = {
        "dashboard_read": max(600, plan_default),
        "auth": 20,                # strict auth rate limit
        "ingestion": 1000,         # high for event ingestion
        "search": 100,
        "admin": 200,
        "stats": 60,               # rate limit dashboard: 60/min
        "default": plan_default,
    }
    return limits.get(category, plan_default)


# =============================================================================
# Unified Rate Limit Middleware
# =============================================================================

class PlanRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Unified rate limiting middleware.
    - Redis-backed sliding window for distributed environments
    - In-memory sliding window fallback
    - Per-route-category rate limit buckets
    - Plan-aware limits with per-tenant caching
    - Falls back to IP-based limiting for unauthenticated requests
    """

    def __init__(self, app):
        super().__init__(app)
        self._ip_cache: Dict[str, Tuple[int, float]] = {}
        self._tenant_cache: Dict[str, Dict[str, Tuple[int, float]]] = {}
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                from cybernova.database.redis import get_redis
                self._redis = await get_redis()
            except (ConnectionError, TimeoutError, ImportError, OSError) as e:
                log.warning("Redis connection failed for rate limiter: %s", e)
                self._redis = False  # Sentinel: don't retry
        return self._redis if self._redis else None

    # -- cache eviction constant ------------------------------------------------
    _CACHE_EVICT_MAX = 10_000  # per-cache cap to prevent unbounded memory growth

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip excluded paths (docs, health, WS, static, etc.)
        if _should_exclude(path):
            return await call_next(request)

        tenant_id = self._get_tenant_id(request)
        category = _get_route_category(path)

        # Try Redis-backed rate limit first, fall back to in-memory
        if tenant_id:
            allowed, reason, current_count, limit = await self._check_tenant_rate_limit(
                tenant_id, category
            )
        else:
            allowed, reason, current_count, limit = self._check_ip_rate_limit(
                request.client.host if request.client else "unknown", category
            )

        # Record stats for dashboard
        await record_rate_limit_hit(
            tenant_id or "anonymous",
            category,
            path,
            limit,
            current_count,
            not allowed,
        )

        if not allowed:
            log.warning(
                "Rate limit exceeded: tenant=%s category=%s count=%d limit=%d path=%s",
                tenant_id or "anonymous", category, current_count, limit, path,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": reason,
                    "category": category,
                    "limit": limit,
                    "current": current_count,
                    "retry_after": 60,
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Category": category,
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Category"] = category
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count))
        return response

    def _get_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant ID from request."""
        if hasattr(request.state, "tenant_id"):
            return request.state.tenant_id

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from cybernova.security.encryption.jwt_handler import decode_access_token
                payload = decode_access_token(token)
                if payload:
                    return payload.get("tenant_id")
            except JWTError:
                pass  # Invalid token — rate limit as anonymous

        return None

    async def _check_tenant_rate_limit(
        self, tenant_id: str, category: str
    ) -> Tuple[bool, str, int, int]:
        """Check tenant's plan-based rate limit using Redis or in-memory sliding window."""
        plan_rate_limit = await self._get_plan_limit(tenant_id)
        limit = _get_rate_limit(category, plan_rate_limit)

        # Try Redis first (distributed)
        redis = await self._get_redis()
        if redis:
            return await self._check_redis(redis, tenant_id, category, limit)

        # Fall back to in-memory
        return self._check_memory(tenant_id, category, limit)

    async def _check_redis(
        self, redis, key_prefix: str, category: str, limit: int, window: int = 60
    ) -> Tuple[bool, str, int, int]:
        """Redis-backed sliding window rate limit check."""
        now = time.time()
        window_start = now - window
        rate_key = f"ratelimit:{key_prefix}:{category}"

        pipe = None
        try:
            pipe = redis.pipeline()
            pipe.zremrangebyscore(rate_key, 0, window_start)
            pipe.zcard(rate_key)
            pipe.zadd(rate_key, {str(now): now})
            pipe.expire(rate_key, window + 1)
            results = await pipe.execute()

            current_count = results[1] + 1  # +1 for this request
            if current_count > limit:
                return False, f"Rate limit: {current_count}/{limit} req/min ({category})", current_count, limit
            return True, "OK", current_count, limit
        except (ConnectionError, TimeoutError, OSError) as e:
            # Redis error — fall back to in-memory
            log.debug("Redis rate limit error %s, falling back to in-memory: key=%s", e, rate_key)
            return self._check_memory(key_prefix, category, limit)
        except Exception as e:
            # Catch BusyLoadingError (Redis loading dataset), ResponseError, etc.
            log.warning("Redis rate limit unexpected error %s: %s, falling back to in-memory", type(e).__name__, e)
            return self._check_memory(key_prefix, category, limit)
        finally:
            if pipe is not None:
                try:
                    await pipe.reset()
                except Exception:
                    pass  # best-effort cleanup

    def _check_memory(
        self, key: str, category: str, limit: int
    ) -> Tuple[bool, str, int, int]:
        """In-memory sliding window rate limit check."""
        now = time.time()
        storage = self._tenant_cache if key != "anonymous" and key.count("-") > 0 else self._ip_cache

        # Evict stale entries when cache grows too large (DDoS / scanner traffic)
        if len(storage) > self._CACHE_EVICT_MAX:
            self._evict_stale(storage)

        if key not in storage:
            storage[key] = {}

        buckets = storage[key]
        if category not in buckets:
            buckets[category] = (0, now)

        count, window_start = buckets[category]

        if now - window_start < 60:
            current = count + 1
            if current > limit:
                return False, f"Rate limit: {current}/{limit} req/min ({category})", current, limit
            buckets[category] = (current, window_start)
            return True, "OK", current, limit
        else:
            # Reset window
            buckets[category] = (1, now)
            return True, "OK", 1, limit

    @staticmethod
    def _evict_stale(storage: Dict) -> None:
        """Remove entries whose newest bucket is older than 120s.

        When over the cap, first drop fully-stale entries. If that's not
        enough, drop the oldest 25 % of remaining entries to guarantee
        the cache shrinks.
        """
        now = time.time()
        # Pass 1: drop entries where ALL buckets are >120s old
        stale_keys = [
            k for k, buckets in storage.items()
            if isinstance(buckets, dict)
            and all(now - ws > 120 for _, ws in buckets.values())
        ]
        for k in stale_keys:
            del storage[k]

        # Pass 2: if still over cap, drop the 25 % with the oldest newest-bucket
        if len(storage) > PlanRateLimitMiddleware._CACHE_EVICT_MAX:
            by_age = sorted(
                storage.items(),
                key=lambda item: max(ws for _, ws in item[1].values()) if isinstance(item[1], dict) else 0,
            )
            drop_count = max(1, len(storage) // 4)
            for k, _ in by_age[:drop_count]:
                del storage[k]

    async def _get_plan_limit(self, tenant_id: str) -> int:
        """Get the rate limit for a tenant.
        All tenants use 'free' tier limits ($0 operation).
        Cached for 30 seconds to reduce DB overhead."""
        now = time.time()

        if tenant_id in _plan_limit_cache:
            cached_limit, cached_at = _plan_limit_cache[tenant_id]
            if now - cached_at < 30:
                return cached_limit

        # Evict stale entries to prevent unbounded growth
        if len(_plan_limit_cache) > _PLAN_CACHE_MAX:
            # First drop entries older than the TTL
            stale = [k for k, (_, ts) in _plan_limit_cache.items() if now - ts > 30]
            for k in stale:
                _plan_limit_cache.pop(k, None)
            # If still over cap, drop oldest 25 %
            if len(_plan_limit_cache) > _PLAN_CACHE_MAX:
                by_age = sorted(_plan_limit_cache.items(), key=lambda kv: kv[1][1])
                for k, _ in by_age[: len(by_age) // 4]:
                    _plan_limit_cache.pop(k, None)

        # All tenants get free tier (300 req/min) — no billing module needed
        limit = TIER_LIMITS["free"]["requests_per_minute"]
        _plan_limit_cache[tenant_id] = (limit, now)
        return limit

    def _check_ip_rate_limit(
        self, ip: str, category: str
    ) -> Tuple[bool, str, int, int]:
        """Check IP-based rate limit (for unauthenticated requests).
        Uses per-category tracking within the IP cache."""
        now = time.time()
        limit = _get_rate_limit(category, 120)  # moderate default for unauthenticated

        # Evict stale IPs when cache grows too large
        if len(self._ip_cache) > self._CACHE_EVICT_MAX:
            self._evict_stale(self._ip_cache)

        if ip not in self._ip_cache:
            self._ip_cache[ip] = {}

        buckets = self._ip_cache[ip]
        if category not in buckets:
            buckets[category] = (0, now)

        count, window_start = buckets[category]

        if now - window_start < 60:
            current = count + 1
            if current > limit:
                return False, f"Rate limit: {current}/{limit} req/min ({category})", current, limit
            buckets[category] = (current, window_start)
            return True, "OK", current, limit
        else:
            buckets[category] = (1, now)
            return True, "OK", 1, limit


# =============================================================================
# Legacy helpers (re-exported for backward compatibility)
# =============================================================================

async def enforce_event_limit(tenant_id: str, event_count: int = 1) -> None:
    """
    Enforce plan event limit before ingestion.
    All tenants get unlimited events ($0 operation) — no billing.
    """
    # Always allowed — no paid event limits
    pass


class LegacyTieredRateLimiter:
    """
    Backward-compatible wrapper for TieredRateLimiter signatures.
    Delegates to PlanRateLimitMiddleware internals.

    DEPRECATED: All rate limiting is now handled by PlanRateLimitMiddleware.
    This shim is kept only for backward compatibility and always returns
    (allowed=True, remaining=0, limit=max_requests) to avoid double-limiting.
    """

    def __init__(self, *args, **kwargs):
        import warnings
        warnings.warn(
            "LegacyTieredRateLimiter is deprecated. Rate limiting is now handled "
            "by PlanRateLimitMiddleware automatically.",
            DeprecationWarning,
            stacklevel=2,
        )

    def get_tier_limits(self, tier: str = "free") -> Dict[str, int]:
        return TIER_LIMITS.get(tier, FREE_LIMITS)

    async def check_rate_limit(
        self, key: str, tier: str = "free", window: int = 60
    ) -> Tuple[bool, int, int]:
        limits = self.get_tier_limits(tier)
        max_requests = limits.get("requests_per_minute", 300)
        # Always allow — the middleware handles real enforcement
        return True, 0, max_requests
