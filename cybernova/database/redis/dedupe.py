"""
CyberNova Redis Dedup + Lock (Patch B)
Provides Redis-backed deduplication (60s window) and distributed locking to prevent race conditions.
"""
import hashlib
import logging
from datetime import datetime
from typing import Dict, Any

log = logging.getLogger("cybernova.database.redis.dedupe")

_redis_client = None


async def init_redis(url: str = "redis://localhost:6379"):
    """Initialize Redis client. Call once at startup."""
    global _redis_client
    try:
        import redis.asyncio as redis
        _redis_client = await redis.from_url(url, decode_responses=True)
        await _redis_client.ping()
        return _redis_client
    except Exception as e:
        log.warning("Redis unavailable: %s", e)
        return None


async def close_redis():
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None


def _make_dedup_key(alert: Dict[str, Any], bucket_seconds: int = 60) -> str:
    """Generate dedup key: event_type:source_ip:dest_ip:time_bucket."""
    ts = alert.get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_bucket = int(dt.timestamp()) // bucket_seconds
        except (ValueError, TypeError):
            ts_bucket = 0
    else:
        ts_bucket = 0
    key_base = f"{alert.get('event_type', '')}:{alert.get('source_ip', '')}:{alert.get('dest_ip', '')}:{ts_bucket}"
    return f"dedupe:{hashlib.sha256(key_base.encode()).hexdigest()[:16]}"


async def is_duplicate(alert: Dict[str, Any]) -> bool:
    """Check if alert is a duplicate within 60s window. Returns True if duplicate."""
    if not _redis_client:
        return False
    key = _make_dedup_key(alert)
    try:
        exists = await _redis_client.exists(key)
        if exists:
            return True
        # Set with 60s TTL
        await _redis_client.setex(key, 60, "1")
        return False
    except Exception as e:
        log.warning("Dedup Redis check failed: %s", e)
        return False


def _make_lock_key(alert: Dict[str, Any]) -> str:
    """Generate lock key for incident creation."""
    key_base = f"{alert.get('event_type', '')}:{alert.get('source_ip', '')}:{alert.get('dest_ip', '')}"
    return f"lock:{hashlib.sha256(key_base.encode()).hexdigest()[:16]}"


async def acquire_lock(alert: Dict[str, Any], ttl_seconds: int = 10) -> bool:
    """Acquire distributed lock to prevent race condition in incident creation."""
    if not _redis_client:
        return True  # No Redis = permissive
    lock_key = _make_lock_key(alert)
    try:
        # NX = only set if not exists, EX = expire
        ok = await _redis_client.set(lock_key, "1", nx=True, ex=ttl_seconds)
        return bool(ok)
    except Exception as e:
        log.warning("Redis lock acquire failed: %s", e)
        return False


async def release_lock(alert: Dict[str, Any]):
    """Release distributed lock."""
    if not _redis_client:
        return
    lock_key = _make_lock_key(alert)
    try:
        await _redis_client.delete(lock_key)
    except Exception as e:
        log.warning("Redis lock release failed: %s", e)


async def dedupe_and_lock(alert: Dict[str, Any]) -> tuple[bool, bool]:
    """
    Combined dedupe + lock check.
    Returns: (is_duplicate, lock_acquired)
    """
    is_dup = await is_duplicate(alert)
    lock_ok = False
    if not is_dup:
        lock_ok = await acquire_lock(alert)
    return is_dup, lock_ok