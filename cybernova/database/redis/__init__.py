"""
CyberNova — Redis Client
Connection pool with graceful degradation, reconnection, and proper async shutdown.
Supports direct Redis and Redis Sentinel for high-availability failover.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional, List, Tuple

import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.redis")

_pool: Optional[aioredis.Redis] = None
_init_lock = asyncio.Lock()


def _parse_sentinels(sentinel_hosts: str) -> List[Tuple[str, int]]:
    """Parse 'host1:port1,host2:port2' into list of (host, port) tuples."""
    pairs = []
    for part in sentinel_hosts.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            host, port_str = part.rsplit(":", 1)
            pairs.append((host.strip(), int(port_str.strip())))
        else:
            pairs.append((part, 26379))
    return pairs


async def _connect_sentinel(settings) -> Optional[aioredis.Redis]:
    """Connect via Redis Sentinel for HA failover."""
    sentinel_hosts = _parse_sentinels(settings.redis_sentinel_hosts)
    if not sentinel_hosts:
        return None

    try:
        from redis.asyncio.sentinel import Sentinel

        sentinel = Sentinel(
            sentinels=sentinel_hosts,
            password=settings.redis_password or None,
            socket_connect_timeout=settings.redis_socket_connect_timeout,
            socket_timeout=settings.redis_socket_timeout,
            max_connections=settings.redis_pool_size,
            decode_responses=True,
        )
        master = sentinel.master_for(settings.redis_sentinel_master, db=settings.redis_db)
        await master.ping()
        log.info("Redis connected via Sentinel master=%s sentinels=%s pool=%d",
                  settings.redis_sentinel_master, settings.redis_sentinel_hosts,
                  settings.redis_pool_size)
        return master
    except Exception as exc:
        log.warning("Redis Sentinel connection failed (%s) - running without Redis", exc)
        return None


async def _connect_direct(settings) -> Optional[aioredis.Redis]:
    """Connect directly to a single Redis instance."""
    redis_host = settings.redis_host
    if not redis_host:
        log.warning("Redis not configured - features requiring Redis disabled")
        return None
    try:
        url = settings.redis_url_override or (
            f"redis://:{settings.redis_password}@{redis_host}:{settings.redis_port}/{settings.redis_db}"
            if settings.redis_password
            else f"redis://{redis_host}:{settings.redis_port}/{settings.redis_db}"
        )
        connection_pool = ConnectionPool.from_url(
            url,
            max_connections=settings.redis_pool_size,
            socket_connect_timeout=settings.redis_socket_connect_timeout,
            socket_timeout=settings.redis_socket_timeout,
            retry_on_timeout=True,
            health_check_interval=30,
            decode_responses=True,
            protocol=2,  # RESP2 — works with --requirepass (RESP3 sends AUTH default <pw> which fails with legacy auth)
        )
        client = aioredis.Redis.from_pool(connection_pool)
        await client.ping()
        log.info("Redis connected at %s:%s pool=%d (RESP2)",
                  redis_host, settings.redis_port, settings.redis_pool_size)
        return client
    except Exception as exc:
        log.warning("Redis unavailable (%s) - running without Redis", exc)
        return None


async def get_redis() -> Optional[aioredis.Redis]:
    global _pool
    if _pool is not None:
        try:
            await _pool.ping()
            return _pool
        except (ConnectionError, TimeoutError, OSError, RuntimeError):
            log.warning("Redis connection lost, reconnecting...")
            await _close_redis_unsafe()
    async with _init_lock:
        if _pool is not None:
            return _pool
        settings = get_settings()

        if settings.redis_sentinel_hosts:
            _pool = await _connect_sentinel(settings)
        else:
            _pool = await _connect_direct(settings)

        return _pool


async def _close_redis_unsafe() -> None:
    global _pool
    if _pool is None:
        return
    try:
        conn_pool = _pool.connection_pool
        await _pool.aclose()
        await conn_pool.disconnect()
    except Exception as e:
        log.warning("Redis close error: %s", e)
    finally:
        _pool = None


async def close_redis() -> None:
    async with _init_lock:
        await _close_redis_unsafe()
        log.info("Redis connection closed")
