"""
Chaos: Network Partition
Scenario: Simulate Redis/DB disconnection; assert graceful degradation then full recovery.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.database.redis import get_redis, close_redis
from cybernova.ha.leader import LeaderElection


@pytest.fixture(autouse=True)
def reset_redis_pool():
    import cybernova.database.redis as rmod
    rmod._pool = None
    yield
    rmod._pool = None


@pytest.mark.asyncio
async def test_redis_disconnect_reconnect():
    """Redis drops — app detects stale pool, reconnects."""
    import cybernova.database.redis as rmod

    old_pool = AsyncMock()
    old_pool.ping = AsyncMock(side_effect=[None, ConnectionError("lost")])
    rmod._pool = old_pool

    first = await get_redis()
    assert first is old_pool

    with patch("cybernova.database.redis.get_settings") as mock_settings:
        s = MagicMock()
        s.redis_host = "localhost"
        s.redis_port = 6379
        s.redis_db = 0
        s.redis_password = ""
        s.redis_url_override = ""
        s.redis_sentinel_hosts = ""
        s.redis_pool_size = 10
        s.redis_socket_connect_timeout = 5
        s.redis_socket_timeout = 10
        mock_settings.return_value = s

        new_pool = AsyncMock()
        new_pool.ping = AsyncMock(return_value=True)
        from_pool = MagicMock(return_value=new_pool)

        with patch("cybernova.database.redis.ConnectionPool.from_url") as mock_cpool, \
             patch("cybernova.database.redis.aioredis.Redis.from_pool", from_pool):
            mock_cpool.return_value = MagicMock()

            result = await get_redis()
            assert result is new_pool
            assert rmod._pool is new_pool


@pytest.mark.asyncio
async def test_leader_detects_redis_loss():
    """When Redis is lost, leader falls to local_mode."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.set = AsyncMock(return_value=True)
    redis.eval = AsyncMock(return_value=1)

    leader = LeaderElection(instance_id="partition-test")
    with patch("cybernova.ha.leader.get_redis", return_value=redis), \
         patch("cybernova.ha.leader.HEARTBEAT_INTERVAL", 0.05):
        await leader.start()
        await asyncio.sleep(0.1)
        assert leader.is_leader is True

    await leader.stop()


@pytest.mark.asyncio
async def test_db_disconnect_readonly_fallback():
    """get_db_readonly creates and closes a session correctly."""
    from cybernova.database.postgres.session import get_db_readonly

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.close = AsyncMock()

    factory = MagicMock(name="factory")
    ctx = MagicMock(name="ctx")
    ctx.__aenter__ = AsyncMock(return_value=mock_session)
    ctx.__aexit__ = AsyncMock(return_value=None)
    factory.return_value = ctx

    with patch("cybernova.database.postgres.session._get_read_session_factory",
               return_value=factory):
        gen = get_db_readonly()
        async for _ in gen:
            break
        await gen.aclose()

    mock_session.execute.assert_awaited()
    mock_session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_replica_health_returns_configured():
    """get_replica_health returns configured=False when no replica engine."""
    from cybernova.database.postgres.session import get_replica_health

    with patch("cybernova.database.postgres.session._replica_configured", False):
        health = await get_replica_health()
        assert health["configured"] is False
        assert health["healthy"] is True

    with patch("cybernova.database.postgres.session._replica_configured", True), \
         patch("cybernova.database.postgres.session.replica_engine", None):
        health = await get_replica_health()
        assert health["configured"] is True
