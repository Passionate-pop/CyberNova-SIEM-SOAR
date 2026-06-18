"""
Chaos: Dashboard Fallback
Scenario: Kill the database read replica; assert dashboard serves cached or degraded data.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_dashboard_service_uses_cache_on_passive_replica():
    """Non-leader replica serves dashboard from Redis cache when available."""
    from cybernova.dashboard import service as ds
    from cybernova.dashboard.service import DashboardService

    service = DashboardService()
    mock_redis = AsyncMock()
    cached_data = json.dumps({"risk_score": 42, "total_alerts": 100})
    mock_redis.get = AsyncMock(return_value=cached_data)
    mock_redis.setex = AsyncMock()

    ds.leader_election._is_leader = False
    ds.leader_election._local_mode = False

    try:
        with patch("cybernova.dashboard.service.get_redis", return_value=mock_redis):
            result = await service.get_summary(AsyncMock(), "tenant-1")
            assert result["risk_score"] == 42
            assert result["total_alerts"] == 100
    finally:
        ds.leader_election._is_leader = True


@pytest.mark.asyncio
async def test_dashboard_service_fetches_fresh_when_leader():
    """Leader replica fetches fresh data from DB and caches it."""
    from cybernova.dashboard import service as ds
    from cybernova.dashboard.service import DashboardService

    service = DashboardService()
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()

    counts = iter([5, 3, 2, 10, 1, 8])
    mock_scalar = MagicMock()
    mock_scalar.scalar = MagicMock(side_effect=lambda: next(counts))
    mock_db.execute.return_value = mock_scalar

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()

    ds.leader_election._is_leader = True
    ds.leader_election._local_mode = False

    try:
        with patch("cybernova.dashboard.service.get_redis", return_value=mock_redis):
            result = await service.get_summary(mock_db, "tenant-1")
        assert result["risk_score"] is not None
        assert mock_redis.setex.called
    finally:
        pass


@pytest.mark.asyncio
async def test_dashboard_service_fallback_when_cache_miss():
    """Passive replica falls back to DB query when Redis cache is cold."""
    from cybernova.dashboard import service as ds
    from cybernova.dashboard.service import DashboardService

    service = DashboardService()
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_scalar = MagicMock()
    mock_scalar.scalar = MagicMock(return_value=0)
    mock_db.execute.return_value = mock_scalar

    ds.leader_election._is_leader = False
    ds.leader_election._local_mode = False

    try:
        with patch("cybernova.dashboard.service.get_redis", return_value=mock_redis):
            result = await service.get_summary(mock_db, "tenant-1")
        assert result["risk_score"] == 0
    finally:
        ds.leader_election._is_leader = True


@pytest.mark.asyncio
async def test_readonly_session_creates_and_closes():
    """get_db_readonly creates session and closes it on exit."""
    from cybernova.database.postgres.session import get_db_readonly

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.close = AsyncMock()

    factory_mock = MagicMock(name="factory")
    ctx_mock = MagicMock(name="context")
    ctx_mock.__aenter__ = AsyncMock(return_value=mock_session)
    ctx_mock.__aexit__ = AsyncMock(return_value=None)
    factory_mock.return_value = ctx_mock

    with patch("cybernova.database.postgres.session._get_read_session_factory",
               return_value=factory_mock):
        gen = get_db_readonly()
        async for _ in gen:
            break
        await gen.aclose()

    assert not mock_session.commit.called
    mock_session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_health_monitor_reports_replica_status():
    """HealthMonitor includes database_replica check in its output."""
    from cybernova.ha.monitor import health_monitor

    with patch("cybernova.ha.monitor.health_monitor._check_replica_database") as mock_check:
        mock_check.return_value = {"healthy": True, "configured": True, "pool_stats": {}}
        health = await health_monitor.check_all()
        assert "database_replica" in health["checks"]
        assert health["checks"]["database_replica"]["healthy"] is True
