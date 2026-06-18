"""Unit tests for database/redis/__init__.py and database/repository/base.py."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.redis import get_redis, close_redis


@pytest.mark.asyncio
async def test_get_redis_returns_cached_pool():
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)
    import cybernova.database.redis as rmod
    rmod._pool = mock_redis
    result = await get_redis()
    assert result is mock_redis
    rmod._pool = None


@pytest.mark.asyncio
async def test_get_redis_reconnects_on_failure():
    old_pool = AsyncMock()
    old_pool.ping = AsyncMock(side_effect=ConnectionError("lost"))
    old_pool.aclose = AsyncMock()
    old_pool.connection_pool = MagicMock()
    old_pool.connection_pool.disconnect = AsyncMock()

    import cybernova.database.redis as rmod
    rmod._pool = old_pool

    new_pool = AsyncMock()
    new_pool.ping = AsyncMock(return_value=True)
    from_pool_cls = MagicMock(return_value=new_pool)

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
        with patch("cybernova.database.redis.ConnectionPool.from_url") as mock_cpool:
            mock_cpool.return_value = MagicMock()
            with patch("cybernova.database.redis.aioredis.Redis.from_pool", from_pool_cls):
                result = await get_redis()
                assert result is new_pool

    rmod._pool = None


@pytest.mark.asyncio
async def test_get_redis_no_host_returns_none():
    import cybernova.database.redis as rmod
    rmod._pool = None
    with patch("cybernova.database.redis.get_settings") as mock_settings:
        s = MagicMock()
        s.redis_host = ""
        s.redis_sentinel_hosts = ""
        mock_settings.return_value = s
        result = await get_redis()
        assert result is None


@pytest.mark.asyncio
async def test_get_redis_connection_failure_returns_none():
    import cybernova.database.redis as rmod
    rmod._pool = None
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
        with patch("cybernova.database.redis.ConnectionPool.from_url") as mock_cpool:
            mock_cpool.side_effect = Exception("connection failed")
            result = await get_redis()
            assert result is None


@pytest.mark.asyncio
async def test_close_redis_closes_connection():
    mock_redis = AsyncMock()
    mock_redis.aclose = AsyncMock()
    mock_redis.connection_pool = MagicMock()
    mock_redis.connection_pool.disconnect = AsyncMock()

    import cybernova.database.redis as rmod
    rmod._pool = mock_redis
    await close_redis()
    assert rmod._pool is None
    mock_redis.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_redis_no_pool_does_nothing():
    import cybernova.database.redis as rmod
    rmod._pool = None
    await close_redis()


# ── Repository Tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_repo_get_by_id():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalar = MagicMock()
    scalar.scalar_one_or_none.return_value = "found"
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "tenant-1")
    result = await repo.get_by_id("alert-1")
    assert result == "found"
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_repo_list_all():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalars = MagicMock()
    scalars.scalars.return_value.all.return_value = [MagicMock(), MagicMock()]
    db.execute.return_value = scalars

    repo = BaseRepository(Alert, db, "tenant-1")
    results = await repo.list_all(limit=5, offset=10)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_repo_list_all_with_filters():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalars = MagicMock()
    scalars.scalars.return_value.all.return_value = [MagicMock()]
    db.execute.return_value = scalars

    repo = BaseRepository(Alert, db, "tenant-1")
    results = await repo.list_all(filters={"severity": "high"})
    assert len(results) == 1


@pytest.mark.asyncio
async def test_repo_list_all_with_list_filter():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalars = MagicMock()
    scalars.scalars.return_value.all.return_value = []
    db.execute.return_value = scalars

    repo = BaseRepository(Alert, db, "tenant-1")
    results = await repo.list_all(filters={"severity": ["high", "critical"]})
    assert len(results) == 0


@pytest.mark.asyncio
async def test_repo_count():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalar = MagicMock()
    scalar.scalar.return_value = 5
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "tenant-1")
    count = await repo.count()
    assert count == 5


@pytest.mark.asyncio
async def test_repo_count_with_filters():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalar = MagicMock()
    scalar.scalar.return_value = 3
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "tenant-1")
    count = await repo.count(filters={"severity": "critical"})
    assert count == 3


@pytest.mark.asyncio
async def test_repo_create_sets_tenant():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.flush = AsyncMock()

    entity = MagicMock()
    entity.tenant_id = None

    repo = BaseRepository(Alert, db, "tenant-42")
    result = await repo.create(entity)
    assert result.tenant_id == "tenant-42"
    db.add.assert_called_once_with(entity)


@pytest.mark.asyncio
async def test_repo_create_many_sets_tenant():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.flush = AsyncMock()

    e1 = MagicMock()
    e1.tenant_id = None
    e2 = MagicMock()
    e2.tenant_id = None

    repo = BaseRepository(Alert, db, "tenant-99")
    results = await repo.create_many([e1, e2])
    assert len(results) == 2
    assert db.add.call_count == 2


@pytest.mark.asyncio
async def test_repo_bulk_insert_empty_does_nothing():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    repo = BaseRepository(Alert, db, "t1")
    await repo.bulk_insert([])
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_repo_bulk_insert_adds_tenant():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock()

    repo = BaseRepository(Alert, db, "t1")
    await repo.bulk_insert([{"id": "a1", "rule_name": "test", "severity": "high"}])
    assert db.execute.called


@pytest.mark.asyncio
async def test_repo_update_fields():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.flush = AsyncMock()

    entity = MagicMock()
    entity.severity = "low"
    scalar = MagicMock()
    scalar.scalar_one_or_none.return_value = entity
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "t1")
    result = await repo.update_fields("a1", severity="critical")
    assert result.severity == "critical"


@pytest.mark.asyncio
async def test_repo_update_fields_not_found():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalar = MagicMock()
    scalar.scalar_one_or_none.return_value = None
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "t1")
    result = await repo.update_fields("nonexistent", severity="critical")
    assert result is None


@pytest.mark.asyncio
async def test_repo_delete_by_id():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.flush = AsyncMock()
    db.delete = AsyncMock()

    entity = MagicMock()
    scalar = MagicMock()
    scalar.scalar_one_or_none.return_value = entity
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "t1")
    result = await repo.delete_by_id("a1")
    assert result is True
    db.delete.assert_awaited_once_with(entity)


@pytest.mark.asyncio
async def test_repo_delete_by_id_not_found():
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    scalar = MagicMock()
    scalar.scalar_one_or_none.return_value = None
    db.execute.return_value = scalar

    repo = BaseRepository(Alert, db, "t1")
    result = await repo.delete_by_id("nonexistent")
    assert result is False


@pytest.mark.asyncio
async def test_repo_delete_older_than():
    from datetime import datetime, timezone
    from cybernova.database.repository.base import BaseRepository
    from cybernova.database.postgres.models import Alert

    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock()
    rowcount = MagicMock()
    rowcount.rowcount = 3
    db.execute.return_value = rowcount

    repo = BaseRepository(Alert, db, "t1")
    cutoff = datetime.now(timezone.utc)
    count = await repo.delete_older_than(Alert.created_at, cutoff)
    assert count == 3
