"""Unit tests for database/postgres/session.py — targeting 80%+ line coverage."""

from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from cybernova.database.postgres.session import (
    compute_pool_size, compute_max_overflow, get_db, get_db_session,
)


class TestComputePoolSize:
    def test_explicit_setting_used(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_pool_size = 25
            s.db_expected_eps = 10000
            s.db_batch_size = 100
            assert compute_pool_size() == 25

    def test_auto_at_10k_eps(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_pool_size = 0
            s.db_expected_eps = 10000
            s.db_batch_size = 100
            # 10000/1000 + 100/50 = 10 + 2 = 12
            assert compute_pool_size() == 12

    def test_auto_at_50k_eps(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_pool_size = 0
            s.db_expected_eps = 50000
            s.db_batch_size = 100
            # 50000/1000 + 100/50 = 50 + 2 = 52 -> clamped to 50
            assert compute_pool_size() == 50

    def test_minimum_floor(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_pool_size = 0
            s.db_expected_eps = 100
            s.db_batch_size = 1
            # 100/1000 + 1/50 = 0.1 + 0.02 = 0.12 -> ceil = 1, clamped min 10
            assert compute_pool_size() == 10

    def test_min_eps_batch_safety(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_pool_size = 0
            s.db_expected_eps = 0
            s.db_batch_size = 0
            # eps maxed to 1000, batch maxed to 1: 1000/1000 + 1/50 = 1.02 -> ceil = 2, clamped min 10
            assert compute_pool_size() == 10


class TestComputeMaxOverflow:
    def test_explicit_setting_used(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_max_overflow = 15
            s.db_pool_size = 10
            assert compute_max_overflow() == 15

    def test_auto_half_pool(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_max_overflow = 0
            with patch("cybernova.database.postgres.session.compute_pool_size", return_value=20):
                assert compute_max_overflow() == 10

    def test_minimum_floor(self):
        with patch("cybernova.database.postgres.session.settings") as s:
            s.db_max_overflow = 0
            with patch("cybernova.database.postgres.session.compute_pool_size", return_value=4):
                assert compute_max_overflow() == 5


@pytest.mark.asyncio
async def test_get_db_commits_on_success():
    mock_session = AsyncMock()
    mock_factory = AsyncMock()
    mock_factory.__aenter__.return_value = mock_session
    mock_factory.__aexit__.return_value = None

    with patch("cybernova.database.postgres.session.async_session_factory", return_value=mock_factory):
        async for session in get_db():
            assert session is mock_session
        mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_db_rollback_on_error():
    mock_session = AsyncMock()
    mock_factory = AsyncMock()
    mock_factory.__aenter__.return_value = mock_session
    mock_factory.__aexit__.return_value = None

    with patch("cybernova.database.postgres.session.async_session_factory", return_value=mock_factory):
        gen = get_db()
        session = await gen.__anext__()
        assert session is mock_session
        with pytest.raises(RuntimeError, match="test error"):
            await gen.athrow(RuntimeError("test error"))
        mock_session.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_db_session_commits_on_success():
    mock_session = AsyncMock()
    mock_factory = AsyncMock()
    mock_factory.__aenter__.return_value = mock_session
    mock_factory.__aexit__.return_value = None

    with patch("cybernova.database.postgres.session.async_session_factory", return_value=mock_factory):
        async for session in get_db_session():
            assert session is mock_session
        mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_db_session_rollback_on_error():
    mock_session = AsyncMock()
    mock_factory = AsyncMock()
    mock_factory.__aenter__.return_value = mock_session
    mock_factory.__aexit__.return_value = None

    with patch("cybernova.database.postgres.session.async_session_factory", return_value=mock_factory):
        gen = get_db_session()
        session = await gen.__anext__()
        assert session is mock_session
        with pytest.raises(ValueError, match="test error"):
            await gen.athrow(ValueError("test error"))
        mock_session.rollback.assert_awaited_once()
