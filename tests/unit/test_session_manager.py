"""
Tests for Session Manager.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.auth.services.session_manager import (
    SessionManager, SessionRecord, InMemorySessionStore,
    session_manager,
)


@pytest.fixture
def manager():
    m = SessionManager()
    m._memory._sessions.clear()
    m._memory._user_sessions.clear()
    m._redis = None
    return m


@pytest.fixture(autouse=True)
def no_redis():
    with patch("cybernova.auth.services.session_manager.get_redis", return_value=None):
        yield


@pytest.fixture
def store():
    s = InMemorySessionStore()
    s._sessions.clear()
    s._user_sessions.clear()
    return s


# ── InMemorySessionStore ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_memory_store_set_and_get(store):
    session = SessionRecord(
        session_id="sid-1", user_id="user-1", tenant_id="tenant-1",
        username="alice", expires_at=9999999999,
    )
    await store.set(session, 3600)
    result = await store.get("sid-1")
    assert result is not None
    assert result.user_id == "user-1"
    assert result.username == "alice"


@pytest.mark.asyncio
async def test_memory_store_get_missing(store):
    result = await store.get("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_memory_store_delete(store):
    session = SessionRecord(
        session_id="sid-1", user_id="user-1", tenant_id="tenant-1",
        username="alice", expires_at=9999999999,
    )
    await store.set(session, 3600)
    assert await store.delete("sid-1") is True
    assert await store.get("sid-1") is None


@pytest.mark.asyncio
async def test_memory_store_delete_missing(store):
    assert await store.delete("nonexistent") is False


@pytest.mark.asyncio
async def test_memory_store_get_user_sessions(store):
    s1 = SessionRecord(session_id="s1", user_id="u1", tenant_id="t1", username="a", expires_at=9999999999)
    s2 = SessionRecord(session_id="s2", user_id="u1", tenant_id="t1", username="a", expires_at=9999999999)
    s3 = SessionRecord(session_id="s3", user_id="u2", tenant_id="t1", username="b", expires_at=9999999999)
    await store.set(s1, 3600)
    await store.set(s2, 3600)
    await store.set(s3, 3600)

    sessions = await store.get_user_sessions("t1", "u1")
    assert len(sessions) == 2


@pytest.mark.asyncio
async def test_memory_store_delete_user_sessions(store):
    s1 = SessionRecord(session_id="s1", user_id="u1", tenant_id="t1", username="a", expires_at=9999999999)
    s2 = SessionRecord(session_id="s2", user_id="u1", tenant_id="t1", username="a", expires_at=9999999999)
    await store.set(s1, 3600)
    await store.set(s2, 3600)

    count = await store.delete_user_sessions("t1", "u1")
    assert count == 2
    assert await store.get_user_sessions("t1", "u1") == []


@pytest.mark.asyncio
async def test_memory_store_cleanup_expired(store):
    s1 = SessionRecord(session_id="s1", user_id="u1", tenant_id="t1", username="a", expires_at=100)
    s2 = SessionRecord(session_id="s2", user_id="u1", tenant_id="t1", username="a", expires_at=9999999999)
    await store.set(s1, 3600)
    await store.set(s2, 3600)

    count = await store.cleanup_expired()
    assert count == 1
    assert await store.get("s1") is None
    assert await store.get("s2") is not None


# ── Create Session ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session_returns_record(manager):
    session = await manager.create_session(
        user_id="user-1", tenant_id="tenant-1",
        username="alice", roles=["viewer"],
        ip_address="192.168.1.1",
    )
    assert session.session_id is not None
    assert session.user_id == "user-1"
    assert session.tenant_id == "tenant-1"
    assert session.username == "alice"
    assert session.roles == ["viewer"]
    assert session.ip_address == "192.168.1.1"
    assert session.is_active is True
    assert session.expires_at > session.created_at


@pytest.mark.asyncio
async def test_create_session_enforces_concurrent_limit(manager):
    sessions = []
    for i in range(6):
        s = await manager.create_session(
            user_id="user-1", tenant_id="tenant-1",
            username="alice", max_concurrent=3,
        )
        sessions.append(s)

    active = await manager.list_user_sessions("tenant-1", "user-1")
    assert len(active) <= 3


# ── Get / Validate Session ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_session_returns_session(manager):
    created = await manager.create_session("u1", "t1", "alice")
    retrieved = await manager.get_session(created.session_id)
    assert retrieved is not None
    assert retrieved.session_id == created.session_id
    assert retrieved.user_id == "u1"


@pytest.mark.asyncio
async def test_get_session_missing(manager):
    result = await manager.get_session("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_validate_session_valid(manager):
    created = await manager.create_session("u1", "t1", "alice")
    assert await manager.validate_session(created.session_id) is True


@pytest.mark.asyncio
async def test_validate_session_missing(manager):
    assert await manager.validate_session("nonexistent") is False


# ── Revoke Session ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_revoke_session(manager):
    created = await manager.create_session("u1", "t1", "alice")
    assert await manager.revoke_session(created.session_id) is True
    assert await manager.validate_session(created.session_id) is False


@pytest.mark.asyncio
async def test_revoke_session_missing(manager):
    assert await manager.revoke_session("nonexistent") is False


# ── Revoke User Sessions ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_revoke_user_sessions(manager):
    await manager.create_session("u1", "t1", "alice")
    await manager.create_session("u1", "t1", "alice")
    await manager.create_session("u2", "t1", "bob")

    count = await manager.revoke_user_sessions("t1", "u1")
    assert count == 2

    user_sessions = await manager.list_user_sessions("t1", "u1")
    assert len(user_sessions) == 0

    bob_sessions = await manager.list_user_sessions("t1", "u2")
    assert len(bob_sessions) == 1


# ── List Sessions ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_user_sessions(manager):
    await manager.create_session("u1", "t1", "alice", ip_address="10.0.0.1")
    await manager.create_session("u1", "t1", "alice", ip_address="10.0.0.2")

    sessions = await manager.list_user_sessions("t1", "u1")
    assert len(sessions) == 2
    ips = {s["ip_address"] for s in sessions}
    assert ips == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.asyncio
async def test_list_user_sessions_empty(manager):
    sessions = await manager.list_user_sessions("t1", "no-one")
    assert sessions == []


# ── Start / Stop ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_stop(manager):
    await manager.start(interval=99999)
    assert manager._running is True
    assert manager._task is not None

    await manager.stop()
    assert manager._running is False


# ── Get Stats ─────────────────────────────────────────────────

def test_get_stats(manager):
    stats = manager.get_stats()
    assert "memory_session_count" in stats
    assert "redis_connected" in stats
    assert stats["redis_connected"] is False
    assert "default_max_concurrent" in stats


# ── Singleton ─────────────────────────────────────────────────────

def test_singleton_instance_exists():
    assert session_manager is not None
    assert isinstance(session_manager, SessionManager)
