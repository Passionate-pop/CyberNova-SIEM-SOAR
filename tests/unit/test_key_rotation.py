"""
Tests for API Key Rotation Service.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.auth.services.key_rotation import (
    KeyRotationService, ServiceKeyInfo, key_rotation_service,
)


@pytest.fixture
def service():
    svc = KeyRotationService()
    svc._keys.clear()
    return svc


@pytest.fixture
def db():
    m = MagicMock()
    m.execute = AsyncMock()
    m.flush = AsyncMock()
    m.add = MagicMock()
    return m


# ── Key Generation ─────────────────────────────────────────────────

def test_generate_raw_key_has_prefix(service):
    key = service._generate_raw_key()
    assert key.startswith("svc:")
    assert len(key) > 40


def test_hash_key_produces_sha256(service):
    raw = "svc:test-key-value"
    h = service._hash_key(raw)
    assert len(h) == 64
    assert h == service._hash_key(raw)  # deterministic


# ── Register Service Key ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_service_key_creates_api_key(service, db):
    result = await service.register_service_key("pipeline-worker", db)

    assert result["service_name"] == "pipeline-worker"
    assert result["api_key"].startswith("svc:")
    assert "key_id" in result
    assert db.add.call_count >= 1
    assert service._keys["pipeline-worker"].service_name == "pipeline-worker"


@pytest.mark.asyncio
async def test_register_service_key_tracks_info(service, db):
    await service.register_service_key("detection-engine", db, rate_limit=500)

    info = service._keys["detection-engine"]
    assert info.service_name == "detection-engine"
    assert info.current_key_hash is not None
    assert info.last_rotated_at is not None


# ── Single Key Rotation ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_rotate_key_preserves_old_key(service, db):
    await service.register_service_key("worker", db)
    old_hash = service._keys["worker"].current_key_hash

    result = await service.rotate_key("worker", db)

    assert result["service_name"] == "worker"
    assert result["api_key"].startswith("svc:")
    assert service._keys["worker"].previous_key_hash == old_hash
    assert service._keys["worker"].current_key_hash != old_hash
    assert service._keys["worker"].previous_expires_at is not None


@pytest.mark.asyncio
async def test_rotate_key_unknown_service_raises(service, db):
    mr = MagicMock()
    mr.scalar_one_or_none.return_value = None
    db.execute.return_value = mr
    with pytest.raises(ValueError, match="No registered service key for 'unknown'"):
        await service.rotate_key("unknown", db)


# ── Deactivate Old Keys ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_deactivate_old_keys_skips_fresh_keys(service, db):
    await service.register_service_key("worker", db)
    count = await service.deactivate_old_keys(db)
    assert count == 0


@pytest.mark.asyncio
async def test_deactivate_old_keys_removes_expired(service, db):
    await service.register_service_key("worker", db)

    info = service._keys["worker"]
    info.previous_key_hash = "fake-old-hash"
    info.previous_expires_at = "2020-01-01T00:00:00"

    mr = MagicMock()
    mr.scalar_one_or_none.return_value = None
    db.execute.side_effect = [mr]

    count = await service.deactivate_old_keys(db)
    assert count == 0
    assert info.previous_key_hash == ""
    assert info.previous_expires_at is None


# ── Rotate All ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rotate_all_rotates_registered_keys(service, db):
    await service.register_service_key("svc-a", db)
    await service.register_service_key("svc-b", db)

    db.add = MagicMock()

    result = await service.rotate_all(db)

    assert result["rotated"] == 2
    assert result["errors"] == 0
    assert "old_keys_deactivated" in result


# ── List Service Keys ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_service_keys_no_keys(service, db):
    mr = MagicMock()
    sm = MagicMock()
    sm.all.return_value = []
    mr.scalars.return_value = sm
    db.execute.return_value = mr
    keys = await service.list_service_keys(db)
    assert keys == []


@pytest.mark.asyncio
async def test_list_service_keys_with_keys(service, db):
    await service.register_service_key("svc-a", db)

    mock_key = MagicMock()
    mock_key.id = "key-1"
    mock_key.name = "svc:svc-a"
    mock_key.is_active = True
    mock_key.created_at = MagicMock()
    mock_key.created_at.isoformat.return_value = "2024-01-01T00:00:00"
    mock_key.last_used_at = None
    mock_key.rate_limit = 1000

    mr = MagicMock()
    sm = MagicMock()
    sm.all.return_value = [mock_key]
    mr.scalars.return_value = sm
    db.execute.return_value = mr

    keys = await service.list_service_keys(db)
    assert len(keys) >= 1


# ── Get Status ────────────────────────────────────────────────────

def test_get_status_empty(service):
    status = service.get_status()
    assert status["managed_services"] == 0
    assert status["is_running"] is False
    assert status["overlap_hours"] == 48


def test_get_status_with_services(service, db):
    import asyncio
    service._keys["svc-a"] = ServiceKeyInfo(
        service_name="svc-a",
        current_key_hash="hash-a",
        created_at="2024-01-01T00:00:00",
        last_rotated_at="2024-01-01T00:00:00",
        key_id="key-a",
    )

    status = service.get_status()
    assert status["managed_services"] == 1
    assert status["services"][0]["service_name"] == "svc-a"


# ── Start / Stop ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_stop_loop(service):
    await service.start(interval=99999)
    assert service._running is True
    assert service._task is not None

    await service.stop()
    assert service._running is False


# ── Singleton ─────────────────────────────────────────────────────

def test_singleton_instance_exists():
    assert key_rotation_service is not None
    assert isinstance(key_rotation_service, KeyRotationService)
