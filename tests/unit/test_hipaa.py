"""
Tests for HIPAA Evidence Collector.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.compliance.hipaa import (
    HIPAAComplianceCollector, BAARegistry, BAARecord,
    hipaa_collector, baa_registry,
)


TENANT = "tenant-1"
_UNSET = object()


def _result(scalar=_UNSET, rows=_UNSET, scalars_rows=_UNSET):
    mr = MagicMock()
    if scalar is not _UNSET:
        mr.scalar.return_value = scalar
    if rows is not _UNSET:
        mr.__iter__.return_value = iter(rows)
    if scalars_rows is not _UNSET:
        sm = MagicMock()
        sm.__iter__.return_value = iter(scalars_rows)
        mr.scalars.return_value = sm
    return mr


@pytest.fixture
def collector():
    return HIPAAComplianceCollector()


@pytest.fixture
def db():
    m = MagicMock()
    m.execute = AsyncMock()
    return m


@pytest.fixture(autouse=True)
def clear_baa_registry():
    baa_registry._baas.clear()
    yield


# ── BAA Evidence ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_baa_evidence_no_baas(collector, db):
    """BAA evidence returns warning when no BAAs recorded."""
    result = await collector.collect_baa_evidence(TENANT, db)

    assert result["baa_count"] == 0
    assert result["status"] == "warning"


@pytest.mark.asyncio
async def test_collect_baa_evidence_with_active_baas(collector, db):
    """BAA evidence returns compliant when all BAAs are active."""
    baa_registry.record_baa("Hospital A", status="signed")
    baa_registry.record_baa("Clinic B", status="signed")

    result = await collector.collect_baa_evidence(TENANT, db)

    assert result["baa_count"] == 2
    assert result["baa_status"]["active_baas"] == 2
    assert result["status"] == "compliant"


@pytest.mark.asyncio
async def test_collect_baa_evidence_with_expired_baa(collector, db):
    """BAA evidence returns warning when a BAA is expired."""
    baa_registry.record_baa("Hospital A", status="signed")
    baa_registry.record_baa("Old Clinic", status="expired")

    result = await collector.collect_baa_evidence(TENANT, db)

    assert result["baa_count"] == 2
    assert result["baa_status"]["active_baas"] == 1
    assert result["baa_status"]["expired_baas"] == 1
    assert result["status"] == "warning"


# ── BAA Registry ─────────────────────────────────────────────────

def test_baa_registry_record():
    """BAARegistry records a new BAA."""
    registry = BAARegistry()
    baa = registry.record_baa("Test Clinic", status="signed")

    assert baa.covered_entity == "Test Clinic"
    assert baa.status == "signed"
    assert baa.baa_id is not None
    assert len(registry.get_baas()) == 1


def test_baa_registry_filter_by_status():
    """BAARegistry filters BAAs by status."""
    registry = BAARegistry()
    registry.record_baa("A", status="signed")
    registry.record_baa("B", status="pending")
    registry.record_baa("C", status="terminated")

    assert len(registry.get_baas("signed")) == 1
    assert len(registry.get_baas("pending")) == 1
    assert len(registry.get_baas("terminated")) == 1


def test_baa_registry_overall_status():
    """BAARegistry overall_status returns correct counts."""
    registry = BAARegistry()
    registry.record_baa("A", status="signed")
    registry.record_baa("B", status="signed")
    registry.record_baa("C", status="expired")
    registry.record_baa("D", status="pending")

    status = registry.overall_status()
    assert status["total_baas"] == 4
    assert status["active_baas"] == 2
    assert status["expired_baas"] == 1
    assert status["pending_baas"] == 1
    assert status["all_baas_active"] is False


def test_baa_registry_count_active():
    """BAARegistry count_active returns signed BAAs that haven't expired."""
    registry = BAARegistry()
    registry.record_baa("A", status="signed")
    registry.record_baa("B", status="expired")

    assert registry.count_active() == 1


# ── PHI Access Logs ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_phi_access_logs_returns_breakdown(collector, db):
    """PHI access logs return action/resource breakdown and security events."""
    db.execute.side_effect = [
        _result(scalar=300),  # total
        _result(rows=[
            ("login", 120), ("alert_updated", 40), ("incident_created", 30),
            ("user_created", 20), ("settings_updated", 50), ("login_failed", 25),
            ("password_changed", 10), ("permission_denied", 5),
        ]),
        _result(rows=[
            ("user", 140), ("alert", 40), ("incident", 30),
            ("device", 60), ("settings", 30),
        ]),
        _result(scalar=20),  # active users
        _result(rows=[
            ("user-1", 80), ("user-2", 60), ("user-3", 40),
        ]),
        # _count_security_events — 2 calls
        _result(scalar=40),  # total
        _result(rows=[
            ("login_failed", 25), ("password_changed", 10), ("permission_denied", 5),
        ]),
        # _collect_ip_exposure — 2 calls
        _result(scalar=15),  # distinct IPs
        _result(scalar=200),  # total with IP
    ]

    result = await collector.collect_phi_access_logs(TENANT, db, period_days=90)

    assert result["total_phi_access_events"] == 300
    assert result["actions_breakdown"]["login"] == 120
    assert result["resources_accessed"]["user"] == 140
    assert result["active_phi_users"] == 20
    assert len(result["top_phi_users"]) == 3
    assert result["security_events"]["total_security_events"] == 40
    assert result["ip_exposure"]["distinct_ip_addresses"] == 15
    assert result["ip_exposure"]["total_logs_with_ip"] == 200
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_phi_access_logs_no_data(collector, db):
    """PHI access logs return no_data when no entries."""
    db.execute.side_effect = [
        _result(scalar=0), _result(rows=[]), _result(rows=[]),
        _result(scalar=0), _result(rows=[]),
        _result(scalar=0), _result(rows=[]),
        _result(scalar=0), _result(scalar=0),
    ]

    result = await collector.collect_phi_access_logs(TENANT, db)

    assert result["total_phi_access_events"] == 0
    assert result["status"] == "no_data"


# ── Encryption Verification ──────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_encryption_with_custom_secret(collector, db):
    """Encryption verification reports compliant when custom secret is set."""
    with patch("cybernova.compliance.hipaa.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "a-real-secret-key-that-is-not-default-64-chars"
        mock_settings.return_value.max_login_attempts = 5
        mock_settings.return_value.lockout_minutes = 15
        mock_settings.return_value.rate_limit = 100

        db.execute.side_effect = [_result(scalar=25)]  # total_phi_users

        result = await collector.verify_encryption(TENANT, db)

        assert result["encryption_at_rest"] is True
        assert result["tls_enabled"] is True
        assert result["jwt_algorithm"] == "HS256"
        assert result["has_custom_jwt_secret"] is True
        assert result["status"] == "compliant"


@pytest.mark.asyncio
async def test_verify_encryption_default_secret_warns(collector, db):
    """Encryption verification warns when default JWT secret is used."""
    with patch("cybernova.compliance.hipaa.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING"
        mock_settings.return_value.max_login_attempts = 5
        mock_settings.return_value.lockout_minutes = 15
        mock_settings.return_value.rate_limit = 100

        db.execute.side_effect = [_result(scalar=0)]

        result = await collector.verify_encryption(TENANT, db)

        assert result["has_custom_jwt_secret"] is False
        assert result["status"] == "warning"


# ── Collect All ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_all_aggregates_all_categories(collector, db):
    """collect_all returns BAA evidence, PHI access logs, and encryption verification."""
    baa_registry.record_baa("Test Hospital", status="signed")

    db.execute.side_effect = [
        # collect_phi_access_logs (9 calls)
        _result(scalar=1),
        _result(rows=[("login", 1)]),
        _result(rows=[("user", 1)]),
        _result(scalar=1),
        _result(rows=[("user-1", 1)]),
        _result(scalar=1),
        _result(rows=[("login_failed", 1)]),
        _result(scalar=1),
        _result(scalar=1),
        # verify_encryption (1 call)
        _result(scalar=1),
    ]

    with patch("cybernova.compliance.hipaa.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "custom-secret"
        mock_settings.return_value.max_login_attempts = 5
        mock_settings.return_value.lockout_minutes = 15
        mock_settings.return_value.rate_limit = 100

        result = await collector.collect_all(TENANT, db, period_days=90)

    assert "collected_at" in result
    assert result["tenant_id"] == TENANT
    assert result["period_days"] == 90
    assert "baa_evidence" in result
    assert "phi_access_logs" in result
    assert "encryption_verification" in result


# ── Error Handling ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_baa_evidence_error(collector, db):
    """BAA evidence returns error on exception."""
    result = await collector.collect_baa_evidence(TENANT, db)
    assert result["status"] == "warning"  # no exception — just no BAAs

    # Force an exception by patching baa_registry to raise
    with patch.object(baa_registry, "overall_status", side_effect=Exception("registry fail")):
        result = await collector.collect_baa_evidence(TENANT, db)
        assert result["status"] == "error"
        assert "registry fail" in result["error"]


# ── Singletons ───────────────────────────────────────────────────

def test_singleton_instance_exists():
    """Module-level singleton hipaa_collector is available."""
    assert hipaa_collector is not None
    assert isinstance(hipaa_collector, HIPAAComplianceCollector)


def test_baa_registry_singleton_exists():
    """Module-level baa_registry singleton is available."""
    assert baa_registry is not None
    assert isinstance(baa_registry, BAARegistry)
