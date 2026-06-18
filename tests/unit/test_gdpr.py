"""
Tests for GDPR Evidence Collector.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.compliance.gdpr import (
    GDPRComplianceCollector, DPIARegistry, DPIARecord,
    DataSubjectRequestRegistry, DataSubjectRequestRecord,
    ConsentRegistry, ConsentRecord,
    gdpr_collector, dpia_registry, dsar_registry, consent_registry,
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
    return GDPRComplianceCollector()


@pytest.fixture
def db():
    m = MagicMock()
    m.execute = AsyncMock()
    return m


@pytest.fixture(autouse=True)
def clear_registries():
    dpia_registry._dpias.clear()
    dsar_registry._requests.clear()
    consent_registry._consents.clear()
    yield


# ── DPIA Registry ──────────────────────────────────────────────────

def test_dpia_registry_record():
    registry = DPIARegistry()
    dpia = registry.record_dpia(
        "Employee data processing", risk_level="high",
        status="approved", data_categories=["names", "emails"],
    )

    assert dpia.processing_activity == "Employee data processing"
    assert dpia.risk_level == "high"
    assert dpia.status == "approved"
    assert dpia.data_categories == ["names", "emails"]
    assert dpia.dpia_id is not None
    assert len(registry.get_dpias()) == 1


def test_dpia_registry_filter_by_status():
    registry = DPIARegistry()
    registry.record_dpia("Activity A", status="draft")
    registry.record_dpia("Activity B", status="approved")
    registry.record_dpia("Activity C", status="reviewed")

    assert len(registry.get_dpias("draft")) == 1
    assert len(registry.get_dpias("approved")) == 1
    assert len(registry.get_dpias("reviewed")) == 1


def test_dpia_registry_count_high_risk():
    registry = DPIARegistry()
    registry.record_dpia("Activity A", risk_level="high")
    registry.record_dpia("Activity B", risk_level="medium")
    registry.record_dpia("Activity C", risk_level="high")

    assert registry.count_high_risk() == 2


def test_dpia_registry_overall_status():
    registry = DPIARegistry()
    registry.record_dpia("A", risk_level="high", status="approved")
    registry.record_dpia("B", risk_level="medium", status="approved")
    registry.record_dpia("C", risk_level="low", status="draft")

    status = registry.overall_status()
    assert status["total_dpias"] == 3
    assert status["high_risk_dpias"] == 1
    assert status["all_approved"] is False
    assert status["status_breakdown"]["approved"] == 2


# ── Data Subject Request Registry ─────────────────────────────────

def test_dsar_registry_record():
    registry = DataSubjectRequestRegistry()
    req = registry.record_request("user-1", request_type="deletion")

    assert req.user_id == "user-1"
    assert req.request_type == "deletion"
    assert req.status == "submitted"
    assert req.request_id is not None


def test_dsar_registry_complete_request():
    registry = DataSubjectRequestRegistry()
    req = registry.record_request("user-1", request_type="access")
    assert req.status == "submitted"

    result = registry.complete_request(req.request_id, "Data exported to user")
    assert result is True
    assert req.status == "completed"
    assert req.completed_at != ""


def test_dsar_registry_complete_nonexistent():
    registry = DataSubjectRequestRegistry()
    result = registry.complete_request("nonexistent")
    assert result is False


def test_dsar_registry_filter():
    registry = DataSubjectRequestRegistry()
    registry.record_request("user-1", request_type="access")
    registry.record_request("user-2", request_type="deletion")

    access = registry.get_requests(request_type="access")
    assert len(access) == 1

    deletion = registry.get_requests(request_type="deletion")
    assert len(deletion) == 1


def test_dsar_registry_overall_status():
    registry = DataSubjectRequestRegistry()
    r1 = registry.record_request("user-1", request_type="access")
    registry.record_request("user-2", request_type="deletion")
    registry.complete_request(r1.request_id)

    status = registry.overall_status()
    assert status["total_requests"] == 2
    assert status["completed_requests"] == 1
    assert status["pending_requests"] == 1


# ── Consent Registry ───────────────────────────────────────────────

def test_consent_registry_grant():
    registry = ConsentRegistry()
    consent = registry.grant_consent("user-1", "marketing")

    assert consent.user_id == "user-1"
    assert consent.purpose == "marketing"
    assert consent.granted is True
    assert consent.consent_id is not None


def test_consent_registry_revoke():
    registry = ConsentRegistry()
    consent = registry.grant_consent("user-1", "marketing")
    assert consent.granted is True

    result = registry.revoke_consent("user-1", "marketing")
    assert result is True
    assert consent.granted is False
    assert consent.revoked_at != ""


def test_consent_registry_revoke_nonexistent():
    registry = ConsentRegistry()
    result = registry.revoke_consent("nobody", "spam")
    assert result is False


def test_consent_registry_get_active():
    registry = ConsentRegistry()
    registry.grant_consent("user-1", "marketing")
    registry.grant_consent("user-2", "analytics")
    registry.revoke_consent("user-1", "marketing")

    active = registry.get_active_consents()
    assert len(active) == 1
    assert active[0].user_id == "user-2"


def test_consent_registry_overall_status():
    registry = ConsentRegistry()
    registry.grant_consent("user-1", "marketing")
    registry.grant_consent("user-2", "analytics")
    registry.revoke_consent("user-1", "marketing")

    status = registry.overall_status()
    assert status["total_consents"] == 2
    assert status["active_consents"] == 1
    assert status["revoked_consents"] == 1
    assert "marketing" in status["distinct_purposes"]


# ── Data Subject Access Logs ───────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_data_subject_access_logs_returns_breakdown(collector, db):
    db.execute.side_effect = [
        _result(scalar=250),
        _result(rows=[
            ("login", 100), ("user_created", 30), ("settings_updated", 50),
            ("email_changed", 10), ("password_changed", 20), ("login_failed", 40),
        ]),
        _result(rows=[
            ("user", 120), ("settings", 80), ("profile", 30), ("email", 20),
        ]),
        _result(scalar=15),
        _result(rows=[
            ("user-1", 60), ("user-2", 40), ("user-3", 30),
        ]),
    ]

    result = await collector.collect_data_subject_access_logs(TENANT, db, period_days=90)

    assert result["total_pii_access_events"] == 250
    assert result["actions_breakdown"]["login"] == 100
    assert result["resources_accessed"]["user"] == 120
    assert result["active_users_with_pii_access"] == 15
    assert len(result["top_users"]) == 3
    assert result["data_subject_requests"]["total_requests"] == 0
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_data_subject_access_logs_no_data(collector, db):
    db.execute.side_effect = [
        _result(scalar=0), _result(rows=[]), _result(rows=[]),
        _result(scalar=0), _result(rows=[]),
    ]

    result = await collector.collect_data_subject_access_logs(TENANT, db)

    assert result["total_pii_access_events"] == 0
    assert result["status"] == "no_data"


# ── Deletion Evidence ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_deletion_evidence_with_requests(collector, db):
    r1 = dsar_registry.record_request("user-1", request_type="deletion")
    dsar_registry.complete_request(r1.request_id, "Account deleted")
    dsar_registry.record_request("user-2", request_type="deletion")

    db.execute.side_effect = [
        _result(scalar=5),
    ]

    result = await collector.collect_deletion_evidence(TENANT, db, period_days=90)

    assert result["completed_deletion_requests"] == 1
    assert result["pending_deletion_requests"] == 1
    assert result["audit_log_user_deletions"] == 5
    assert len(result["deletion_requests"]) == 2
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_deletion_evidence_no_data(collector, db):
    db.execute.side_effect = [_result(scalar=0)]

    result = await collector.collect_deletion_evidence(TENANT, db)

    assert result["completed_deletion_requests"] == 0
    assert result["pending_deletion_requests"] == 0
    assert result["status"] == "no_data"


# ── DPIA Evidence ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_dpia_evidence_no_dpias(collector, db):
    result = await collector.collect_dpia_evidence(TENANT, db)

    assert result["dpia_count"] == 0
    assert result["status"] == "warning"


@pytest.mark.asyncio
async def test_collect_dpia_evidence_with_dpias(collector, db):
    dpia_registry.record_dpia(
        "Employee monitoring", risk_level="high",
        status="approved", data_categories=["location", "activity"],
    )
    dpia_registry.record_dpia(
        "Customer analytics", risk_level="medium",
        status="approved",
    )

    result = await collector.collect_dpia_evidence(TENANT, db)

    assert result["dpia_count"] == 2
    assert result["dpia_status"]["high_risk_dpias"] == 1
    assert result["high_risk_count"] == 1
    assert result["status"] == "compliant"


# ── Retention Enforcement ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_retention_enforcement(collector, db):
    result = await collector.collect_retention_enforcement(TENANT, db)

    assert result["policy_count"] > 0
    assert "retention_policies" in result
    assert "pii_retention_check" in result
    assert "residency_retention_check" in result
    assert result["status"] == "active"


# ── Consent Evidence ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_consent_evidence_no_consents(collector, db):
    result = await collector.collect_consent_evidence(TENANT, db)

    assert result["consent_count"] == 0
    assert result["status"] == "no_data"


@pytest.mark.asyncio
async def test_collect_consent_evidence_with_consents(collector, db):
    consent_registry.grant_consent("user-1", "marketing")
    consent_registry.grant_consent("user-1", "analytics")
    consent_registry.grant_consent("user-2", "marketing")

    result = await collector.collect_consent_evidence(TENANT, db)

    assert result["consent_count"] == 3
    assert result["consent_status"]["active_consents"] == 3
    assert len(result["active_consents"]) == 3
    assert result["status"] == "active"


# ── Collect All ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_all_aggregates_all_categories(collector, db):
    dpia_registry.record_dpia("Test processing", status="approved")
    consent_registry.grant_consent("user-1", "marketing")

    db.execute.side_effect = [
        # collect_data_subject_access_logs (5 calls)
        _result(scalar=1),
        _result(rows=[("login", 1)]),
        _result(rows=[("user", 1)]),
        _result(scalar=1),
        _result(rows=[("user-1", 1)]),
        # collect_deletion_evidence (1 call)
        _result(scalar=0),
    ]

    result = await collector.collect_all(TENANT, db, period_days=90)

    assert "collected_at" in result
    assert result["tenant_id"] == TENANT
    assert result["period_days"] == 90
    assert "data_subject_access_logs" in result
    assert "deletion_evidence" in result
    assert "dpia_evidence" in result
    assert "retention_enforcement" in result
    assert "consent_evidence" in result


# ── Error Handling ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_data_subject_access_logs_error(collector, db):
    db.execute.side_effect = Exception("db timeout")
    result = await collector.collect_data_subject_access_logs(TENANT, db)
    assert result["status"] == "error"
    assert "db timeout" in result["error"]


@pytest.mark.asyncio
async def test_dpia_evidence_error(collector, db):
    with patch.object(dpia_registry, "overall_status", side_effect=Exception("registry fail")):
        result = await collector.collect_dpia_evidence(TENANT, db)
        assert result["status"] == "error"
        assert "registry fail" in result["error"]


# ── Singletons ─────────────────────────────────────────────────────

def test_singleton_instance_exists():
    assert gdpr_collector is not None
    assert isinstance(gdpr_collector, GDPRComplianceCollector)


def test_dpia_registry_singleton_exists():
    assert dpia_registry is not None
    assert isinstance(dpia_registry, DPIARegistry)


def test_dsar_registry_singleton_exists():
    assert dsar_registry is not None
    assert isinstance(dsar_registry, DataSubjectRequestRegistry)


def test_consent_registry_singleton_exists():
    assert consent_registry is not None
    assert isinstance(consent_registry, ConsentRegistry)
