"""
Tests for SOC 2 Evidence Collector.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.compliance.evidence_collector import SOC2EvidenceCollector, soc2_evidence_collector


@pytest.fixture
def collector():
    return SOC2EvidenceCollector()


@pytest.fixture
def db():
    m = AsyncMock()
    m.execute = AsyncMock()
    return m


_UNSET = object()


def _result(scalar=_UNSET, one_or_none=_UNSET, rows=_UNSET, scalars_rows=_UNSET):
    """Build a MagicMock that mimics an async SQLAlchemy Result."""
    mr = MagicMock()
    if scalar is not _UNSET:
        mr.scalar.return_value = scalar
    if one_or_none is not _UNSET:
        mr.scalar_one_or_none.return_value = one_or_none
    if rows is not _UNSET:
        mr.__iter__.return_value = iter(rows)
    if scalars_rows is not _UNSET:
        scalars_mock = MagicMock()
        scalars_mock.__iter__.return_value = iter(scalars_rows)
        mr.scalars.return_value = scalars_mock
    return mr


TENANT = "tenant-1"


@pytest.mark.asyncio
async def test_collect_config_snapshot_returns_expected_structure(collector, db):
    """Config snapshot returns app version, detection rules, playbooks, retention."""
    # _query_detection_rules: 2 calls (count total, count enabled)
    # _query_playbooks: 2 calls (count total, count automated)
    # _query_tenant: 1 call (select Tenant) -> None
    # _query_user_summary: 2 calls (select roles, count users)
    db.execute.side_effect = [
        _result(scalar=0), _result(scalar=0),  # detection rules
        _result(scalar=0), _result(scalar=0),  # playbooks
        _result(one_or_none=None),              # tenant
        _result(scalars_rows=[]), _result(scalar=0),  # user summary
    ]

    with patch("cybernova.compliance.evidence_collector.get_settings") as mock_settings, \
         patch("cybernova.compliance.evidence_collector.retention_manager") as mock_retention:

        mock_settings.return_value.app_version = "2.0.0"
        mock_settings.return_value.environment = "production"
        mock_retention.get_policies.return_value = {}

        result = await collector.collect_config_snapshot(TENANT, db)

        assert result["app_version"] == "2.0.0"
        assert result["environment"] == "production"
        assert "detection_rules" in result
        assert "playbooks" in result
        assert "retention_policies" in result
        assert "encryption" in result
        assert result["encryption"]["tls_enabled"] is True
        assert "collected_at" in result
        assert result["status"] == "warning"


@pytest.mark.asyncio
async def test_collect_config_snapshot_includes_detection_rules(collector, db):
    """Config snapshot includes detection rule counts."""
    db.execute.side_effect = [
        _result(scalar=10), _result(scalar=7),  # detection rules (total=10, enabled=7)
        _result(scalar=0), _result(scalar=0),  # playbooks
        _result(one_or_none=None),              # tenant
        _result(scalars_rows=[]), _result(scalar=0),  # user summary
    ]

    with patch("cybernova.compliance.evidence_collector.get_settings") as mock_settings, \
         patch("cybernova.compliance.evidence_collector.retention_manager") as mock_retention:

        mock_settings.return_value.app_version = "2.0.0"
        mock_settings.return_value.environment = "production"
        mock_retention.get_policies.return_value = {}

        result = await collector.collect_config_snapshot(TENANT, db)

        assert result["detection_rules"]["total_rules"] == 10
        assert result["detection_rules"]["enabled_rules"] == 7
        assert result["detection_rules"]["disabled_rules"] == 3
        assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_config_snapshot_handles_missing_tenant(collector, db):
    """Config snapshot handles case where tenant record is missing."""
    db.execute.side_effect = [
        _result(scalar=0), _result(scalar=0),  # detection rules
        _result(scalar=0), _result(scalar=0),  # playbooks
        _result(one_or_none=None),              # tenant -> None
        _result(scalars_rows=[]), _result(scalar=0),  # user summary
    ]

    with patch("cybernova.compliance.evidence_collector.get_settings") as mock_settings, \
         patch("cybernova.compliance.evidence_collector.retention_manager") as mock_retention:

        mock_settings.return_value.app_version = "2.0.0"
        mock_settings.return_value.environment = "production"
        mock_retention.get_policies.return_value = {}

        result = await collector.collect_config_snapshot("nonexistent", db)

        assert result["tenant_plan"] == "unknown"
        assert result["tenant_active"] is False


@pytest.mark.asyncio
async def test_collect_access_logs_returns_breakdown(collector, db):
    """Access logs return period info, action breakdown, and active users."""
    # _count_audit_logs: 1 call (count)
    # _aggregate_audit_by_action: 1 call (iter rows)
    # _aggregate_audit_by_resource: 1 call (iter rows)
    # _count_active_users: 1 call (count distinct)
    db.execute.side_effect = [
        _result(scalar=100),  # total access events
        _result(rows=[("login", 40), ("login_failed", 5), ("logout", 30), ("user_created", 10), ("settings_updated", 15)]),
        _result(rows=[("user", 50), ("settings", 15), ("rule", 20), ("incident", 10), ("alert", 5)]),
        _result(scalar=12),  # active users
    ]

    result = await collector.collect_access_logs(TENANT, db, period_days=90)

    assert result["period_days"] == 90
    assert result["total_access_events"] == 100
    assert result["distinct_actions"] == 5
    assert result["actions_breakdown"]["login"] == 40
    assert result["actions_breakdown"]["login_failed"] == 5
    assert result["resources_accessed"]["user"] == 50
    assert result["failed_logins"] == 5
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_access_logs_no_data(collector, db):
    """Access logs return no_data status when no logs exist."""
    db.execute.side_effect = [
        _result(scalar=0),  # total access events = 0
        _result(rows=[]),
        _result(rows=[]),
        _result(scalar=0),
    ]

    result = await collector.collect_access_logs(TENANT, db)

    assert result["total_access_events"] == 0
    assert result["status"] == "no_data"


@pytest.mark.asyncio
async def test_collect_change_logs_returns_changes(collector, db):
    """Change logs return total changes, breakdown, and top changers."""
    # _count_audit_logs: 1 call (count with action filter)
    # _aggregate_audit_by_action: 1 call (iter rows)
    # _aggregate_audit_by_resource: 1 call (iter rows)
    # _top_users_by_action: 1 call (iter rows)
    db.execute.side_effect = [
        _result(scalar=50),  # total changes
        _result(rows=[("user_created", 15), ("rule_updated", 10), ("settings_updated", 25)]),
        _result(rows=[("user", 15), ("rule", 10), ("settings", 25)]),
        _result(rows=[("user-1", 20), ("user-2", 15), ("user-3", 10)]),
    ]

    result = await collector.collect_change_logs(TENANT, db, period_days=90)

    assert result["total_changes"] == 50
    assert result["changes_breakdown"]["user_created"] == 15
    assert result["changes_by_resource"]["user"] == 15
    assert len(result["top_changers"]) == 3
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_incident_metrics_returns_metrics(collector, db):
    """Incident metrics return counts, severity/status breakdown, and MTTR."""
    # _count_model(Incident): 1 call
    # _aggregate_incidents_by_severity: 1 call (iter rows)
    # _aggregate_incidents_by_status: 1 call (iter rows)
    # _count_model(Alert): 1 call
    # _compute_mttr: 1 call (scalar)
    # _count_open_critical: 1 call (scalar)
    db.execute.side_effect = [
        _result(scalar=20),  # total incidents
        _result(rows=[("critical", 5), ("high", 8), ("medium", 4), ("low", 3)]),
        _result(rows=[("new", 5), ("investigating", 3), ("resolved", 10), ("closed", 2)]),
        _result(scalar=7200),  # avg MTTR in seconds
        _result(scalar=5),   # total alerts
        _result(scalar=3),   # open critical
    ]

    result = await collector.collect_incident_metrics(TENANT, db, period_days=90)

    assert result["total_incidents"] == 20
    assert result["resolved_incidents"] == 10
    assert result["open_incidents"] == 10
    assert result["open_critical_incidents"] == 3
    assert result["total_alerts"] == 5
    assert result["mean_time_to_resolve_hours"] == 2.0
    assert result["severity_breakdown"]["critical"] == 5
    assert result["status_breakdown"]["resolved"] == 10
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_incident_metrics_no_resolved_returns_null_mttr(collector, db):
    """MTTR is None when no incidents are resolved."""
    db.execute.side_effect = [
        _result(scalar=0),  # total incidents
        _result(rows=[]),
        _result(rows=[]),
        _result(scalar=0),  # total alerts
        _result(scalar=None),  # mttr -> None
        _result(scalar=0),  # open critical
    ]

    result = await collector.collect_incident_metrics(TENANT, db, period_days=90)

    assert result["mean_time_to_resolve_hours"] is None


@pytest.mark.asyncio
async def test_collect_all_aggregates_all_categories(collector, db):
    """collect_all returns all four evidence categories."""
    # config_snapshot: 7 calls
    # access_logs: 4 calls
    # change_logs: 4 calls
    # incident_metrics: 6 calls
    db.execute.side_effect = [
        # config_snapshot (7)
        _result(scalar=0), _result(scalar=0),
        _result(scalar=0), _result(scalar=0),
        _result(one_or_none=None),
        _result(scalars_rows=[]), _result(scalar=0),
        # access_logs (4)
        _result(scalar=0), _result(rows=[]), _result(rows=[]), _result(scalar=0),
        # change_logs (4)
        _result(scalar=0), _result(rows=[]), _result(rows=[]), _result(rows=[]),
        # incident_metrics (6)
        _result(scalar=0), _result(rows=[]), _result(rows=[]), _result(scalar=0), _result(scalar=None), _result(scalar=0),
    ]

    with patch("cybernova.compliance.evidence_collector.get_settings") as mock_settings, \
         patch("cybernova.compliance.evidence_collector.retention_manager") as mock_retention:

        mock_settings.return_value.app_version = "2.0.0"
        mock_settings.return_value.environment = "production"
        mock_retention.get_policies.return_value = {}

        result = await collector.collect_all(TENANT, db, period_days=90)

        assert "collected_at" in result
        assert result["tenant_id"] == TENANT
        assert result["period_days"] == 90
        assert "config_snapshot" in result
        assert "access_logs" in result
        assert "change_logs" in result
        assert "incident_metrics" in result


@pytest.mark.asyncio
async def test_error_handling_returns_error_status(collector, db):
    """When DB raises, collector returns error status."""
    db.execute.side_effect = Exception("connection lost")

    with patch("cybernova.compliance.evidence_collector.get_settings") as mock_settings, \
         patch("cybernova.compliance.evidence_collector.retention_manager") as mock_retention:

        mock_settings.return_value.app_version = "2.0.0"
        mock_settings.return_value.environment = "production"
        mock_retention.get_policies.return_value = {}

        result = await collector.collect_config_snapshot(TENANT, db)

        assert result["status"] == "error"
        assert "connection lost" in result["error"]


@pytest.mark.asyncio
async def test_singleton_instance_exists():
    """Module-level singleton soc2_evidence_collector is available."""
    assert soc2_evidence_collector is not None
    assert isinstance(soc2_evidence_collector, SOC2EvidenceCollector)
