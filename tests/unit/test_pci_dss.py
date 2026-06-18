"""
Tests for PCI DSS Evidence Collector.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.compliance.pci_dss import (
    PCIComplianceCollector, ScanRegistry, PCIDSSScanRecord,
    pci_collector, scan_registry,
)


TENANT = "tenant-1"
_UNSET = object()


def _result(scalar=_UNSET, rows=_UNSET, scalars_rows=_UNSET):
    """Build a MagicMock that mimics an async SQLAlchemy Result."""
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
    return PCIComplianceCollector()


@pytest.fixture
def db():
    m = MagicMock()
    m.execute = AsyncMock()
    return m


@pytest.fixture(autouse=True)
def clear_scan_registry():
    scan_registry._scans.clear()
    yield


# ── CDE Detection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detect_cde_components_returns_structure(collector, db):
    """CDE detection returns devices, api_keys, users, blocked_ips, chd_indicators."""
    db.execute.side_effect = [
        # _collect_devices (3)
        _result(scalar=10), _result(scalar=8), _result(scalar=3),
        # _collect_api_keys (2)
        _result(scalar=5), _result(scalar=4),
        # _collect_users (2)
        _result(scalar=20), _result(scalar=18),
        # _collect_blocked_ips (2)
        _result(scalar=15), _result(scalar=12),
        # _collect_chd_indicators (3)
        _result(scalar=50), _result(scalar=10), _result(scalar=8),
        # _network_exposure (1)
        _result(scalar=6),
    ]

    result = await collector.detect_cde_components(TENANT, db)

    assert result["total_cde_components"] == 35
    assert result["devices"]["total_devices"] == 10
    assert result["devices"]["active_devices"] == 8
    assert result["api_keys"]["total_keys"] == 5
    assert result["api_keys"]["active_keys"] == 4
    assert result["users"]["total_users"] == 20
    assert result["blocked_ips"]["total_blocked_ips"] == 15
    assert result["blocked_ips"]["active_blocked_ips"] == 12
    assert result["chd_indicators"]["total_alerts_in_period"] == 50
    assert result["chd_indicators"]["distinct_source_ips"] == 10
    assert result["network_exposure"]["unique_device_ips"] == 6
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_detect_cde_components_no_data(collector, db):
    """CDE detection returns no_data status when nothing found."""
    db.execute.side_effect = [
        _result(scalar=0), _result(scalar=0), _result(scalar=0),
        _result(scalar=0), _result(scalar=0),
        _result(scalar=0), _result(scalar=0),
        _result(scalar=0), _result(scalar=0),
        _result(scalar=0), _result(scalar=0), _result(scalar=0),
        _result(scalar=0),
    ]

    result = await collector.detect_cde_components(TENANT, db)

    assert result["total_cde_components"] == 0
    assert result["status"] == "no_data"


@pytest.mark.asyncio
async def test_detect_cde_components_error(collector, db):
    """CDE detection returns error on exception."""
    db.execute.side_effect = Exception("db timeout")

    result = await collector.detect_cde_components(TENANT, db)

    assert result["status"] == "error"
    assert "db timeout" in result["error"]


# ── CDE Access Logs ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_cde_access_logs_returns_breakdown(collector, db):
    """CDE access logs return action/resource breakdown and top users."""
    db.execute.side_effect = [
        _result(scalar=200),  # total
        _result(rows=[
            ("login", 80), ("user_created", 20), ("settings_updated", 50),
            ("api_key_created", 10), ("tenant_updated", 5), ("pipeline_started", 35),
        ]),
        _result(rows=[
            ("user", 100), ("settings", 50), ("api_key", 10),
            ("tenant", 5), ("pipeline", 35),
        ]),
        _result(scalar=15),  # active users
        _result(rows=[
            ("user-1", 60), ("user-2", 40), ("user-3", 30),
        ]),
    ]

    result = await collector.collect_cde_access_logs(TENANT, db, period_days=90)

    assert result["total_cde_access_events"] == 200
    assert result["actions_breakdown"]["login"] == 80
    assert result["resources_accessed"]["user"] == 100
    assert result["active_cde_users"] == 15
    assert len(result["top_cde_users"]) == 3
    assert result["top_cde_users"][0]["user_id"] == "user-1"
    assert result["top_cde_users"][0]["access_count"] == 60
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_collect_cde_access_logs_no_data(collector, db):
    """CDE access logs returns no_data when no entries."""
    db.execute.side_effect = [
        _result(scalar=0), _result(rows=[]), _result(rows=[]),
        _result(scalar=0), _result(rows=[]),
    ]

    result = await collector.collect_cde_access_logs(TENANT, db)

    assert result["total_cde_access_events"] == 0
    assert result["status"] == "no_data"


# ── Scan Evidence ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_scan_evidence_no_scans(collector, db):
    """Scan evidence returns no_data when no scans recorded."""
    result = await collector.collect_scan_evidence(TENANT, db)

    assert result["scan_count"] == 0
    assert result["asv_scans_current"] is False
    assert result["vulnerability_scans_current"] is False
    assert result["status"] == "no_data"


@pytest.mark.asyncio
async def test_collect_scan_evidence_with_scans(collector, db):
    """Scan evidence returns scan records and quarterly status when scans exist."""
    scan_registry.record_scan(
        scan_type="asv", scanner_name="Trustwave",
        status="passed", findings_count=0,
    )
    scan_registry.record_scan(
        scan_type="internal_vulnerability", scanner_name="Nessus",
        status="passed", findings_count=3, critical_findings=0, high_findings=1,
    )

    result = await collector.collect_scan_evidence(TENANT, db)

    assert result["scan_count"] == 2
    assert result["quarterly_scan_status"]["asv"]["status"] == "passed"
    assert result["quarterly_scan_status"]["internal_vulnerability"]["is_current"] is True
    assert result["asv_scans_current"] is True
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_scan_registry_record_and_latest():
    """ScanRegistry records scans and retrieves the latest."""
    registry = ScanRegistry()

    registry.record_scan("asv", "Rapid7", "failed", findings_count=12)
    registry.record_scan("asv", "Qualys", "passed", findings_count=0)

    all_asv = registry.get_scans("asv")
    assert len(all_asv) == 2
    scanners = {s.scanner_name for s in all_asv}
    assert "Rapid7" in scanners
    assert "Qualys" in scanners

    latest = registry.latest_scan("asv")
    assert latest is not None
    assert latest.scan_type == "asv"

    all_asv = registry.get_scans("asv")
    assert len(all_asv) == 2


@pytest.mark.asyncio
async def test_scan_registry_is_current_expired():
    """ScanRegistry correctly reports expired scans."""
    registry = ScanRegistry()

    registry.record_scan("asv", "Qualys", "passed")

    assert registry.is_current("asv") is True
    assert registry.is_current("internal_vulnerability") is False


@pytest.mark.asyncio
async def test_scan_registry_quarterly_status():
    """ScanRegistry quarterly_status returns structured data."""
    registry = ScanRegistry()

    registry.record_scan("asv", "Trustwave", "passed")
    registry.record_scan("network", "Nessus", "passed", findings_count=2)

    status = registry.quarterly_status()
    assert status["asv"]["is_current"] is True
    assert status["asv"]["days_since_last_scan"] == 0
    assert status["internal_vulnerability"]["is_current"] is False
    assert status["internal_vulnerability"]["last_scan"] is None
    assert status["network"]["is_current"] is True
    assert status["application"]["is_current"] is False


# ── Collect All ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_all_aggregates_all_categories(collector, db):
    """collect_all returns CDE components, CDE access logs, and scan evidence."""
    db.execute.side_effect = [
        # detect_cde_components (13 calls)
        _result(scalar=1), _result(scalar=1), _result(scalar=1),
        _result(scalar=1), _result(scalar=1),
        _result(scalar=1), _result(scalar=1),
        _result(scalar=1), _result(scalar=1),
        _result(scalar=1), _result(scalar=1), _result(scalar=1),
        _result(scalar=1),
        # collect_cde_access_logs (5 calls)
        _result(scalar=1), _result(rows=[("login", 1)]),
        _result(rows=[("user", 1)]), _result(scalar=1), _result(rows=[("user-1", 1)]),
    ]

    result = await collector.collect_all(TENANT, db, period_days=90)

    assert "collected_at" in result
    assert result["tenant_id"] == TENANT
    assert result["period_days"] == 90
    assert "cde_components" in result
    assert "cde_access_logs" in result
    assert "scan_evidence" in result


# ── Singleton ──────────────────────────────────────────────────────

def test_singleton_instance_exists():
    """Module-level singleton pci_collector is available."""
    assert pci_collector is not None
    assert isinstance(pci_collector, PCIComplianceCollector)


def test_scan_registry_singleton_exists():
    """Module-level scan_registry singleton is available."""
    assert scan_registry is not None
    assert isinstance(scan_registry, ScanRegistry)
