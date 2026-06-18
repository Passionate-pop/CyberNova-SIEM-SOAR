"""
Tests for DetectionService — verifies Alert creation populates all required fields.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from sqlalchemy import select

from cybernova.database.postgres.models import Alert, NormalizedEvent
from cybernova.detection.services.detection_service import detection_service, DetectionService


@pytest.mark.asyncio
async def test_alert_created_with_required_fields():
    """Verify Alert model has all fields needed by correlation_service._alert_to_dict()."""
    alert = Alert(
        id="test-id",
        tenant_id="default",
        event_id="evt-1",
        device_id="dev-1",
        rule_name="test_rule",
        severity="high",
        risk_score=75.0,
        description="Test alert",
        status="new",
        created_at=datetime.now(timezone.utc),
        source_ip="192.168.1.1",
        dest_ip="10.0.0.1",
        user="testuser",
        event_type="failed_login",
        raw_event={"message": "test", "source": "test"},
    )
    assert alert.source_ip == "192.168.1.1"
    assert alert.dest_ip == "10.0.0.1"
    assert alert.user == "testuser"
    assert alert.event_type == "failed_login"
    assert alert.raw_event == {"message": "test", "source": "test"}


@pytest.mark.asyncio
async def test_alert_to_dict_fields():
    """Verify _alert_to_dict accesses work without AttributeError."""
    from cybernova.detection.correlation_engine.correlation_service import correlation_service
    alert = Alert(
        id="test-id",
        tenant_id="default",
        event_id="evt-1",
        device_id="dev-1",
        rule_name="brute_force",
        severity="critical",
        risk_score=90.0,
        description="Brute force detected",
        status="new",
        created_at=datetime.now(timezone.utc),
        source_ip="10.0.0.1",
        dest_ip="192.168.1.1",
        user="attacker",
        event_type="failed_login",
        raw_event={"source_ip": "10.0.0.1"},
    )
    result = correlation_service._alert_to_dict(alert)
    assert result["source_ip"] == "10.0.0.1"
    assert result["dest_ip"] == "192.168.1.1"
    assert result["user"] == "attacker"
    assert result["event_type"] == "failed_login"
    assert result["raw_event"] == {"source_ip": "10.0.0.1"}
    assert result["id"] == "test-id"
    assert result["rule_name"] == "brute_force"
    assert result["severity"] == "critical"
