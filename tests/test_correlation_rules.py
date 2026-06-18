"""
Tests for correlation rules engine — verifies sequence matching and alert grouping.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone

from cybernova.correlation.rules_engine import CorrelationRule, CorrelationRulesEngine


@pytest.fixture
def sample_alerts():
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "a1",
            "rule_name": "failed_login",
            "event_type": "failed_login",
            "source_ip": "10.0.0.1",
            "user": "bob",
            "severity": "medium",
            "risk_score": 30.0,
            "created_at": now.isoformat(),
            "description": "Failed login attempt",
        },
        {
            "id": "a2",
            "rule_name": "failed_login",
            "event_type": "failed_login",
            "source_ip": "10.0.0.1",
            "user": "bob",
            "severity": "medium",
            "risk_score": 30.0,
            "created_at": now.isoformat(),
            "description": "Failed login attempt",
        },
        {
            "id": "a3",
            "rule_name": "failed_login",
            "event_type": "failed_login",
            "source_ip": "10.0.0.1",
            "user": "bob",
            "severity": "medium",
            "risk_score": 30.0,
            "created_at": now.isoformat(),
            "description": "Failed login attempt",
        },
        {
            "id": "a4",
            "rule_name": "successful_login",
            "event_type": "successful_login",
            "source_ip": "10.0.0.1",
            "user": "bob",
            "severity": "low",
            "risk_score": 10.0,
            "created_at": now.isoformat(),
            "description": "Successful login after failures",
        },
    ]


@pytest.mark.asyncio
async def test_brute_force_sequence_match(sample_alerts):
    """3 failed logins + 1 successful login from same IP should match brute_force rule."""
    engine = CorrelationRulesEngine()
    rule = CorrelationRule(
        id="brute_force_success",
        name="Brute Force -> Successful Login",
        description="Brute force followed by success",
        sequence=["failed_login", "failed_login", "failed_login", "successful_login"],
        entity_field="source_ip",
        window_seconds=300,
        severity="critical",
        enabled=True,
        tenant_id="default",
    )
    matched, confidence = await engine.match_sequence(sample_alerts, rule)
    assert matched is True
    assert confidence > 0


@pytest.mark.asyncio
async def test_port_scan_sequence_match():
    """Port scan followed by exploit should match."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "s1",
            "rule_name": "port_scan",
            "event_type": "port_scan",
            "source_ip": "10.0.0.5",
            "severity": "medium",
            "risk_score": 40.0,
            "created_at": now.isoformat(),
            "description": "Port scan detected",
        },
        {
            "id": "s2",
            "rule_name": "exploitation_attempt",
            "event_type": "exploitation_attempt",
            "source_ip": "10.0.0.5",
            "severity": "high",
            "risk_score": 80.0,
            "created_at": now.isoformat(),
            "description": "Exploit attempt detected",
        },
    ]
    engine = CorrelationRulesEngine()
    rule = CorrelationRule(
        id="port_scan_then_exploit",
        name="Port Scan -> Exploitation Attempt",
        description="Port scan followed by exploitation",
        sequence=["port_scan", "exploitation_attempt"],
        entity_field="source_ip",
        window_seconds=120,
        severity="high",
        enabled=True,
        tenant_id="default",
    )
    matched, confidence = await engine.match_sequence(alerts, rule)
    assert matched is True


@pytest.mark.asyncio
async def test_no_match_wrong_sequence():
    """Same IP but wrong event order should not match."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "n1",
            "rule_name": "successful_login",
            "event_type": "successful_login",
            "source_ip": "10.0.0.9",
            "severity": "low",
            "risk_score": 10.0,
            "created_at": now.isoformat(),
            "description": "Login success",
        },
        {
            "id": "n2",
            "rule_name": "failed_login",
            "event_type": "failed_login",
            "source_ip": "10.0.0.9",
            "severity": "medium",
            "risk_score": 30.0,
            "created_at": now.isoformat(),
            "description": "Login failed",
        },
    ]
    engine = CorrelationRulesEngine()
    rule = CorrelationRule(
        id="brute_force_success",
        name="Brute Force -> Successful Login",
        description="Brute force followed by success",
        sequence=["failed_login", "successful_login"],
        entity_field="source_ip",
        window_seconds=300,
        severity="critical",
        enabled=True,
        tenant_id="default",
    )
    matched, confidence = await engine.match_sequence(alerts, rule)
    assert matched is False


@pytest.mark.asyncio
async def test_normalize_event_type():
    """Verify event type normalization covers all cases."""
    engine = CorrelationRulesEngine()

    assert engine._normalize_event_type({"rule_name": "failed_login_detected"}, "source_ip") == "failed_login"
    assert engine._normalize_event_type({"rule_name": "successful_login"}, "source_ip") == "successful_login"
    assert engine._normalize_event_type({"rule_name": "port_scan_detected"}, "source_ip") == "port_scan"
    assert engine._normalize_event_type({"rule_name": "malware_detected"}, "source_ip") == "malware_detected"
    assert engine._normalize_event_type({"rule_name": "exploit_attempt"}, "source_ip") == "exploitation_attempt"
    assert engine._normalize_event_type({"rule_name": "privilege_escalation"}, "source_ip") == "privilege_escalation"
    assert engine._normalize_event_type({"rule_name": "data_exfiltration"}, "source_ip") == "large_outbound_transfer"
    assert engine._normalize_event_type({"rule_name": "c2_beacon"}, "source_ip") == "suspicious_outbound"
    assert engine._normalize_event_type({"rule_name": "credential_access"}, "source_ip") == "credential_access"
    assert engine._normalize_event_type({"rule_name": "unknown_event"}, "source_ip") == "unknown_event"


@pytest.mark.asyncio
async def test_correlation_rule_from_dict():
    """Verify CorrelationRule.from_dict works with all fields."""
    rule = CorrelationRule.from_dict({
        "id": "test_rule",
        "name": "Test Rule",
        "description": "A test rule",
        "sequence": ["event_a", "event_b"],
        "entity_field": "source_ip",
        "window_seconds": 600,
        "severity": "high",
        "enabled": True,
        "created_at": datetime.now(timezone.utc),
    }, tenant_id="test-tenant")
    assert rule.id == "test_rule"
    assert rule.tenant_id == "test-tenant"
    assert rule.sequence == ["event_a", "event_b"]
    assert rule.window_seconds == 600


@pytest.mark.asyncio
async def test_correlation_rule_from_dict_defaults():
    """Verify defaults when minimal data is provided."""
    rule = CorrelationRule.from_dict({"name": "Minimal Rule"})
    assert rule.id is not None
    assert rule.sequence == []
    assert rule.entity_field == "source_ip"
    assert rule.window_seconds == 300
    assert rule.severity == "medium"
    assert rule.enabled is True
    assert rule.tenant_id == "default"


@pytest.mark.asyncio
async def test_incident_builds_attack_story():
    """Verify incident builder constructs readable attack story."""
    from cybernova.correlation.incident_builder import incident_builder
    now = datetime.now(timezone.utc)
    alerts = [
        {"id": "a1", "rule_name": "port_scan", "source_ip": "10.0.0.1",
         "severity": "medium", "created_at": now.isoformat()},
        {"id": "a2", "rule_name": "exploit", "source_ip": "10.0.0.1",
         "severity": "high", "created_at": now.isoformat()},
    ]
    incident = incident_builder.build_incident(
        "Port Scan -> Exploit", "Scan followed by exploit", alerts, "default"
    )
    assert "attack_story" in incident
    assert "1. [" in incident["attack_story"]
    assert "2. [" in incident["attack_story"]
    assert incident["severity"] == "high"


@pytest.mark.asyncio
async def test_incident_builder_extracts_entities():
    """Verify affected entities are extracted from alerts."""
    from cybernova.correlation.incident_builder import incident_builder
    now = datetime.now(timezone.utc)
    alerts = [
        {"id": "a1", "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
         "user": "bob", "raw_event": {}, "severity": "low",
         "risk_score": 10.0, "created_at": now.isoformat()},
    ]
    entities = incident_builder._extract_affected_entities(alerts)
    assert "10.0.0.1" in entities["source_ips"]
    assert "10.0.0.2" in entities["dest_ips"]
    assert "bob" in entities["users"]


@pytest.mark.asyncio
async def test_incident_recommendations_by_type():
    """Verify recommendations match rule type."""
    from cybernova.correlation.incident_builder import incident_builder
    recs = incident_builder._get_recommendations("brute_force_detected", [])
    texts = " ".join(recs).lower()
    assert "block" in texts
    assert "password" in texts
    assert "mfa" in texts

    recs_malware = incident_builder._get_recommendations("malware_detected", [])
    texts_m = " ".join(recs_malware).lower()
    assert "isolate" in texts_m
    assert "forensics" in texts_m
