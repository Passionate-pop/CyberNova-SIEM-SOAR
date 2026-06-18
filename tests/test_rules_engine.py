"""Tests for the detection rules engine — verifies rule evaluation logic."""
from __future__ import annotations
import pytest
from cybernova.detection.rules_engine.rules import rule_engine, DetectionRule, BruteForceRule, PortScanRule


@pytest.mark.asyncio
async def test_rule_engine_evaluate_match():
    event = {"event_type": "malware_detected", "severity": "critical"}
    triggered = rule_engine.evaluate(event)
    rule_names = [r.name for r in triggered]
    assert "malware_detected" in rule_names


@pytest.mark.asyncio
async def test_rule_engine_evaluate_no_match():
    event = {"event_type": "innocuous_event", "severity": "info"}
    triggered = rule_engine.evaluate(event)
    assert len(triggered) == 0


@pytest.mark.asyncio
async def test_custom_rule_registration():
    rule = DetectionRule("custom_test", "medium", {"event_type": "custom_event"}, 50.0, "Custom test rule")
    rule_engine.register_rule(rule)
    event = {"event_type": "custom_event"}
    triggered = rule_engine.evaluate(event)
    assert any(r.name == "custom_test" for r in triggered)


@pytest.mark.asyncio
async def test_regex_rule_matching():
    event = {"event_type": "ransomware_encryption_detected", "severity": "critical"}
    triggered = rule_engine.evaluate(event)
    assert any("ransomware" in r.name for r in triggered)


@pytest.mark.asyncio
async def test_stateful_brute_force():
    rule = BruteForceRule()
    # Use a public IP - rate limiter skips private IPs
    source_ip = "203.0.113.50"
    result = None
    for _ in range(10):
        result = rule.evaluate({
            "event_type": "authentication_failure",
            "source_ip": source_ip,
            "user": "testuser",
            "success": False,
        })
    assert result is not None
    assert result.get("detected") is True


@pytest.mark.asyncio
async def test_stateful_port_scan():
    rule = PortScanRule()
    source_ip = "10.0.0.100"
    results = []
    for port in range(1, 15):
        r = rule.evaluate({
            "event_type": "port_scan",
            "source_ip": source_ip,
            "dest_port": port,
        })
        if r:
            results.append(r)
    assert len(results) >= 1
    assert results[0]["threat_type"] == "port_scan"
