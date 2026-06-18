"""Unit tests for detection/rules_engine/ — targeting 80%+ coverage."""

from unittest.mock import MagicMock, patch

import pytest

from cybernova.detection.rules_engine import DetectionRule, rule_engine


class TestDetectionRule:
    def test_rule_creation(self):
        rule = DetectionRule(
            name="test_rule",
            severity="high",
            conditions={"event_type": "test_event"},
            risk_score=75.0,
            description="A test rule",
        )
        assert rule.name == "test_rule"
        assert rule.risk_score == 75.0

    def test_evaluate_match(self):
        rule = DetectionRule(
            name="match_test",
            severity="high",
            conditions={"event_type": "login_failure"},
            risk_score=50, description="",
        )
        assert rule.evaluate({"event_type": "login_failure"}) is True
        assert rule.evaluate({"event_type": "success"}) is False

    def test_evaluate_in_list(self):
        rule = DetectionRule(
            name="in_test",
            severity="medium",
            conditions={"source_ip": ["1.2.3.4", "5.6.7.8"]},
            risk_score=30, description="",
        )
        assert rule.evaluate({"source_ip": "1.2.3.4"}) is True
        assert rule.evaluate({"source_ip": "9.9.9.9"}) is False

    def test_evaluate_multiple_conditions(self):
        rule = DetectionRule(
            name="multi",
            severity="critical",
            conditions={"event_type": "brute_force", "severity": "high"},
            risk_score=90, description="",
        )
        assert rule.evaluate({"event_type": "brute_force", "severity": "high"}) is True
        assert rule.evaluate({"event_type": "brute_force", "severity": "low"}) is False

    def test_evaluate_regex_condition(self):
        rule = DetectionRule(
            name="regex_test",
            severity="high",
            conditions={"event_type": "regex:ransomware|ransom"},
            risk_score=80, description="",
        )
        assert rule.evaluate({"event_type": "ransomware_attack"}) is True
        assert rule.evaluate({"event_type": "ransom_note"}) is True
        assert rule.evaluate({"event_type": "normal_event"}) is False

    def test_evaluate_severity_list(self):
        rule = DetectionRule(
            name="sev_list",
            severity="high",
            conditions={"severity": ["critical", "high"]},
            risk_score=70, description="",
        )
        assert rule.evaluate({"severity": "critical"}) is True
        assert rule.evaluate({"severity": "high"}) is True
        assert rule.evaluate({"severity": "low"}) is False


class TestRuleEngine:
    def test_evaluate_match(self):
        event = {"event_type": "malware_detected", "severity": "high"}
        results = rule_engine.evaluate(event)
        assert len(results) >= 1
        names = [r.name for r in results]
        assert "malware_detected" in names

    def test_evaluate_no_match(self):
        event = {"event_type": "unknown_type", "severity": "info"}
        results = rule_engine.evaluate(event)
        assert len(results) == 0

    def test_evaluate_stateful_returns_list(self):
        event = {"event_type": "authentication_failure", "source_ip": "10.0.0.99",
                 "user": "admin", "severity": "medium"}
        results = rule_engine.evaluate_stateful(event)
        assert isinstance(results, list)

    def test_register_rule(self):
        rule = DetectionRule(
            name="custom_test", severity="high",
            conditions={"event_type": "custom_event"},
            risk_score=60, description="custom",
        )
        rule_engine.register_rule(rule)
        assert any(r.name == "custom_test" for r in rule_engine.rules)

    def test_list_rules(self):
        rules = rule_engine.list_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0
        assert "name" in rules[0]
        assert "severity" in rules[0]


class TestDefaultRules:
    def test_all_rules_have_required_fields(self):
        for rule in rule_engine.rules:
            assert rule.name
            assert rule.description is not None
            assert rule.severity in ("critical", "high", "medium", "low", "info")
            assert 0 <= rule.risk_score <= 100

    def test_no_duplicate_names(self):
        names = [r.name for r in rule_engine._default_rules()]
        assert len(names) == len(set(names))

    def test_key_detection_rules_exist(self):
        names = {r.name for r in rule_engine.rules}
        for key in ("malware_detected", "brute_force_detected", "waf_block",
                     "sqli_detected", "webshell_detected", "rootkit_detected"):
            assert key in names, f"Missing rule: {key}"


class TestStatefulRules:
    def test_default_stateful_rules_exist(self):
        assert len(rule_engine.stateful_rules) >= 6

    def test_brute_force_detection(self):
        event = {"event_type": "authentication_failure", "source_ip": "10.0.0.1",
                 "user": "admin", "severity": "medium"}
        from cybernova.detection.rules_engine.rules import BruteForceRule
        rule = BruteForceRule()
        result = rule.evaluate(event)
        assert result is None or isinstance(result, dict)


class TestRegexRuleMatching:
    def test_ransomware_regex(self):
        rule = DetectionRule(
            name="test_ransom", severity="critical",
            conditions={"event_type": "regex:ransom"},
            risk_score=90, description="",
        )
        assert rule.evaluate({"event_type": "ransomware"}) is True
        assert rule.evaluate({"event_type": "ransom_note_created"}) is True
        assert rule.evaluate({"event_type": "normal"}) is False
