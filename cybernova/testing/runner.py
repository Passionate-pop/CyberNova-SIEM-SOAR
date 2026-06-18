from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from cybernova.detection.rules_engine.rules import rule_engine
from cybernova.detection.rules_engine.rules_dsl import detection_rules_engine
from cybernova.testing.atomic_tests import ATOMIC_TESTS, get_atomic_test

log = logging.getLogger("cybernova.testing.runner")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class MatchedRuleInfo:
    def __init__(self, name: str, severity: str, risk_score: float, source: str):
        self.name = name
        self.severity = severity
        self.risk_score = risk_score
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "source": self.source,
        }


class TestResult:
    def __init__(
        self,
        test_id: str,
        test_name: str,
        passed: bool,
        matched_rules: List[MatchedRuleInfo],
        expected_match: bool,
        expected_severity: Optional[str],
        actual_severity: Optional[str],
        detection_time_ms: float,
        errors: List[str],
    ):
        self.test_id = test_id
        self.test_name = test_name
        self.passed = passed
        self.matched_rules = matched_rules
        self.expected_match = expected_match
        self.expected_severity = expected_severity
        self.actual_severity = actual_severity
        self.detection_time_ms = detection_time_ms
        self.errors = errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "passed": self.passed,
            "matched_rules": [r.to_dict() for r in self.matched_rules],
            "expected_match": self.expected_match,
            "expected_severity": self.expected_severity,
            "actual_severity": self.actual_severity,
            "detection_time_ms": round(self.detection_time_ms, 2),
            "errors": self.errors,
        }


def _highest_severity(severities: List[str]) -> str:
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, -1))


async def run_single_test(test_id: str, tenant_id: str = "default") -> TestResult:
    test = get_atomic_test(test_id)
    if test is None:
        return TestResult(
            test_id=test_id,
            test_name="unknown",
            passed=False,
            matched_rules=[],
            expected_match=False,
            expected_severity=None,
            actual_severity=None,
            detection_time_ms=0.0,
            errors=[f"Test {test_id} not found"],
        )

    event = test["event"]
    event_data = {
        "event_type": event.get("event_type", ""),
        "severity": event.get("severity", "info"),
        "source_ip": event.get("source_ip", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", 0),
        "protocol": event.get("protocol", ""),
        "user": event.get("user", ""),
        "message": event.get("message", ""),
        "process_name": event.get("process_name", ""),
        "command_line": event.get("command_line", ""),
        "bytes_sent": event.get("bytes_sent", 0),
    }

    start = time.perf_counter()
    matched_rules: List[MatchedRuleInfo] = []
    errors: List[str] = []

    try:
        static_matches = await asyncio.get_running_loop().run_in_executor(
            None, rule_engine.evaluate, event_data
        )
        for rule in static_matches:
            matched_rules.append(MatchedRuleInfo(
                name=rule.name,
                severity=rule.severity,
                risk_score=rule.risk_score,
                source="static",
            ))
    except Exception as e:
        errors.append(f"Static rule evaluation error: {e}")
        log.warning("Static rule eval error for %s: %s", test_id, e)

    try:
        stateful_results = await asyncio.get_running_loop().run_in_executor(
            None, rule_engine.evaluate_stateful, event_data
        )
        for result in stateful_results:
            if result.get("detected"):
                matched_rules.append(MatchedRuleInfo(
                    name=result.get("threat_type", "stateful_detection"),
                    severity=result.get("severity", "medium"),
                    risk_score=result.get("risk_score", 50.0),
                    source="stateful",
                ))
    except Exception as e:
        errors.append(f"Stateful rule evaluation error: {e}")
        log.warning("Stateful rule eval error for %s: %s", test_id, e)

    try:
        await detection_rules_engine.load_rules(tenant_id)
        dsl_matches = await detection_rules_engine.evaluate(event_data, tenant_id)
        for rule in dsl_matches:
            matched_rules.append(MatchedRuleInfo(
                name=rule.name,
                severity=rule.severity,
                risk_score=rule.risk_score,
                source="dsl",
            ))
    except Exception as e:
        errors.append(f"DSL rule evaluation error: {e}")
        log.warning("DSL rule eval error for %s: %s", test_id, e)

    elapsed = (time.perf_counter() - start) * 1000

    actual_match = len(matched_rules) > 0
    actual_severity = _highest_severity([r.severity for r in matched_rules]) if actual_match else None
    expected_match = test.get("expected_match", True)
    expected_severity = test.get("expected_severity")

    passed = True
    if actual_match != expected_match:
        passed = False
    if expected_match and expected_severity and actual_severity:
        if SEVERITY_ORDER.get(actual_severity, -1) < SEVERITY_ORDER.get(expected_severity, -1):
            passed = False

    return TestResult(
        test_id=test["id"],
        test_name=test["name"],
        passed=passed,
        matched_rules=matched_rules,
        expected_match=expected_match,
        expected_severity=expected_severity,
        actual_severity=actual_severity,
        detection_time_ms=elapsed,
        errors=errors,
    )


async def run_all_tests(tenant_id: str = "default") -> List[TestResult]:
    results: List[TestResult] = []
    for test in ATOMIC_TESTS:
        result = await run_single_test(test["id"], tenant_id)
        results.append(result)
    return results


class TestRunner:
    """Test runner singleton wrapping atomic test execution."""

    async def run(self, test_id: str, tenant_id: str = "default") -> TestResult:
        return await run_single_test(test_id, tenant_id)

    async def run_all(self, tenant_id: str = "default") -> List[TestResult]:
        return await run_all_tests(tenant_id)


# Module-level singleton for clean API access
test_runner = TestRunner()

