"""
Tests for K8s detection rules.
Cloud provider (AWS/Azure/GCP) rules removed for $0 local deployment.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from cybernova.detection.kubernetes.k8s_detections import K8S_RULES


def _all_cloud_rules() -> list:
    return K8S_RULES


def _matching_event(rule) -> Dict[str, Any]:
    event: Dict[str, Any] = {"event_type": "__test__"}
    for field, value in rule.conditions.items():
        if isinstance(value, list):
            event[field] = str(value[0]) if value else ""
        elif isinstance(value, str) and value.startswith("regex:"):
            event[field] = value[6:] if len(value) > 6 else "test"
        else:
            event[field] = value
    return event


def _rule_breakdown() -> str:
    return f"K8s={len(K8S_RULES)}"


@pytest.mark.asyncio
async def test_k8s_rule_count() -> None:
    assert len(K8S_RULES) == 30, f"K8s rules: expected 30, got {len(K8S_RULES)}"


@pytest.mark.asyncio
async def test_all_k8s_rules_have_conditions() -> None:
    empty = [r.name for r in K8S_RULES if not r.conditions]
    assert not empty, f"{len(empty)} K8s rules with empty conditions: {empty[:5]}"


@pytest.mark.asyncio
async def test_all_k8s_rules_evaluate_match() -> None:
    rules = _all_cloud_rules()
    failures: List[str] = []
    for rule in rules:
        event = _matching_event(rule)
        if not rule.evaluate(event):
            failures.append(f"{rule.name}: conds={dict(rule.conditions)}, event={event}")
    assert not failures, (
        f"{len(failures)}/{len(rules)} rules failed match:\n" + "\n".join(failures[:10])
    )


@pytest.mark.asyncio
async def test_all_k8s_rules_no_false_positive() -> None:
    rules = _all_cloud_rules()
    false_positives: List[str] = []
    non_matching_event: Dict[str, Any] = {
        "event_type": "__nonexistent_non_matching_event__",
        "source": "__nonexistent__",
    }
    for rule in rules:
        if rule.evaluate(non_matching_event):
            false_positives.append(rule.name)
    assert not false_positives, (
        f"{len(false_positives)}/{len(rules)} rules falsely matched non-matching event: {false_positives[:10]}"
    )


@pytest.mark.asyncio
async def test_all_k8s_rules_unique_names() -> None:
    rules = _all_cloud_rules()
    names = [r.name for r in rules]
    duplicates = [n for n in names if names.count(n) > 1]
    assert not duplicates, f"Duplicate rule names: {set(duplicates)}"


@pytest.mark.asyncio
async def test_k8s_rules_severity_levels() -> None:
    rules = _all_cloud_rules()
    valid = {"info", "low", "medium", "high", "critical"}
    invalid = [r.name for r in rules if r.severity not in valid]
    assert not invalid, f"Invalid severity in: {invalid[:10]}"


@pytest.mark.asyncio
async def test_k8s_rules_risk_scores() -> None:
    rules = _all_cloud_rules()
    invalid = [r.name for r in rules if not (0 <= r.risk_score <= 100)]
    assert not invalid, f"Invalid risk_score in: {invalid[:10]}"


@pytest.mark.asyncio
async def test_k8s_rules_minimum_coverage() -> None:
    total = len(_all_cloud_rules())
    assert total >= 30, f"K8s coverage dropped: {total} < 30"
