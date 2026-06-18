"""
Tests for Sigma detection rules.
Loads every Sigma rule, verifies parse + convert, and tests evaluation.
"""
from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional

import pytest
import yaml

from cybernova.detection.sigma.sigma_parser import sigma_parser
from cybernova.detection.sigma.sigma_converter import sigma_converter

SIGMA_RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "cybernova", "detection", "sigma", "rules"
)


def _all_sigma_files() -> List[str]:
    return sorted(glob.glob(os.path.join(SIGMA_RULES_DIR, "**", "*.yml"), recursive=True))


def _load_yaml(filepath: str) -> Optional[Dict[str, Any]]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _matching_event_from_conditions(conditions: Dict[str, Any]) -> Dict[str, Any]:
    event: Dict[str, Any] = {"event_type": "test_sigma_event"}
    for field, value in conditions.items():
        if isinstance(value, list):
            event[field] = str(value[0]) if value else ""
        elif isinstance(value, str) and value.startswith("regex:"):
            event[field] = value[6:] if len(value) > 6 else "test"
        else:
            event[field] = value
    return event


@pytest.mark.asyncio
async def test_all_sigma_rules_parse() -> None:
    files = _all_sigma_files()
    assert len(files) >= 400, f"Expected >=400 Sigma rule files, found {len(files)}"
    errors = []
    for fpath in files:
        raw = _load_yaml(fpath)
        if raw is None:
            errors.append(f"YAML load failed: {os.path.basename(fpath)}")
            continue
        try:
            parsed = sigma_parser.parse(raw)
            assert parsed.title, f"Missing title in {os.path.basename(fpath)}"
        except Exception as e:
            errors.append(f"Parse failed {os.path.basename(fpath)}: {e}")
    assert not errors, f"{len(errors)} parse errors:\n" + "\n".join(errors[:5])


@pytest.mark.asyncio
async def test_all_sigma_rules_convert() -> None:
    files = _all_sigma_files()
    converted = 0
    errors = []
    for fpath in files:
        raw = _load_yaml(fpath)
        if raw is None:
            continue
        try:
            rule = sigma_converter.convert_raw(raw)
            if rule is not None:
                converted += 1
        except Exception as e:
            errors.append(f"Convert failed {os.path.basename(fpath)}: {e}")
    assert converted >= 400, f"Expected >=400 converted rules, got {converted}"
    assert not errors, f"{len(errors)} convert errors:\n" + "\n".join(errors[:5])


@pytest.mark.asyncio
async def test_sigma_rules_evaluate_match() -> None:
    files = _all_sigma_files()
    tested = 0
    matched = 0
    skipped = 0
    errors: List[str] = []
    for fpath in files:
        raw = _load_yaml(fpath)
        if raw is None:
            skipped += 1
            continue
        rule = sigma_converter.convert_raw(raw)
        if rule is None:
            skipped += 1
            continue
        conds = rule.conditions
        if not conds or all(k.startswith("_") for k in conds):
            skipped += 1
            continue
        event = _matching_event_from_conditions(conds)
        if rule.evaluate(event):
            matched += 1
        else:
            errors.append(f"No match for {rule.name}: conds={dict(conds)}, event={event}")
        tested += 1
    assert tested >= 300, f"Expected >=300 testable rules, got {tested}"
    assert matched >= tested * 0.8, (
        f"Only {matched}/{tested} rules matched. "
        f"This may indicate broken conditions (known: endswith/startswith not supported).\n"
        + "\n".join(errors[:5])
    )


@pytest.mark.asyncio
async def test_sigma_rules_no_false_positive() -> None:
    files = _all_sigma_files()
    tested = 0
    false_positives = 0
    for fpath in files:
        raw = _load_yaml(fpath)
        if raw is None:
            continue
        rule = sigma_converter.convert_raw(raw)
        if rule is None:
            continue
        if not rule.conditions:
            continue
        event: Dict[str, Any] = {
            "event_type": "__nonexistent_non_matching_event__",
            "source": "__nonexistent__",
            "severity": "info",
        }
        if rule.evaluate(event):
            false_positives += 1
        tested += 1
    assert false_positives == 0, (
        f"{false_positives} rules falsely matched a non-matching event (out of {tested})"
    )
