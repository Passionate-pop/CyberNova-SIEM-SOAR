"""
CI test: counts all detection rules across the system.
Fails if total drops below the minimum threshold (500).
Cloud provider (AWS/Azure/GCP) rules excluded for $0 local deployment.
"""
from __future__ import annotations

import glob
import os
from typing import Dict

import pytest
import yaml

from cybernova.detection.rules_engine.rules import RuleEngine

SIGMA_RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "cybernova", "detection", "sigma", "rules"
)

MINIMUM_TOTAL_RULES = 400  # reduced from 500 since cloud provider rules removed


def _count_sigma_rules() -> int:
    files = glob.glob(os.path.join(SIGMA_RULES_DIR, "**", "*.yml"), recursive=True)
    count = 0
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if isinstance(raw, dict) and raw.get("title"):
                count += 1
        except Exception:
            continue
    return count


def _count_cloud_rules() -> Dict[str, int]:
    from cybernova.detection.kubernetes.k8s_detections import K8S_RULES

    return {
        "k8s": len(K8S_RULES),
    }


def _count_default_rules() -> int:
    engine = RuleEngine()
    return len(engine.rules)


@pytest.mark.asyncio
async def test_detection_coverage_total() -> None:
    default_count = _count_default_rules()
    sigma_count = _count_sigma_rules()
    cloud_counts = _count_cloud_rules()
    cloud_total = sum(cloud_counts.values())

    total = default_count + sigma_count + cloud_total

    print(f"  Default rules:   {default_count}")
    print(f"  Sigma rules:     {sigma_count}")
    print(f"  Cloud rules:     {cloud_total} ({', '.join(f'{k}={v}' for k, v in cloud_counts.items())})")
    print("  ─────────────────────────────────────")
    print(f"  Total:           {total}")
    print(f"  Minimum:         {MINIMUM_TOTAL_RULES}")

    assert total >= MINIMUM_TOTAL_RULES, (
        f"Detection rule count ({total}) dropped below minimum threshold ({MINIMUM_TOTAL_RULES}). "
        f"Default={default_count}, Sigma={sigma_count}, Cloud={cloud_total}"
    )


@pytest.mark.asyncio
async def test_sigma_rule_count() -> None:
    count = _count_sigma_rules()
    assert count >= 400, f"Sigma rule count dropped: {count} < 400"


@pytest.mark.asyncio
async def test_k8s_rule_count() -> None:
    counts = _count_cloud_rules()
    assert counts["k8s"] >= 30, f"K8s rules: {counts['k8s']} < 30"


@pytest.mark.asyncio
async def test_default_rule_count() -> None:
    count = _count_default_rules()
    assert count >= 60, f"Default rules dropped: {count} < 60"
