from __future__ import annotations

from typing import Any, Dict

import pytest

from cybernova.cspm.scanner import CSPMScanner, CSPM_RULES, FindingSeverity, CloudProvider


def test_cspm_rule_count() -> None:
    assert len(CSPM_RULES) >= 7
    k8s = [r for r in CSPM_RULES if r["provider"] == "kubernetes"]
    assert len(k8s) >= 7


def test_cspm_rules_have_required_fields() -> None:
    required = {"id", "provider", "service", "name", "description", "severity", "remediation"}
    for rule in CSPM_RULES:
        assert required.issubset(rule.keys()), f"Rule {rule.get('id')} missing fields"
        assert rule["severity"] in {"critical", "high", "medium", "low", "info"}
        assert rule["provider"] in {"kubernetes"}


def test_cspm_dispatch_covers_all_rules() -> None:
    scanner = CSPMScanner()
    uncovered = [r["id"] for r in CSPM_RULES if r["id"] not in scanner._SCANNER_DISPATCH]
    assert not uncovered, f"Rules without scanner dispatch: {uncovered}"


def test_evaluate_rule_returns_finding() -> None:
    scanner = CSPMScanner()
    rule = {
        "id": "k8s-pod-security",
        "provider": "kubernetes",
        "service": "pod",
        "name": "Test",
        "description": "Test description",
        "severity": "critical",
        "remediation": "Fix it",
        "frameworks": ["pci_dss"],
    }
    finding = scanner._evaluate_rule(rule, "local")
    assert finding is not None
    assert finding.check_id == "k8s-pod-security"
    assert finding.status in ("passed", "failed", "error")
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.provider == CloudProvider.KUBERNETES


@pytest.mark.parametrize("rule", CSPM_RULES)
def test_evaluate_every_rule(rule: Dict[str, Any]) -> None:
    scanner = CSPMScanner()
    finding = scanner._evaluate_rule(rule, "local")
    assert finding is not None
    assert finding.check_id == rule["id"]
    assert finding.status in ("passed", "failed", "error", "info")
    assert finding.severity.value == rule["severity"]


@pytest.mark.asyncio
async def test_run_scan_returns_proper_structure() -> None:
    scanner = CSPMScanner()
    result = await scanner.run_scan("kubernetes", "local")
    assert "scan_id" in result
    assert result["provider"] == "kubernetes"
    assert result["region"] == "local"
    assert result["total_rules"] > 0
    assert result["passed"] + result["failed"] <= result["total_rules"]
    assert isinstance(result["findings"], list)
    if result["findings"]:
        f = result["findings"][0]
        assert "check_id" in f
        assert "check_name" in f
        assert "status" in f


def test_scanner_get_rules() -> None:
    scanner = CSPMScanner()
    all_rules = scanner.get_rules()
    assert len(all_rules) == len(CSPM_RULES)
    k8s_rules = scanner.get_rules("kubernetes")
    assert all(r["provider"] == "kubernetes" for r in k8s_rules)


def test_scanner_get_providers() -> None:
    scanner = CSPMScanner()
    providers = scanner.get_providers()
    provider_names = {p["provider"] for p in providers}
    assert "kubernetes" in provider_names
    assert "aws" not in provider_names
    assert "azure" not in provider_names
    assert "gcp" not in provider_names


def test_scanner_get_stats() -> None:
    scanner = CSPMScanner()
    stats = scanner.get_stats()
    assert stats["total_scans"] == 0
    assert stats["total_findings"] == 0
    assert stats["available_rules"] == len(CSPM_RULES)


@pytest.mark.asyncio
async def test_scan_history_tracking() -> None:
    scanner = CSPMScanner()
    assert len(scanner.get_scan_history()) == 0
    await scanner.run_scan("kubernetes", "local")
    assert len(scanner.get_scan_history()) == 1
    history = scanner.get_scan_history()[0]
    assert history["provider"] == "kubernetes"
