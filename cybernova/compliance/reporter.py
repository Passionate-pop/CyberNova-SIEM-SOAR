from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.compliance.collector import EvidenceCollector
from cybernova.compliance.framework import (
    ComplianceControl, ComplianceReport, ComplianceStandard,
    ControlFramework, ControlResult, ControlStatus,
)

log = logging.getLogger("cybernova.compliance.reporter")

REPORTS_DIR = Path("data/compliance")


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).isoformat()


class ComplianceReporter:
    def __init__(self):
        self.framework = ControlFramework()
        self.collector = EvidenceCollector()

    async def generate_report(
        self,
        standard: ComplianceStandard,
        tenant_id: str,
        db: AsyncSession,
        period_days: int = 90,
        include_evidence: bool = True,
    ) -> ComplianceReport:
        controls = self.framework.get_controls(standard)
        if not controls:
            return ComplianceReport(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                standard=standard,
                generated_at=_utcnow_str(),
                period_start=(datetime.now(timezone.utc) - timedelta(days=period_days)).isoformat(),
                period_end=_utcnow_str(),
                overall_score=0.0,
                control_results=[],
                summary={"error": f"No controls defined for {standard.value}"},
            )

        control_results: List[ControlResult] = []
        for control in controls:
            evidence = {}
            if include_evidence:
                evidence = await self.collector.collect(control, tenant_id, db)

            result = self._evaluate_control(control, evidence)
            control_results.append(result)

        passed = sum(1 for r in control_results if r.status == ControlStatus.PASSED)
        applicable = sum(
            1 for r in control_results
            if r.status not in (ControlStatus.NOT_APPLICABLE, ControlStatus.NOT_CHECKED)
        )
        overall_score = (passed / applicable * 100) if applicable > 0 else 0.0

        severity_counts: Dict[str, int] = {}
        category_counts: Dict[str, Dict[str, int]] = {}
        for ctrl in controls:
            severity_counts.setdefault(ctrl.severity, 0)
            severity_counts[ctrl.severity] += 1
            category_counts.setdefault(ctrl.category, {"total": 0, "passed": 0})
            category_counts[ctrl.category]["total"] += 1

        for result in control_results:
            ctrl = next((c for c in controls if c.id == result.control_id), None)
            if ctrl and ctrl.category in category_counts:
                if result.status == ControlStatus.PASSED:
                    category_counts[ctrl.category]["passed"] += 1

        report = ComplianceReport(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            standard=standard,
            generated_at=_utcnow_str(),
            period_start=(datetime.now(timezone.utc) - timedelta(days=period_days)).isoformat(),
            period_end=_utcnow_str(),
            overall_score=round(overall_score, 1),
            control_results=control_results,
            summary={
                "total_controls": len(controls),
                "passed": passed,
                "failed": sum(1 for r in control_results if r.status == ControlStatus.FAILED),
                "warning": sum(1 for r in control_results if r.status == ControlStatus.WARNING),
                "not_applicable": sum(1 for r in control_results if r.status == ControlStatus.NOT_APPLICABLE),
                "not_checked": sum(1 for r in control_results if r.status == ControlStatus.NOT_CHECKED),
                "applicable_controls": applicable,
                "overall_score": round(overall_score, 1),
                "severity_breakdown": severity_counts,
                "category_breakdown": category_counts,
            },
        )

        await self._save_report(report)
        return report

    def _evaluate_control(self, control: ComplianceControl, evidence: Dict[str, Any]) -> ControlResult:
        if control.id == "pci_9_1":
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.NOT_APPLICABLE,
                evidence=evidence,
                details="Physical access control is managed by cloud provider — not applicable for SaaS.",
                checked_at=_utcnow_str(),
            )

        if not control.evidence_required:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.NOT_CHECKED,
                evidence=evidence,
                details="No evidence requirements defined for this control.",
                checked_at=_utcnow_str(),
            )

        issues: List[str] = []
        warnings: List[str] = []

        for ev_type in control.evidence_required:
            ev_data = evidence.get(ev_type, {})
            status = ev_data.get("status", "error")

            if status == "error":
                issues.append(f"{ev_type}: evidence collection failed")
            elif status == "no_data":
                warnings.append(f"{ev_type}: no data found — may need configuration")
            elif status == "warning":
                warnings.append(f"{ev_type}: configuration needs attention")

            if ev_type == "blocked_ips" and ev_data.get("total_blocked_ips", 0) == 0:
                warnings.append("No blocked IPs configured — firewall rules may be incomplete")
            if ev_type == "retention_policies" and ev_data.get("policy_count", 0) == 0:
                issues.append("No retention policies configured")
            if ev_type == "detection_rules" and ev_data.get("enabled_rules", 0) == 0:
                warnings.append("No active detection rules")
            if ev_type == "rbac" and ev_data.get("role_count", 0) < 2:
                warnings.append("Fewer than 2 distinct roles — RBAC may be insufficient")
            if ev_type == "audit_logs" and ev_data.get("total_logs", 0) == 0:
                warnings.append("No audit logs found")
            if ev_type == "audit_log_retention" and not ev_data.get("meets_requirement", False) and "oldest" in ev_data.get("oldest_log", "") or ev_data.get("oldest_log") is not None:
                if ev_data.get("status") == "warning":
                    warnings.append("Audit log retention may not meet requirements")
            if ev_type == "encryption_settings" and ev_data.get("status") != "active":
                issues.append("Encryption not properly configured")
            if ev_type == "incidents" and ev_data.get("total_incidents", 0) == 0:
                warnings.append("No incidents recorded — incident response readiness unknown")
            if ev_type == "playbooks" and ev_data.get("total_playbooks", 0) == 0:
                warnings.append("No playbooks configured")

        if len(issues) > 0:
            status = ControlStatus.FAILED
        elif len(warnings) > 0:
            status = ControlStatus.WARNING
        else:
            status = ControlStatus.PASSED

        details_parts: List[str] = []
        if issues:
            details_parts.append("Issues: " + "; ".join(issues))
        if warnings:
            details_parts.append("Warnings: " + "; ".join(warnings))
        if not issues and not warnings:
            details_parts.append("All evidence checks passed")

        return ControlResult(
            control_id=control.id,
            status=status,
            evidence=evidence,
            details=" | ".join(details_parts),
            checked_at=_utcnow_str(),
        )

    async def _save_report(self, report: ComplianceReport) -> None:
        report_path = REPORTS_DIR / report.tenant_id
        report_path.mkdir(parents=True, exist_ok=True)
        filepath = report_path / f"{report.id}.json"
        try:
            with open(filepath, "w") as f:
                json.dump(self._report_to_dict(report), f, indent=2, default=str)
            log.info("Compliance report saved: %s", filepath)
        except Exception as e:
            log.warning("Failed to save compliance report: %s", e)

    def _report_to_dict(self, report: ComplianceReport) -> Dict[str, Any]:
        return {
            "id": report.id,
            "tenant_id": report.tenant_id,
            "standard": report.standard.value,
            "generated_at": report.generated_at,
            "period_start": report.period_start,
            "period_end": report.period_end,
            "overall_score": report.overall_score,
            "summary": report.summary,
            "control_results": [
                {
                    "control_id": r.control_id,
                    "status": r.status.value,
                    "evidence": r.evidence,
                    "details": r.details,
                    "checked_at": r.checked_at,
                }
                for r in report.control_results
            ],
        }

    def list_reports(self, tenant_id: str) -> List[Dict[str, Any]]:
        report_path = REPORTS_DIR / tenant_id
        if not report_path.exists():
            return []
        reports = []
        for f in sorted(report_path.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.suffix == ".json":
                try:
                    with open(f) as fh:
                        data = json.load(fh)
                        reports.append({
                            "id": data.get("id"),
                            "standard": data.get("standard"),
                            "overall_score": data.get("overall_score"),
                            "generated_at": data.get("generated_at"),
                            "period_start": data.get("period_start"),
                            "period_end": data.get("period_end"),
                        })
                except Exception as e:
                    log.warning("Failed to read report %s: %s", f.name, e)
        return reports

    def get_report(self, tenant_id: str, report_id: str) -> Dict[str, Any] | None:
        filepath = REPORTS_DIR / tenant_id / f"{report_id}.json"
        if not filepath.exists():
            return None
        try:
            with open(filepath) as f:
                return json.load(f)
        except Exception as e:
            log.warning("Failed to read report %s: %s", filepath, e)
            return None
