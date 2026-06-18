"""
CyberNova — Compliance Report Download Endpoints
Generates downloadable compliance reports per framework (JSON/CSV).
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.compliance.framework import ComplianceStandard
from cybernova.compliance.reporter import ComplianceReporter
from cybernova.compliance.evidence_collector import soc2_evidence_collector
from cybernova.compliance.pci_dss import pci_collector
from cybernova.compliance.hipaa import hipaa_collector
from cybernova.compliance.gdpr import gdpr_collector
from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser, get_current_user

log = logging.getLogger("cybernova.api.compliance_routes")
router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance Downloads"])

reporter = ComplianceReporter()

STANDARD_COLLECTOR_MAP = {
    ComplianceStandard.SOC2: soc2_evidence_collector.collect_all,
    ComplianceStandard.PCI_DSS: pci_collector.collect_all,
    ComplianceStandard.HIPAA: hipaa_collector.collect_all,
    ComplianceStandard.GDPR: gdpr_collector.collect_all,
}

STANDARD_DISPLAY_NAMES = {
    "soc2": "SOC 2",
    "pci_dss": "PCI DSS",
    "hipaa": "HIPAA",
    "gdpr": "GDPR",
}


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _collect_standard_evidence(
    standard: ComplianceStandard,
    tenant_id: str,
    db: AsyncSession,
    period_days: int = 90,
) -> Dict[str, Any]:
    collector = STANDARD_COLLECTOR_MAP.get(standard)
    if collector:
        return await collector(tenant_id, db, period_days)
    return {}


def _build_report_rows(
    report_dict: Dict[str, Any],
    evidence: Dict[str, Any],
    standard_name: str,
) -> List[Dict[str, Any]]:
    rows = []
    summary = report_dict.get("summary", {})
    base = {
        "report_id": report_dict.get("id"),
        "standard": standard_name,
        "generated_at": report_dict.get("generated_at"),
        "period_start": report_dict.get("period_start"),
        "period_end": report_dict.get("period_end"),
        "overall_score": report_dict.get("overall_score"),
        "total_controls": summary.get("total_controls", 0),
        "passed": summary.get("passed", 0),
        "failed": summary.get("failed", 0),
        "warning": summary.get("warning", 0),
        "not_applicable": summary.get("not_applicable", 0),
    }

    control_results = report_dict.get("control_results", [])
    if control_results:
        for cr in control_results:
            row = {
                **base,
                "control_id": cr.get("control_id"),
                "status": cr.get("status"),
                "details": cr.get("details"),
                "checked_at": cr.get("checked_at"),
            }
            rows.append(row)
    else:
        rows.append(base)

    evidence_sections = {k: v for k, v in evidence.items() if isinstance(v, dict)}
    if evidence_sections:
        ev_row = {**base, "control_id": "evidence_summary", "status": "info"}
        for section_name, section_data in evidence_sections.items():
            ev_row[f"evidence_{section_name}_status"] = section_data.get("status", "unknown")
        rows.append(ev_row)

    return rows


def _report_to_csv(report_dict: Dict[str, Any], evidence: Dict[str, Any], standard_name: str) -> str:
    output = io.StringIO()
    rows = _build_report_rows(report_dict, evidence, standard_name)
    if not rows:
        return ""

    fieldnames = list(rows[0].keys())
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@router.get("/report/{standard}/download", summary="Download compliance report")
async def download_compliance_report(
    standard: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    period_days: int = Query(90, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Generate and download a compliance report for the specified framework."""
    try:
        std = ComplianceStandard(standard)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown standard: {standard}")

    report = await reporter.generate_report(
        standard=std,
        tenant_id=tenant_id,
        db=db,
        period_days=period_days,
        include_evidence=True,
    )
    report_dict = reporter._report_to_dict(report)
    evidence = await _collect_standard_evidence(std, tenant_id, db, period_days)
    display_name = STANDARD_DISPLAY_NAMES.get(standard, standard.upper())
    timestamp = _utcnow_str()[:10]

    if format == "csv":
        csv_content = _report_to_csv(report_dict, evidence, display_name)
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="compliance-{standard}-{timestamp}.csv"',
            },
        )

    payload = {
        "report": report_dict,
        "evidence": evidence,
        "generated_at": _utcnow_str(),
        "standard": display_name,
        "tenant_id": tenant_id,
        "format": "cybernova-compliance-report-v1",
    }
    return StreamingResponse(
        iter([json.dumps(payload, indent=2, default=str)]),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="compliance-{standard}-{timestamp}.json"',
        },
    )


@router.get("/report/summary", summary="Cross-framework compliance summary")
async def compliance_summary(
    period_days: int = Query(90, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Generate a summary across all compliance frameworks."""
    results = {}
    for std in (ComplianceStandard.SOC2, ComplianceStandard.PCI_DSS, ComplianceStandard.HIPAA, ComplianceStandard.GDPR):
        try:
            report = await reporter.generate_report(
                standard=std,
                tenant_id=tenant_id,
                db=db,
                period_days=period_days,
                include_evidence=False,
            )
            name = STANDARD_DISPLAY_NAMES.get(std.value, std.value.upper())
            results[name] = {
                "overall_score": report.overall_score,
                "total_controls": report.summary.get("total_controls", 0),
                "passed": report.summary.get("passed", 0),
                "failed": report.summary.get("failed", 0),
                "warning": report.summary.get("warning", 0),
                "generated_at": report.generated_at,
            }
        except Exception as e:
            log.warning("Failed to generate %s report: %s", std.value, e)
            results[std.value] = {"error": str(e)}

    all_scores = [v["overall_score"] for v in results.values() if "overall_score" in v]
    return {
        "tenant_id": tenant_id,
        "generated_at": _utcnow_str(),
        "period_days": period_days,
        "frameworks": results,
        "overall_compliance_score": round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0,
    }
