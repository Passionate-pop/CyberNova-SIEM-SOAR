from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.compliance.framework import ComplianceStandard, ControlFramework
from cybernova.compliance.reporter import ComplianceReporter
from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser, get_current_user

log = logging.getLogger("cybernova.compliance.router")
router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

framework = ControlFramework()
reporter = ComplianceReporter()


class ReportRequest(BaseModel):
    standard: str
    period_days: int = 90
    include_evidence: bool = True


@router.get("/standards", summary="List supported compliance standards")
async def list_standards(
    user: CurrentUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    return framework.get_all_standards()


@router.get("/standards/{standard}/controls", summary="List controls for a standard")
async def list_controls(
    standard: str,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    try:
        std = ComplianceStandard(standard)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown standard: {standard}")

    controls = framework.get_controls(std)
    return {
        "standard": standard,
        "control_count": len(controls),
        "controls": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "category": c.category,
                "severity": c.severity,
                "evidence_required": c.evidence_required,
                "remediation": c.remediation,
            }
            for c in controls
        ],
    }


@router.post("/report", summary="Generate a compliance report")
async def generate_report(
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
) -> Dict[str, Any]:
    try:
        standard = ComplianceStandard(body.standard)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown standard: {body.standard}")

    report = await reporter.generate_report(
        standard=standard,
        tenant_id=tenant_id,
        db=db,
        period_days=body.period_days,
        include_evidence=body.include_evidence,
    )

    return reporter._report_to_dict(report)


@router.get("/reports", summary="List generated reports")
async def list_reports(
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
) -> List[Dict[str, Any]]:
    return reporter.list_reports(tenant_id)


@router.get("/reports/{report_id}", summary="Get report detail")
async def get_report(
    report_id: str,
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
) -> Dict[str, Any]:
    report = reporter.get_report(tenant_id, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
