"""
CyberNova — Tenant Data Export API (GDPR Right to Data Portability)
Exports all tenant data as structured JSON with a SIEM-compatible event stream.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Tenant
from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin
from cybernova.audit.service import audit_service, AuditAction, AuditResource

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin/tenants", tags=["Tenant Export"])

EXPORT_TABLES = [
    "organization_keys",
    "subscriptions",
    "api_keys",
    "tenant_usage_daily",
    "users",
    "devices",
    "device_commands",
    "raw_events",
    "normalized_events",
    "enriched_events",
    "alerts",
    "incidents",
    "alert_suppressions",
    "whitelist_entries",
    "playbooks",
    "notifications",
    "response_actions",
    "audit_logs",
    "correlation_rules",
    "detection_rules",
    "blocked_ips",
    "analytics_events",
    "user_sessions",
    "insights",
    "dead_letter_events",
    "training_records",
    "model_registry",
    "entity_baselines",
    "drift_records",
    "ab_tests",
    "ab_test_results",
]


class ExportStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ExportRun:
    status: ExportStatus = ExportStatus.PENDING
    total_tables: int = 0
    completed_tables: int = 0
    total_rows: int = 0
    data: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    siem_events: List[Dict[str, Any]] = field(default_factory=list)
    tenant_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    tenant_id: str = ""
    requested_by: str = ""


_export_runs: Dict[str, ExportRun] = {}


class ExportInitiateResponse(BaseModel):
    tenant_id: str
    status: ExportStatus
    message: str


class ExportStatusResponse(BaseModel):
    tenant_id: str
    status: ExportStatus
    total_tables: int
    completed_tables: int
    total_rows: int
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    download_ready: bool = False


def _row_to_dict(row: Any) -> Dict[str, Any]:
    d = dict(row._mapping)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def _build_siem_event(row: Dict[str, Any], table: str) -> Optional[Dict[str, Any]]:
    if table == "normalized_events":
        return {
            "event_type": row.get("event_type", ""),
            "severity": row.get("severity", "info"),
            "timestamp": row.get("timestamp") or row.get("normalized_at"),
            "source_ip": row.get("source_ip", ""),
            "dest_ip": row.get("dest_ip", ""),
            "source_port": row.get("source_port"),
            "dest_port": row.get("dest_port"),
            "protocol": row.get("protocol", ""),
            "user": row.get("user", ""),
            "message": row.get("message", ""),
            "device_id": row.get("device_id"),
            "extra_data": row.get("extra_data"),
            "table_source": "normalized_events",
            "original_id": row.get("id"),
        }
    if table == "alerts":
        return {
            "event_type": f"alert_{row.get('rule_name', 'unknown')}",
            "severity": row.get("severity", "medium"),
            "timestamp": row.get("created_at"),
            "source_ip": row.get("source_ip", ""),
            "dest_ip": row.get("dest_ip", ""),
            "user": row.get("user", ""),
            "message": row.get("description", ""),
            "rule_name": row.get("rule_name"),
            "status": row.get("status"),
            "risk_score": row.get("risk_score"),
            "mitre_tactic": row.get("mitre_tactic"),
            "mitre_technique": row.get("mitre_technique"),
            "table_source": "alerts",
            "original_id": row.get("id"),
        }
    if table == "raw_events":
        return {
            "event_type": "raw_event",
            "severity": "info",
            "timestamp": row.get("received_at"),
            "source": row.get("source", ""),
            "source_type": row.get("source_type", ""),
            "payload": row.get("payload"),
            "table_source": "raw_events",
            "original_id": row.get("id"),
        }
    if table == "incidents":
        return {
            "event_type": "incident",
            "severity": row.get("severity", "medium"),
            "timestamp": row.get("created_at"),
            "message": row.get("description", ""),
            "title": row.get("title"),
            "status": row.get("status"),
            "risk_score": row.get("risk_score"),
            "assigned_to": row.get("assigned_to"),
            "table_source": "incidents",
            "original_id": row.get("id"),
        }
    return None


async def _export_tenant_data(tenant_id: str, requested_by: str, db: AsyncSession) -> None:
    run = _export_runs[tenant_id]
    run.status = ExportStatus.IN_PROGRESS
    run.started_at = datetime.now(timezone.utc).isoformat()

    try:
        result = await db.execute(
            select(Tenant).where(Tenant.id == tenant_id)
        )
        tenant = result.scalar_one_or_none()
        if tenant:
            run.tenant_info = _row_to_dict(tenant)

        for table in EXPORT_TABLES:
            rows_result = await db.execute(
                text(f"SELECT * FROM {table} WHERE tenant_id = :tenant_id"),  # nosec - table from whitelist EXPORT_TABLES, value parameterized
                {"tenant_id": tenant_id},
            )
            rows = rows_result.fetchall()
            table_rows = [_row_to_dict(r) for r in rows]
            run.data[table] = table_rows
            run.total_rows += len(table_rows)
            run.completed_tables += 1

            for row in table_rows:
                siem = _build_siem_event(row, table)
                if siem:
                    run.siem_events.append(siem)

            log.debug("Exported %d rows from %s", len(table_rows), table)

        run.status = ExportStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc).isoformat()

        await audit_service.log(
            db=db,
            action=AuditAction.DATA_EXPORTED,
            tenant_id=tenant_id,
            user_id=requested_by,
            resource_type=AuditResource.TENANT,
            resource_id=tenant_id,
            details={
                "tables_exported": run.completed_tables,
                "rows_exported": run.total_rows,
                "completed_at": run.completed_at,
            },
        )
        await db.commit()

    except Exception as exc:
        await db.rollback()
        run.status = ExportStatus.FAILED
        run.error = str(exc)
        log.error("Tenant export failed for %s: %s", tenant_id, exc)


@router.post("/{tenant_id}/export", response_model=ExportInitiateResponse)
async def initiate_tenant_export(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """Initiate export of all data for a tenant (GDPR data portability).
    Runs asynchronously — poll /{tenant_id}/export-status for completion,
    then download via /{tenant_id}/export."""

    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if tenant_id in _export_runs:
        existing = _export_runs[tenant_id]
        if existing.status in (ExportStatus.PENDING, ExportStatus.IN_PROGRESS):
            raise HTTPException(
                status_code=409,
                detail=f"Export already in progress (status: {existing.status.value})",
            )

    _export_runs[tenant_id] = ExportRun(tenant_id=tenant_id, requested_by=user.id)
    asyncio.create_task(_export_tenant_data(tenant_id, user.id, db))

    return ExportInitiateResponse(
        tenant_id=tenant_id,
        status=ExportStatus.PENDING,
        message=f"Export of tenant {tenant_id} initiated. "
                f"Poll /api/v1/admin/tenants/{tenant_id}/export-status for progress.",
    )


@router.get("/{tenant_id}/export-status", response_model=ExportStatusResponse)
async def get_export_status(
    tenant_id: str,
    user: CurrentUser = Depends(require_admin),
):
    """Check the status of an in-progress or completed tenant export."""

    run = _export_runs.get(tenant_id)
    if not run:
        raise HTTPException(status_code=404, detail="No export found for this tenant")

    return ExportStatusResponse(
        tenant_id=run.tenant_id,
        status=run.status,
        total_tables=len(EXPORT_TABLES),
        completed_tables=run.completed_tables,
        total_rows=run.total_rows,
        error=run.error,
        started_at=run.started_at,
        completed_at=run.completed_at,
        download_ready=run.status == ExportStatus.COMPLETED,
    )


@router.get("/{tenant_id}/export")
async def download_tenant_export(
    tenant_id: str,
    user: CurrentUser = Depends(require_admin),
):
    """Download the completed tenant data export as JSON."""

    run = _export_runs.get(tenant_id)
    if not run or run.status != ExportStatus.COMPLETED:
        raise HTTPException(
            status_code=404 if not run else 425,
            detail="Export not ready" if run else "No export found for this tenant",
        )

    payload = {
        "export_metadata": {
            "tenant_id": tenant_id,
            "exported_at": run.completed_at,
            "format": "cybernova-export-v1",
            "total_records": run.total_rows,
            "tables_exported": run.completed_tables,
            "requested_by": run.requested_by,
        },
        "tenant": run.tenant_info,
        "siem_events": run.siem_events,
    }
    payload.update(run.data)

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cybernova-export-{tenant_id}-{run.completed_at[:10]}.json"',
        },
    )
