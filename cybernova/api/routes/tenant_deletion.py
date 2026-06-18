"""
CyberNova — Tenant Data Deletion API (GDPR Right to Deletion)
Cascade deletes all tenant data across every tenant-scoped table.
Runs asynchronously to avoid blocking the request.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Tenant
from cybernova.database.postgres.row_security import TENANT_SCOPED_TABLES
from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin
from cybernova.audit.service import audit_service, AuditAction, AuditResource

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin/tenants", tags=["Tenant Deletion"])


class DeletionStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DeletionRun:
    status: DeletionStatus = DeletionStatus.PENDING
    total_tables: int = 0
    completed_tables: int = 0
    total_rows: int = 0
    deleted_rows: int = 0
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    tenant_id: str = ""
    requested_by: str = ""


_deletion_runs: Dict[str, DeletionRun] = {}


class DeletionStatusResponse(BaseModel):
    tenant_id: str
    status: DeletionStatus
    total_tables: int
    completed_tables: int
    total_rows: int
    deleted_rows: int
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class DeletionInitiateResponse(BaseModel):
    tenant_id: str
    status: DeletionStatus
    message: str


async def _cascade_delete(tenant_id: str, requested_by: str, db: AsyncSession) -> None:
    run = _deletion_runs[tenant_id]
    run.status = DeletionStatus.IN_PROGRESS
    run.started_at = datetime.now(timezone.utc).isoformat()

    try:
        for table in TENANT_SCOPED_TABLES:
            stmt_count = select(text("COUNT(*)")).select_from(text(table)).where(
                text("tenant_id = :tenant_id")
            )
            result = await db.execute(stmt_count, {"tenant_id": tenant_id})
            count = result.scalar() or 0
            run.total_rows += count

            if count > 0:
                stmt_del = delete(text(table)).where(text("tenant_id = :tenant_id"))
                result = await db.execute(stmt_del, {"tenant_id": tenant_id})
                run.deleted_rows += result.rowcount

            run.completed_tables += 1

        stmt_del_tenant = delete(Tenant).where(Tenant.id == tenant_id)
        result = await db.execute(stmt_del_tenant)
        if result.rowcount == 0:
            log.warning("Tenant %s not found during deletion", tenant_id)

        await db.commit()

        run.status = DeletionStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc).isoformat()

        await audit_service.log(
            db=db,
            action=AuditAction.DATA_DELETED,
            tenant_id=tenant_id,
            user_id=requested_by,
            resource_type=AuditResource.TENANT,
            resource_id=tenant_id,
            details={
                "tables_cleared": run.completed_tables,
                "rows_deleted": run.deleted_rows,
                "completed_at": run.completed_at,
            },
        )
        await db.commit()

    except Exception as exc:
        await db.rollback()
        run.status = DeletionStatus.FAILED
        run.error = str(exc)
        log.error("Tenant deletion failed for %s: %s", tenant_id, exc)


@router.post("/{tenant_id}/delete", response_model=DeletionInitiateResponse)
async def initiate_tenant_deletion(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """Initiate cascade deletion of all data for a tenant (GDPR right to deletion).
    Runs asynchronously — poll /{tenant_id}/deletion-status for completion."""

    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if tenant_id in _deletion_runs:
        existing = _deletion_runs[tenant_id]
        if existing.status in (DeletionStatus.PENDING, DeletionStatus.IN_PROGRESS):
            raise HTTPException(
                status_code=409,
                detail=f"Deletion already in progress (status: {existing.status.value})",
            )

    _deletion_runs[tenant_id] = DeletionRun(tenant_id=tenant_id, requested_by=user.id)

    asyncio.create_task(_cascade_delete(tenant_id, user.id, db))

    return DeletionInitiateResponse(
        tenant_id=tenant_id,
        status=DeletionStatus.PENDING,
        message=f"Deletion of tenant {tenant_id} initiated. "
                f"Poll /api/v1/admin/tenants/{tenant_id}/deletion-status for progress.",
    )


@router.get("/{tenant_id}/deletion-status", response_model=DeletionStatusResponse)
async def get_deletion_status(
    tenant_id: str,
    user: CurrentUser = Depends(require_admin),
):
    """Check the status of an in-progress or completed tenant deletion."""

    run = _deletion_runs.get(tenant_id)
    if not run:
        stmt = select(Tenant).where(Tenant.id == tenant_id)
        async for db in get_db():
            result = await db.execute(stmt)
            tenant = result.scalar_one_or_none()
            break
        if tenant:
            raise HTTPException(
                status_code=404,
                detail="No deletion found for this tenant",
            )
        return DeletionStatusResponse(
            tenant_id=tenant_id,
            status=DeletionStatus.COMPLETED,
            total_tables=0,
            completed_tables=0,
            total_rows=0,
            deleted_rows=0,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

    return DeletionStatusResponse(
        tenant_id=run.tenant_id,
        status=run.status,
        total_tables=len(TENANT_SCOPED_TABLES),
        completed_tables=run.completed_tables,
        total_rows=run.total_rows,
        deleted_rows=run.deleted_rows,
        error=run.error,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )
