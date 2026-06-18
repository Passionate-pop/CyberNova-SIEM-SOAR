"""
CyberNova — Demo Control Endpoints
POST /api/v1/demo/reset   — Reset system to clean state
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import (
    Alert, Incident, ResponseAction, RawEvent,
    NormalizedEvent, EnrichedEvent, Device, TenantUsageDaily,
)
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.audit.service import audit_service

log = logging.getLogger("cybernova.demo")
router = APIRouter(prefix="/api/v1/demo", tags=["Demo Control"])


@router.post("/reset", summary="Reset system to clean state")
async def reset_demo(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Delete all alerts, incidents, response actions, events, devices.
    Keeps users, tenants, and rules intact.
    """
    if user.roles and "admin" not in user.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Delete in dependency order
    tables = [ResponseAction, Alert, Incident, EnrichedEvent, NormalizedEvent, RawEvent, Device, TenantUsageDaily]
    deleted = {}
    for table in tables:
        result = await db.execute(
            select(table).where(table.tenant_id == tenant_id)
        )
        rows = result.scalars().all()
        count = len(rows)
        for row in rows:
            await db.delete(row)
        deleted[table.__tablename__] = count

    # Reset unified pipeline metrics
    unified_pipeline._metrics = {
        "ingested": 0, "normalized": 0, "enriched": 0,
        "detected": 0, "correlated": 0, "alerted": 0,
        "soared": 0, "errors": 0, "latency_ms": [],
    }

    await audit_service.log(
        db=db, action="demo_reset", tenant_id=tenant_id, user_id=user.id,
        resource_type="system", resource_id=None,
        details=deleted,
    )
    await db.commit()

    log.warning("Demo reset performed by %s", user.email)
    return {"success": True, "deleted": deleted, "message": "System reset to clean state"}
