"""
CyberNova — Noise Control Routes
POST /api/v1/detect/alerts/{id}/snooze
POST /api/v1/detect/whitelist
POST /api/v1/detect/alerts/{id}/mark-safe
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import (
    AlertSuppression, WhitelistEntry, Alert,
)
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.audit.service import audit_service
from cybernova.monitoring.metrics import metrics

log = logging.getLogger("cybernova.noise")
router = APIRouter(prefix="/api/v1/detect", tags=["Noise Control"])


class SnoozeRequest(BaseModel):
    hours: int = 24


class WhitelistRequest(BaseModel):
    entity: str
    entity_type: str = "ip"
    reason: Optional[str] = None


@router.post("/alerts/{alert_id}/snooze", summary="Snooze an alert for N hours")
async def snooze_alert(
    alert_id: str,
    payload: SnoozeRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    expires = datetime.now(timezone.utc) + timedelta(hours=payload.hours)
    entity = (alert.extra_data or {}).get("source_ip", alert_id)

    suppression = AlertSuppression(
        tenant_id=tenant_id,
        rule_id=alert.rule_name,
        entity=entity,
        entity_type="ip",
        expires_at=expires,
        created_by=user.id,
    )
    db.add(suppression)
    alert.status = "snoozed"
    await db.commit()

    await audit_service.log(
        db=db, action="alert_snoozed", tenant_id=tenant_id, user_id=user.id,
        resource_type="alert", resource_id=alert_id,
        details={"hours": payload.hours, "entity": entity},
    )
    return {"success": True, "expires_at": expires.isoformat()}


@router.post("/whitelist", summary="Add entity to whitelist")
async def add_whitelist(
    payload: WhitelistRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    # Check if already whitelisted
    result = await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.tenant_id == tenant_id,
            WhitelistEntry.entity == payload.entity,
            WhitelistEntry.entity_type == payload.entity_type,
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Entity already whitelisted")

    entry = WhitelistEntry(
        tenant_id=tenant_id,
        entity=payload.entity,
        entity_type=payload.entity_type,
        reason=payload.reason,
        created_by=user.id,
    )
    db.add(entry)
    await db.commit()

    await audit_service.log(
        db=db, action="entity_whitelisted", tenant_id=tenant_id, user_id=user.id,
        resource_type="whitelist", resource_id=entry.id,
        details={"entity": payload.entity, "reason": payload.reason},
    )
    return {"success": True, "id": entry.id}


@router.post("/alerts/{alert_id}/mark-safe", summary="Mark alert as false positive")
async def mark_safe(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "false_positive"
    metrics.increment("alerts_false_positive_total", tags={"rule": alert.rule_name or "unknown"})
    await audit_service.log(
        db=db, action="alert_marked_safe", tenant_id=tenant_id, user_id=user.id,
        resource_type="alert", resource_id=alert_id,
    )
    await db.commit()
    return {"success": True}
