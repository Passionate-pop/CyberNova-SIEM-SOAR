"""
CyberNova — Audit Logging API Routes
REST endpoints for viewing and querying audit logs.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import RequirePermission
from cybernova.auth.rbac import Permission
from cybernova.audit.service import audit_service, AuditAction, AuditResource

require_audit = RequirePermission(Permission.AUDIT_VIEW)

log = logging.getLogger("cybernova.audit.api")

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Logging"])


@router.get("/logs", summary="Get audit logs")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action (e.g., 'login', 'alert_updated')"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    start_date: Optional[datetime] = Query(None, description="Filter from date (ISO format)"),
    end_date: Optional[datetime] = Query(None, description="Filter to date (ISO format)"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_audit),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Query audit logs with filters.
    
    Returns chronological list of all administrative actions.
    """
    logs = await audit_service.get_logs(
        db=db,
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        start_date=start_date,
        end_date=end_date,
    )

    return {
        "logs": [
            {
                "id": log_entry.id,
                "user_id": log_entry.user_id,
                "action": log_entry.action,
                "resource_type": log_entry.resource_type,
                "resource_id": log_entry.resource_id,
                "details": log_entry.details,
                "ip_address": log_entry.ip_address,
                "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
            }
            for log_entry in logs
        ],
        "total": len(logs),
        "limit": limit,
        "offset": offset,
    }


@router.get("/logs/security", summary="Get security events")
async def get_security_events(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_audit),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Get security-related audit events.
    
    Includes: login failures, password changes, user deletions, API key operations.
    """
    logs = await audit_service.get_security_events(
        db=db,
        tenant_id=tenant_id,
        days=days,
    )

    return {
        "events": [
            {
                "id": log_entry.id,
                "user_id": log_entry.user_id,
                "action": log_entry.action,
                "resource_type": log_entry.resource_type,
                "resource_id": log_entry.resource_id,
                "details": log_entry.details,
                "ip_address": log_entry.ip_address,
                "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
            }
            for log_entry in logs
        ],
        "total": len(logs),
        "period_days": days,
    }


@router.get("/users/{user_id}/activity", summary="Get user activity")
async def get_user_activity(
    user_id: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_audit),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Get activity log for a specific user.
    
    Shows all actions performed by the user within the specified period.
    """
    logs = await audit_service.get_user_activity(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        days=days,
    )

    return {
        "user_id": user_id,
        "activities": [
            {
                "id": log_entry.id,
                "action": log_entry.action,
                "resource_type": log_entry.resource_type,
                "resource_id": log_entry.resource_id,
                "details": log_entry.details,
                "ip_address": log_entry.ip_address,
                "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
            }
            for log_entry in logs
        ],
        "total": len(logs),
        "period_days": days,
    }


@router.get("/actions", summary="List available audit actions")
async def list_audit_actions():
    """List all possible audit action types."""
    return {
        "actions": [
            {"value": a.value, "name": a.name}
            for a in AuditAction
        ],
        "resources": [
            {"value": r.value, "name": r.name}
            for r in AuditResource
        ],
    }


@router.get("/roles", summary="List available roles and permissions")
async def list_roles_and_permissions(
    current_user: CurrentUser = Depends(require_audit),
):
    """List all available roles and their permissions."""
    from cybernova.auth.rbac import list_roles
    return {"roles": list_roles()}


@router.get("/stats", summary="Get audit statistics")
async def get_audit_stats(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_audit),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Get audit statistics for the specified period.
    
    Returns counts by action type and resource type.
    """
    from datetime import timedelta
    from sqlalchemy import select, func
    from cybernova.database.postgres.models import AuditLog

    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    result = await db.execute(
        select(
            AuditLog.action,
            func.count(AuditLog.id).label("count")
        )
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.timestamp >= start_date,
        )
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
    )
    by_action = [{"action": r[0], "count": r[1]} for r in result.all()]

    result = await db.execute(
        select(
            AuditLog.resource_type,
            func.count(AuditLog.id).label("count")
        )
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.timestamp >= start_date,
        )
        .group_by(AuditLog.resource_type)
        .order_by(func.count(AuditLog.id).desc())
    )
    by_resource = [{"resource": r[0] or "unknown", "count": r[1]} for r in result.all()]

    result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.timestamp >= start_date,
        )
    )
    total = result.scalar() or 0

    result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action == AuditAction.LOGIN_FAILED.value,
            AuditLog.timestamp >= start_date,
        )
    )
    failed_logins = result.scalar() or 0

    return {
        "period_days": days,
        "total_events": total,
        "failed_logins": failed_logins,
        "by_action": by_action,
        "by_resource": by_resource,
    }
