"""
CyberNova — Notifications API Router
Real notification persistence with WebSocket integration.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Notification
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id

log = logging.getLogger("cybernova.notifications")
router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


@router.get("", summary="List notifications for current user")
async def list_notifications(
    limit: int = Query(50, le=100),
    unread_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    # Return user-specific + system-level (user_id IS NULL) notifications
    # so alert-generated notifications are visible to all users in the tenant.
    query = select(Notification).where(
        Notification.tenant_id == tenant_id,
        (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
    )
    if unread_only:
        query = query.where(Notification.read == False)
    query = query.order_by(Notification.created_at.desc()).limit(limit)

    result = await db.execute(query)
    notifications = result.scalars().all()

    unread_count = await db.execute(
        select(func.count(Notification.id)).where(
            Notification.tenant_id == tenant_id,
            (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
            Notification.read == False,
        )
    )

    return {
        "notifications": [
            {
                "id": n.id,
                "type": n.type,
                "title": n.title,
                "message": n.message or "",
                "read": n.read,
                "timestamp": n.created_at.isoformat() if n.created_at else "",
            }
            for n in notifications
        ],
        "unread_count": unread_count.scalar() or 0,
    }


@router.put("/{notification_id}/read", summary="Mark notification as read")
async def mark_read(
    notification_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.tenant_id == tenant_id,
        )
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.read = True
    await db.commit()
    return {"success": True}


@router.put("/read-all", summary="Mark all notifications as read")
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    await db.execute(
        update(Notification)
        .where(
            Notification.tenant_id == tenant_id,
            ((Notification.user_id == user.id) | (Notification.user_id.is_(None))),
            Notification.read == False,
        )
        .values(read=True)
    )
    await db.commit()
    return {"success": True}


async def push_notification(
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    type: str,
    title: str,
    message: Optional[str] = None,
) -> Notification:
    """Create a notification and push via WebSocket. Imported by other services."""
    from cybernova.core.utils.helpers import new_id

    notification = Notification(
        id=new_id(),
        tenant_id=tenant_id,
        user_id=user_id,
        type=type,
        title=title,
        message=message,
        read=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(notification)

    from cybernova.api.websocket import ws_handler
    from cybernova.api.websocket import WebSocketMessage, EventType

    ws_msg = WebSocketMessage(
        event_type=EventType.SYSTEM_NOTIFICATION,
        data={
            "id": notification.id,
            "type": type,
            "title": title,
            "message": message or "",
            "timestamp": notification.created_at.isoformat() if notification.created_at else "",
        },
        tenant_id=tenant_id,
    )
    await ws_handler._manager.send_to_tenant(tenant_id, ws_msg, {EventType.SYSTEM_NOTIFICATION})

    return notification
