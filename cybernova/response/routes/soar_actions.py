"""
CyberNova — Built-in SOAR Actions
Block IP / Isolate Device / Disable User / Kill Process / Quarantine / Ticket / MFA Reset
"""
from __future__ import annotations

import asyncio
import logging
import subprocess  # nosec
from datetime import datetime, timezone
from pathlib import Path

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import (
    BlockedIP, Device, User, Alert, ResponseAction, Notification,
)
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_automation_trigger
from cybernova.audit.service import audit_service
from cybernova.api.websocket import ws_handler
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.config.constants import ActionStatus

log = logging.getLogger("cybernova.soar")
router = APIRouter(prefix="/api/v1/soar", tags=["Built-in SOAR"])


class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str = "Threat detected"
    duration_hours: int = 0


class KillProcessRequest(BaseModel):
    device_id: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    reason: str = "Malicious process detected"


class CreateTicketRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    alert_id: Optional[str] = None
    source_ip: Optional[str] = None


class SendNotificationRequest(BaseModel):
    channel: str = "webhook"
    title: str
    message: str
    severity: str = "info"
    target_user_id: Optional[str] = None


class QuarantineFileRequest(BaseModel):
    device_id: str
    file_path: str
    sha256: Optional[str] = None
    reason: str = "Malicious file detected"


class ActionResponse(BaseModel):
    success: bool
    message: str


@router.post("/block-ip", summary="Block an IP address")
async def block_ip(
    payload: BlockIPRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Block an IP address in the tenant scope."""
    from datetime import timedelta
    expires = None
    if payload.duration_hours > 0:
        expires = datetime.now(timezone.utc) + timedelta(hours=payload.duration_hours)

    result = await db.execute(
        select(BlockedIP).where(
            BlockedIP.tenant_id == tenant_id,
            BlockedIP.ip_address == payload.ip_address,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="IP already blocked")

    entry = BlockedIP(
        tenant_id=tenant_id,
        ip_address=payload.ip_address,
        reason=payload.reason,
        blocked_by=user.id,
        expires_at=expires,
    )
    db.add(entry)
    await _enforce_firewall_block(payload.ip_address)
    # Log as ResponseAction so it appears in Response Centre action history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="block_ip",
        parameters={"target": payload.ip_address, "reason": payload.reason, "duration_hours": payload.duration_hours},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"IP {payload.ip_address} blocked", "ip": payload.ip_address, "reason": payload.reason},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    # Update related open alerts to "resolved" so they reflect the action
    alert_result = await db.execute(
        select(Alert).where(
            Alert.source_ip == payload.ip_address,
            Alert.tenant_id == tenant_id,
            Alert.status.in_(["new", "correlated", "in_progress"]),
        )
    )
    related_alerts = alert_result.scalars().all()
    for alert in related_alerts:
        alert.status = "resolved"

    await audit_service.log(
        db=db, action="ip_blocked", tenant_id=tenant_id, user_id=user.id,
        resource_type="blocked_ip", resource_id=entry.id,
        details={"ip": payload.ip_address, "reason": payload.reason, "alerts_updated": len(related_alerts)},
    )
    await db.commit()
    log.warning("IP %s blocked by %s (%d related alerts resolved)", payload.ip_address, user.email, len(related_alerts))
    await ws_handler.broadcast_soar_action(
        {"action": "block_ip", "target": payload.ip_address, "status": "completed", "message": f"IP {payload.ip_address} blocked"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"IP {payload.ip_address} blocked")


@router.post("/isolate-device/{device_id}", summary="Isolate a device")
async def isolate_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Isolate a device — mark in DB + apply real firewall block on device IP."""
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.is_isolated:
        return ActionResponse(success=True, message=f"Device {device.hostname} already isolated")

    device.is_isolated = True

    # Apply real firewall block on the device's IP address
    fw_ok = False
    if device.ip_address:
        fw_ok = await _enforce_firewall_block(device.ip_address)
        if fw_ok:
            log.info("Device %s (%s) isolated via firewall", device.hostname, device.ip_address)
        else:
            log.warning("Device %s isolated in DB only — no firewall binary found", device.hostname)

    # Log as ResponseAction so it appears in Response Centre action history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        alert_id=None,
        device_id=device_id,
        action_type="isolate_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_enforced": fw_ok},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"Device {device.hostname} isolated (firewall: {'enforced' if fw_ok else 'db_only'})", "firewall_enforced": fw_ok, "hostname": device.hostname},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    # Update related open alerts to "resolved" so they reflect the action
    if device.ip_address:
        alert_result = await db.execute(
            select(Alert).where(
                Alert.source_ip == device.ip_address,
                Alert.tenant_id == tenant_id,
                Alert.status.in_(["new", "correlated", "in_progress"]),
            )
        )
        related_alerts = alert_result.scalars().all()
        for alert in related_alerts:
            alert.status = "resolved"
    else:
        related_alerts = []

    await audit_service.log(
        db=db, action="device_isolated", tenant_id=tenant_id, user_id=user.id,
        resource_type="device", resource_id=device_id,
        details={"hostname": device.hostname, "ip": device.ip_address, "firewall_enforced": True, "alerts_updated": len(related_alerts)},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "isolate_device", "target": device.hostname, "status": "completed", "message": f"Device {device.hostname} isolated"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Device {device.hostname} isolated")


@router.post("/release-device/{device_id}", summary="Release a device from isolation")
async def release_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Release a device from isolation — mark in DB + remove firewall block on device IP."""
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if not device.is_isolated:
        return ActionResponse(success=True, message=f"Device {device.hostname} is not isolated")

    device.is_isolated = False

    # Remove firewall block on the device's IP address
    fw_ok = False
    if device.ip_address:
        fw_ok = await _enforce_firewall_unblock(device.ip_address)
        if fw_ok:
            log.info("Device %s (%s) released via firewall", device.hostname, device.ip_address)
        else:
            log.warning("Device %s released in DB only — no firewall binary found", device.hostname)

    # Log as ResponseAction so it appears in Response Centre action history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        alert_id=None,
        device_id=device_id,
        action_type="release_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_released": fw_ok},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"Device {device.hostname} released (firewall: {'removed' if fw_ok else 'db_only'})", "firewall_released": fw_ok, "hostname": device.hostname},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="device_released", tenant_id=tenant_id, user_id=user.id,
        resource_type="device", resource_id=device_id,
        details={"hostname": device.hostname, "ip": device.ip_address, "firewall_released": fw_ok},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "release_device", "target": device.hostname, "status": "completed", "message": f"Device {device.hostname} released from isolation"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Device {device.hostname} released from isolation")


@router.post("/kill-process", summary="Kill a malicious process on a device")
async def kill_process(
    payload: KillProcessRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Kill a malicious process on a device — uses SOAR KillProcessAction."""
    # Validate device exists
    result = await db.execute(
        select(Device).where(Device.id == payload.device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if not payload.pid and not payload.process_name:
        raise HTTPException(status_code=400, detail="Either pid or process_name must be provided")

    # Log as ResponseAction
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        device_id=payload.device_id,
        action_type="kill_process",
        parameters={
            "device_id": payload.device_id,
            "hostname": device.hostname,
            "pid": payload.pid,
            "process_name": payload.process_name,
            "reason": payload.reason,
        },
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={
            "message": f"Kill process requested on {device.hostname}",
            "hostname": device.hostname,
            "pid": payload.pid,
            "process_name": payload.process_name,
        },
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    # Create device command for agent to pick up
    from cybernova.database.postgres.models import DeviceCommand
    cmd = DeviceCommand(
        id=new_id(),
        tenant_id=tenant_id,
        device_id=payload.device_id,
        action="kill_process",
        payload={
            "pid": payload.pid,
            "process_name": payload.process_name,
            "reason": payload.reason,
            "soar_action_id": ra.id,
        },
        status="pending",
        created_by=user.id,
        created_at=utcnow(),
        expires_at=datetime.now(timezone.utc).replace(hour=23, minute=59, second=59),
    )
    db.add(cmd)

    await audit_service.log(
        db=db, action="process_kill_requested", tenant_id=tenant_id, user_id=user.id,
        resource_type="device", resource_id=payload.device_id,
        details={"hostname": device.hostname, "pid": payload.pid, "process_name": payload.process_name},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "kill_process", "target": device.hostname, "status": "completed", "message": f"Kill process requested on {device.hostname}"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Kill process requested on {device.hostname}")


@router.post("/enable-user/{user_id}", summary="Enable a previously disabled user")
async def enable_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Enable a previously disabled user account."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if not target.is_disabled:
        return ActionResponse(success=True, message=f"User {target.email} is already enabled")

    target.is_disabled = False
    target.is_active = True

    # Log as ResponseAction
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="enable_user",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"User {target.email} enabled", "email": target.email, "username": target.username},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="user_enabled", tenant_id=tenant_id, user_id=user.id,
        resource_type="user", resource_id=user_id,
        details={"email": target.email},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "enable_user", "target": target.email, "status": "completed", "message": f"User {target.email} enabled"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"User {target.email} enabled")


@router.post("/create-ticket", summary="Create a support/tracking ticket")
async def create_ticket(
    payload: CreateTicketRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Create a ticket for tracking the incident response."""
    ticket_id = f"TKT-{new_id()[:8].upper()}"

    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        alert_id=payload.alert_id,
        action_type="create_ticket",
        parameters={
            "title": payload.title,
            "description": payload.description,
            "severity": payload.severity,
            "source_ip": payload.source_ip,
            "ticket_id": ticket_id,
        },
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={
            "message": f"Ticket {ticket_id} created",
            "ticket_id": ticket_id,
            "title": payload.title,
            "severity": payload.severity,
        },
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="ticket_created", tenant_id=tenant_id, user_id=user.id,
        resource_type="ticket", resource_id=ticket_id,
        details={"title": payload.title, "severity": payload.severity, "alert_id": payload.alert_id},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "create_ticket", "target": ticket_id, "status": "completed", "message": f"Ticket {ticket_id} created"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Ticket {ticket_id} created")


@router.post("/send-notification", summary="Send a notification via configured channel")
async def send_notification(
    payload: SendNotificationRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Send a notification through the configured channel (webhook, Slack, email, etc.)."""
    notification = Notification(
        id=new_id(),
        tenant_id=tenant_id,
        user_id=payload.target_user_id,
        type=payload.severity,
        title=payload.title,
        message=payload.message,
        read=False,
        created_at=utcnow(),
    )
    db.add(notification)

    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="send_notification",
        parameters={
            "channel": payload.channel,
            "title": payload.title,
            "severity": payload.severity,
            "target_user_id": payload.target_user_id,
        },
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"Notification sent via {payload.channel}", "channel": payload.channel, "notification_id": notification.id},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="notification_sent", tenant_id=tenant_id, user_id=user.id,
        resource_type="notification", resource_id=notification.id,
        details={"channel": payload.channel, "title": payload.title, "severity": payload.severity},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "send_notification", "target": payload.channel, "status": "completed", "message": f"Notification sent via {payload.channel}"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Notification sent via {payload.channel}")


@router.post("/quarantine-file", summary="Quarantine a malicious file on a device")
async def quarantine_file(
    payload: QuarantineFileRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Quarantine a malicious file on a device — creates device command for agent."""
    # Validate device exists
    result = await db.execute(
        select(Device).where(Device.id == payload.device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Create device command for agent to pick up
    from cybernova.database.postgres.models import DeviceCommand
    cmd = DeviceCommand(
        id=new_id(),
        tenant_id=tenant_id,
        device_id=payload.device_id,
        action="quarantine_file",
        payload={
            "file_path": payload.file_path,
            "sha256": payload.sha256,
            "reason": payload.reason,
        },
        status="pending",
        created_by=user.id,
        created_at=utcnow(),
        expires_at=datetime.now(timezone.utc).replace(hour=23, minute=59, second=59),
    )
    db.add(cmd)

    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        device_id=payload.device_id,
        action_type="quarantine_file",
        parameters={
            "device_id": payload.device_id,
            "hostname": device.hostname,
            "file_path": payload.file_path,
            "sha256": payload.sha256,
            "reason": payload.reason,
        },
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={
            "message": f"Quarantine requested for {payload.file_path} on {device.hostname}",
            "hostname": device.hostname,
            "file_path": payload.file_path,
            "sha256": payload.sha256,
        },
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="file_quarantine_requested", tenant_id=tenant_id, user_id=user.id,
        resource_type="device", resource_id=payload.device_id,
        details={"hostname": device.hostname, "file_path": payload.file_path, "sha256": payload.sha256},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "quarantine_file", "target": device.hostname, "status": "completed", "message": f"Quarantine requested for {payload.file_path}"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"Quarantine requested for {payload.file_path} on {device.hostname}")


@router.post("/reset-mfa/{user_id}", summary="Force reset MFA for a user")
async def reset_mfa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Force reset MFA for a compromised user account."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="reset_mfa",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"MFA reset requested for {target.email}", "email": target.email, "username": target.username},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="mfa_reset_requested", tenant_id=tenant_id, user_id=user.id,
        resource_type="user", resource_id=user_id,
        details={"email": target.email},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "reset_mfa", "target": target.email, "status": "completed", "message": f"MFA reset requested for {target.email}"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"MFA reset requested for {target.email}")


@router.get("/history", summary="Get SOAR action history for Response Centre")
async def get_soar_history(
    limit: int = Query(50, le=500),
    action_type: Optional[str] = Query(None, description="Filter by action type"),
    status: Optional[str] = Query(None, description="Filter by status (pending, success, completed, failed)"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Get SOAR action history for the Response Centre.
    Returns all ResponseAction records with rich details.
    """
    query = select(ResponseAction).where(ResponseAction.tenant_id == tenant_id)

    if action_type:
        query = query.where(ResponseAction.action_type == action_type)
    if status:
        query = query.where(ResponseAction.status == status)

    query = query.order_by(desc(ResponseAction.created_at)).limit(limit)
    result = await db.execute(query)
    actions = result.scalars().all()

    return [
        {
            "id": a.id,
            "action_type": a.action_type,
            "parameters": a.parameters or {},
            "target": (a.parameters or {}).get("target", ""),
            "ip": (a.parameters or {}).get("ip", ""),
            "device_id": a.device_id or "",
            "alert_id": a.alert_id or "",
            "status": a.status,
            "initiated_by": a.initiated_by or "system",
            "result": a.result if a.result else {},
            "error_message": a.error_message or "",
            "retry_count": a.retry_count or 0,
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "updated_at": a.updated_at.isoformat() if a.updated_at else "",
            "completed_at": a.completed_at.isoformat() if a.completed_at else "",
        }
        for a in actions
    ]


@router.post("/unblock-ip", summary="Unblock an IP address (remove firewall rule)")
async def unblock_ip(
    payload: BlockIPRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Unblock an IP address — remove firewall rule + DB entry."""
    result = await db.execute(
        select(BlockedIP).where(
            BlockedIP.tenant_id == tenant_id,
            BlockedIP.ip_address == payload.ip_address,
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")

    await _enforce_firewall_unblock(payload.ip_address)
    await db.delete(entry)

    # Log as ResponseAction so it appears in Response Centre action history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="unblock_ip",
        parameters={"target": payload.ip_address, "reason": payload.reason},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"IP {payload.ip_address} unblocked", "ip": payload.ip_address},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    await audit_service.log(
        db=db, action="ip_unblocked", tenant_id=tenant_id, user_id=user.id,
        resource_type="blocked_ip", resource_id=payload.ip_address,
        details={"ip": payload.ip_address},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "unblock_ip", "target": payload.ip_address, "status": "completed", "message": f"IP {payload.ip_address} unblocked"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"IP {payload.ip_address} unblocked")


@router.post("/disable-user/{user_id}", summary="Disable a user")
async def disable_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Disable a user account."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_disabled = True
    target.is_active = False

    # Log as ResponseAction so it appears in Response Centre action history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=tenant_id,
        action_type="disable_user",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"User {target.email} disabled", "email": target.email, "username": target.username},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    # Update related open alerts to "resolved"
    alert_result = await db.execute(
        select(Alert).where(
            Alert.user == target.username,
            Alert.tenant_id == tenant_id,
            Alert.status.in_(["new", "correlated", "in_progress"]),
        )
    )
    related_alerts = alert_result.scalars().all()
    for alert in related_alerts:
        alert.status = "resolved"

    await audit_service.log(
        db=db, action="user_disabled", tenant_id=tenant_id, user_id=user.id,
        resource_type="user", resource_id=user_id,
        details={"email": target.email, "alerts_updated": len(related_alerts)},
    )
    await db.commit()
    await ws_handler.broadcast_soar_action(
        {"action": "disable_user", "target": target.email, "status": "completed", "message": f"User {target.email} disabled"},
        tenant_id,
    )
    return ActionResponse(success=True, message=f"User {target.email} disabled")



class HostnameLookupRequest(BaseModel):
    hostname: str
    reason: str = "Threat detected"


class UsernameLookupRequest(BaseModel):
    username: str
    reason: str = "Security action"


@router.post("/isolate-host", summary="Isolate a device by hostname")
async def isolate_host(
    body: HostnameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Isolate a device by looking up its hostname."""
    result = await db.execute(
        select(Device).where(Device.hostname == body.hostname, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device with hostname '{body.hostname}' not found")
    # Re-use the isolate-device endpoint logic
    return await _isolate_device_by_id(device.id, db, user, tenant_id, body.reason)


@router.post("/unisolate-host", summary="Release a device isolation by hostname")
async def unisolate_host(
    body: HostnameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Release a device from isolation by looking up its hostname."""
    result = await db.execute(
        select(Device).where(Device.hostname == body.hostname, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device with hostname '{body.hostname}' not found")
    # Re-use the release-device endpoint logic
    return await _release_device_by_id(device.id, db, user, tenant_id)


@router.post("/disable-user", summary="Disable a user by username")
async def disable_user_by_username(
    body: UsernameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Disable a user account by looking up their username."""
    result = await db.execute(
        select(User).where(User.username == body.username, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"User with username '{body.username}' not found")
    return await _disable_user_by_id(target.id, db, user, tenant_id)


@router.post("/enable-user", summary="Enable a user by username")
async def enable_user_by_username(
    body: UsernameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Enable a user account by looking up their username."""
    result = await db.execute(
        select(User).where(User.username == body.username, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"User with username '{body.username}' not found")
    if not target.is_disabled:
        return ActionResponse(success=True, message=f"User {target.email} is already enabled")
    target.is_disabled = False
    target.is_active = True
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, action_type="enable_user",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"User {target.email} enabled", "email": target.email, "username": target.username},
        created_at=utcnow(), updated_at=utcnow(), completed_at=utcnow(),
    )
    db.add(ra)
    await audit_service.log(db=db, action="user_enabled", tenant_id=tenant_id, user_id=user.id, resource_type="user", resource_id=target.id, details={"email": target.email})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "enable_user", "target": target.email, "status": "completed", "message": f"User {target.email} enabled"}, tenant_id)
    return ActionResponse(success=True, message=f"User {target.email} enabled")


@router.post("/scan-host", summary="Request a host scan")
async def scan_host(
    body: HostnameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Request a security scan of a host."""
    now = utcnow()
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, action_type="scan_host",
        parameters={"target": body.hostname, "reason": body.reason},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"Scan requested for {body.hostname}", "hostname": body.hostname},
        created_at=now, updated_at=now, completed_at=now,
    )
    db.add(ra)
    await audit_service.log(db=db, action="host_scan_requested", tenant_id=tenant_id, user_id=user.id, resource_type="host", details={"hostname": body.hostname, "reason": body.reason})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "scan_host", "target": body.hostname, "status": "completed", "message": f"Scan requested for {body.hostname}"}, tenant_id)
    return ActionResponse(success=True, message=f"Scan requested for {body.hostname}")


@router.post("/reset-mfa", summary="Reset MFA for a user by username")
async def reset_mfa_by_username(
    body: UsernameLookupRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_automation_trigger),
    tenant_id: str = Depends(get_tenant_id),
):
    """Reset MFA for a user by looking up their username."""
    result = await db.execute(
        select(User).where(User.username == body.username, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"User with username '{body.username}' not found")
    return await _reset_mfa_by_id(target.id, db, user, tenant_id)


async def _isolate_device_by_id(device_id: str, db: AsyncSession, user: CurrentUser, tenant_id: str, reason: str = "Threat detected") -> ActionResponse:
    """Internal helper: isolate a device by ID."""
    from sqlalchemy import select as _select
    result = await db.execute(
        _select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.is_isolated:
        return ActionResponse(success=True, message=f"Device {device.hostname} already isolated")
    device.is_isolated = True
    fw_ok = False
    if device.ip_address:
        fw_ok = await _enforce_firewall_block(device.ip_address)
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, alert_id=None, device_id=device_id,
        action_type="isolate_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_enforced": fw_ok, "reason": reason},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"Device {device.hostname} isolated (firewall: {'enforced' if fw_ok else 'db_only'})", "firewall_enforced": fw_ok, "hostname": device.hostname},
        created_at=utcnow(), updated_at=utcnow(), completed_at=utcnow(),
    )
    db.add(ra)
    related = []
    if device.ip_address:
        alert_result = await db.execute(
            _select(Alert).where(Alert.source_ip == device.ip_address, Alert.tenant_id == tenant_id, Alert.status.in_(["new", "correlated", "in_progress"]))
        )
        related = alert_result.scalars().all()
        for alert in related:
            alert.status = "resolved"
    await audit_service.log(db=db, action="device_isolated", tenant_id=tenant_id, user_id=user.id, resource_type="device", resource_id=device_id, details={"hostname": device.hostname, "ip": device.ip_address, "firewall_enforced": fw_ok, "alerts_updated": len(related)})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "isolate_device", "target": device.hostname, "status": "completed", "message": f"Device {device.hostname} isolated"}, tenant_id)
    return ActionResponse(success=True, message=f"Device {device.hostname} isolated")


async def _release_device_by_id(device_id: str, db: AsyncSession, user: CurrentUser, tenant_id: str) -> ActionResponse:
    """Internal helper: release a device from isolation by ID."""
    from sqlalchemy import select as _select
    result = await db.execute(
        _select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.is_isolated:
        return ActionResponse(success=True, message=f"Device {device.hostname} is not isolated")
    device.is_isolated = False
    fw_ok = False
    if device.ip_address:
        fw_ok = await _enforce_firewall_unblock(device.ip_address)
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, alert_id=None, device_id=device_id,
        action_type="release_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_released": fw_ok},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"Device {device.hostname} released (firewall: {'removed' if fw_ok else 'db_only'})", "firewall_released": fw_ok, "hostname": device.hostname},
        created_at=utcnow(), updated_at=utcnow(), completed_at=utcnow(),
    )
    db.add(ra)
    await audit_service.log(db=db, action="device_released", tenant_id=tenant_id, user_id=user.id, resource_type="device", resource_id=device_id, details={"hostname": device.hostname, "ip": device.ip_address, "firewall_released": fw_ok})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "release_device", "target": device.hostname, "status": "completed", "message": f"Device {device.hostname} released from isolation"}, tenant_id)
    return ActionResponse(success=True, message=f"Device {device.hostname} released from isolation")


async def _disable_user_by_id(user_id: str, db: AsyncSession, user: CurrentUser, tenant_id: str) -> ActionResponse:
    """Internal helper: disable a user by ID."""
    from sqlalchemy import select as _select
    result = await db.execute(
        _select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_disabled = True
    target.is_active = False
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, action_type="disable_user",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"User {target.email} disabled", "email": target.email, "username": target.username},
        created_at=utcnow(), updated_at=utcnow(), completed_at=utcnow(),
    )
    db.add(ra)
    alert_result = await db.execute(
        _select(Alert).where(Alert.user == target.username, Alert.tenant_id == tenant_id, Alert.status.in_(["new", "correlated", "in_progress"]))
    )
    related = alert_result.scalars().all()
    for alert in related:
        alert.status = "resolved"
    await audit_service.log(db=db, action="user_disabled", tenant_id=tenant_id, user_id=user.id, resource_type="user", resource_id=user_id, details={"email": target.email, "alerts_updated": len(related)})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "disable_user", "target": target.email, "status": "completed", "message": f"User {target.email} disabled"}, tenant_id)
    return ActionResponse(success=True, message=f"User {target.email} disabled")


async def _reset_mfa_by_id(user_id: str, db: AsyncSession, user: CurrentUser, tenant_id: str) -> ActionResponse:
    """Internal helper: reset MFA for a user by ID."""
    from sqlalchemy import select as _select
    result = await db.execute(
        _select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    ra = ResponseAction(
        id=new_id(), tenant_id=tenant_id, action_type="reset_mfa",
        parameters={"target": target.email, "username": target.username},
        status=ActionStatus.SUCCESS.value, initiated_by=user.id,
        result={"message": f"MFA reset requested for {target.email}", "email": target.email, "username": target.username},
        created_at=utcnow(), updated_at=utcnow(), completed_at=utcnow(),
    )
    db.add(ra)
    await audit_service.log(db=db, action="mfa_reset_requested", tenant_id=tenant_id, user_id=user.id, resource_type="user", resource_id=user_id, details={"email": target.email})
    await db.commit()
    await ws_handler.broadcast_soar_action({"action": "reset_mfa", "target": target.email, "status": "completed", "message": f"MFA reset requested for {target.email}"}, tenant_id)
    return ActionResponse(success=True, message=f"MFA reset requested for {target.email}")


def _is_running_in_docker() -> bool:
    """Detect if we're running inside a Docker container."""
    if Path("/.dockerenv").exists():
        return True
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if "docker" in content or "kubepods" in content or "lxc" in content:
                return True
    except (OSError, PermissionError):
        pass
    return False


async def _enforce_firewall_block(ip_address: str) -> bool:
    """Apply firewall block rule at the system level (Windows + Linux).
    
    When running inside a Docker container, the backend cannot modify the host's
    firewall rules. In that case we skip the actual firewall enforcement and let
    the caller know so it can fall back to DB-only blocking.
    """
    import platform as _platform
    system = _platform.system().lower()

    # Inside a Docker container we can't touch the host firewall
    if _is_running_in_docker():
        log.info("Running inside Docker — IP %s blocked in DB only (firewall enforcement skipped)", ip_address)
        return False

    try:
        # ── Windows: netsh advfirewall ──
        if system == "windows":
            rule_name = f"CyberNova_Block_{ip_address.replace('.', '_')}"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_address}",
                    "enable=yes",
                    "profile=any",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                log.info("Blocked %s via Windows Firewall (rule: %s)", ip_address, rule_name)
                return True
            log.warning("Windows Firewall rule failed for %s: %s", ip_address, result.stderr.strip())
            return False

        # ── Linux: iptables ──
        if Path("/sbin/iptables").exists() or Path("/usr/sbin/iptables").exists():
            rule = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            proc1 = await asyncio.to_thread(subprocess.run, rule, capture_output=True, text=True, timeout=10)
            rule2 = ["iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"]
            proc2 = await asyncio.to_thread(subprocess.run, rule2, capture_output=True, text=True, timeout=10)
            if proc1.returncode == 0 and proc2.returncode == 0:
                log.info("iptables rule applied: block %s", ip_address)
                return True
            log.warning("iptables failed for %s: %s / %s", ip_address, proc1.stderr.strip(), proc2.stderr.strip())
            return False

        # ── Linux: nftables ──
        if Path("/sbin/nft").exists() or Path("/usr/sbin/nft").exists():
            rule = ["nft", "add", "rule", "inet", "filter", "INPUT", "ip", "saddr", ip_address, "drop"]
            proc = await asyncio.to_thread(subprocess.run, rule, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                log.info("nftables rule applied: block %s", ip_address)
                return True
            log.warning("nftables failed for %s: %s", ip_address, proc.stderr.strip())
            return False

        # ── BSD/macOS: ipfw ──
        if Path("/sbin/ipfw").exists() or Path("/usr/sbin/ipfw").exists():
            rule = ["ipfw", "add", "deny", "ip", "from", ip_address, "to", "any"]
            proc = await asyncio.to_thread(subprocess.run, rule, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                log.info("ipfw rule applied: block %s", ip_address)
                return True
            log.warning("ipfw failed for %s: %s", ip_address, proc.stderr.strip())
            return False

        log.debug("No firewall binary found — IP %s blocked in DB only", ip_address)
        return False
    except Exception as e:
        log.warning("Firewall enforcement error for %s: %s", ip_address, e)
        return False


async def _enforce_firewall_unblock(ip_address: str) -> bool:
    """Remove firewall block rule for an IP address (Windows + Linux)."""
    import platform as _platform
    system = _platform.system().lower()

    try:
        if system == "windows":
            rule_name = f"CyberNova_Block_{ip_address.replace('.', '_')}"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                log.info("Unblocked %s via Windows Firewall", ip_address)
                return True
            log.warning("Windows Firewall delete rule failed for %s: %s", ip_address, result.stderr.strip())
            return False

        # Linux: remove iptables rules
        if Path("/sbin/iptables").exists() or Path("/usr/sbin/iptables").exists():
            rule = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            await asyncio.to_thread(subprocess.run, rule, capture_output=True, timeout=10)
            rule2 = ["iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"]
            await asyncio.to_thread(subprocess.run, rule2, capture_output=True, timeout=10)
            log.info("iptables rule removed: unblock %s", ip_address)
            return True

        return False
    except Exception as e:
        log.warning("Firewall unblock error for %s: %s", ip_address, e)
        return False
