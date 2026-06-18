"""
CyberNova — Device Admin Router
Protected endpoints for managing devices (requires auth)
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device, Alert, ResponseAction
from cybernova.database.repository.repositories import DeviceRepository
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin, require_devices_manage
from cybernova.config.constants import ActionStatus
from cybernova.response.routes.soar_actions import _enforce_firewall_block, _enforce_firewall_unblock

log = logging.getLogger("cybernova.admin.devices")
router = APIRouter(prefix="/api/v1/admin/devices", tags=["Admin Devices"])


class DeviceResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    is_isolated: bool = False
    last_heartbeat: str
    tenant_id: str


class DeviceListResponse(BaseModel):
    devices: List[DeviceResponse]
    total: int


@router.get("", summary="List all devices")
async def list_devices(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """List all devices for the current tenant."""
    result = await db.execute(
        select(Device).where(Device.tenant_id == user.tenant_id).order_by(Device.hostname)
    )
    devices = result.scalars().all()
    return DeviceListResponse(
        devices=[
            DeviceResponse(
                id=d.id,
                hostname=d.hostname,
                ip_address=d.ip_address or "",
                os_type=d.os_type or "",
                status=d.status,
                is_isolated=d.is_isolated or False,
                last_heartbeat=d.last_heartbeat.isoformat() if d.last_heartbeat else "",
                tenant_id=d.tenant_id,
            )
            for d in devices
        ],
        total=len(devices),
    )


@router.get("/stats", summary="Get device statistics")
async def get_device_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """Get device statistics - admin only."""
    tenant_filter = Device.tenant_id == user.tenant_id

    total_result = await db.execute(select(func.count()).select_from(Device).where(tenant_filter))
    total = total_result.scalar()

    active_result = await db.execute(select(func.count()).select_from(Device).where(
        tenant_filter, Device.status == "active"
    ))
    active = active_result.scalar()

    offline_result = await db.execute(select(func.count()).select_from(Device).where(
        tenant_filter, Device.status == "offline"
    ))
    offline = offline_result.scalar()

    isolated_result = await db.execute(select(func.count()).select_from(Device).where(
        tenant_filter, Device.is_isolated.is_(True)
    ))
    isolated = isolated_result.scalar()

    return {
        "total": total,
        "active": active,
        "offline": offline,
        "isolated": isolated,
    }


@router.post("/{device_id}/isolate", summary="Isolate device")
async def isolate_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_devices_manage),
):
    """Isolate a device — mark is_isolated in DB, apply real firewall, log ResponseAction, update alerts."""
    device_repo = DeviceRepository(db, user.tenant_id)
    device = await device_repo.get_by_id(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if device.is_isolated:
        return {"status": "ok", "message": f"Device {device.hostname} already isolated"}

    device.is_isolated = True
    device.status = "isolated"

    # Apply real firewall block on the device's IP address
    fw_enforced = False
    if device.ip_address:
        fw_enforced = await _enforce_firewall_block(device.ip_address)
        if fw_enforced:
            log.info("Device %s (%s) isolated via firewall", device.hostname, device.ip_address)
        else:
            log.warning("Device %s isolated in DB only — no firewall binary found", device.hostname)

    # Log as ResponseAction for full SOAR tracking history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=user.tenant_id,
        alert_id=None,
        device_id=device_id,
        action_type="isolate_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_enforced": fw_enforced},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"Device {device.hostname} isolated (firewall: {'enforced' if fw_enforced else 'db_only'})", "firewall_enforced": fw_enforced, "hostname": device.hostname},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    # Resolve related open alerts for this device's IP
    related_alerts = []
    if device.ip_address:
        alert_result = await db.execute(
            select(Alert).where(
                Alert.source_ip == device.ip_address,
                Alert.tenant_id == user.tenant_id,
                Alert.status.in_(["new", "correlated", "in_progress"]),
            )
        )
        related_alerts = alert_result.scalars().all()
        for alert in related_alerts:
            alert.status = "resolved"

    # Audit log
    from cybernova.audit.service import audit_service
    await audit_service.log(
        db=db,
        action="device_isolated",
        tenant_id=user.tenant_id,
        user_id=user.id,
        resource_type="device",
        resource_id=device_id,
        details={
            "hostname": device.hostname,
            "ip": device.ip_address,
            "firewall_enforced": fw_enforced,
            "alerts_updated": len(related_alerts),
        },
    )

    await db.commit()

    # Broadcast via WebSocket
    try:
        from cybernova.api.websocket import ws_handler
        await ws_handler.broadcast_soar_action(
            {
                "action": "isolate_device",
                "target": device.hostname,
                "status": "completed",
                "message": f"Device {device.hostname} isolated",
            },
            user.tenant_id,
        )
    except Exception as e:
        log.warning("WS broadcast failed for isolate device: %s", e)

    return {"status": "ok", "message": f"Device {device.hostname} isolated"}


@router.post("/{device_id}/unisolate", summary="Unisolate device")
async def unisolate_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_devices_manage),
):
    """Unisolate a device — mark is_isolated=False, remove firewall block, log ResponseAction."""
    device_repo = DeviceRepository(db, user.tenant_id)
    device = await device_repo.get_by_id(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if not device.is_isolated:
        return {"status": "ok", "message": f"Device {device.hostname} is not isolated"}

    device.is_isolated = False
    device.status = "active"

    # Remove firewall block on the device's IP address
    fw_removed = False
    if device.ip_address:
        fw_removed = await _enforce_firewall_unblock(device.ip_address)
        if fw_removed:
            log.info("Device %s (%s) unblocked from firewall", device.hostname, device.ip_address)
        else:
            log.warning("Device %s unisolated in DB only — no firewall binary found", device.hostname)

    # Log as ResponseAction for full SOAR tracking history
    ra = ResponseAction(
        id=new_id(),
        tenant_id=user.tenant_id,
        alert_id=None,
        device_id=device_id,
        action_type="unisolate_device",
        parameters={"target": device.hostname, "ip": device.ip_address or "", "firewall_removed": fw_removed},
        status=ActionStatus.SUCCESS.value,
        initiated_by=user.id,
        result={"message": f"Device {device.hostname} unisolated (firewall: {'removed' if fw_removed else 'db_only'})", "firewall_removed": fw_removed, "hostname": device.hostname},
        created_at=utcnow(),
        updated_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(ra)

    from cybernova.audit.service import audit_service
    await audit_service.log(
        db=db,
        action="device_unisolated",
        tenant_id=user.tenant_id,
        user_id=user.id,
        resource_type="device",
        resource_id=device_id,
        details={"hostname": device.hostname, "ip": device.ip_address, "firewall_removed": fw_removed},
    )

    await db.commit()

    # Broadcast via WebSocket
    try:
        from cybernova.api.websocket import ws_handler
        await ws_handler.broadcast_soar_action(
            {
                "action": "unisolate_device",
                "target": device.hostname,
                "status": "completed",
                "message": f"Device {device.hostname} unisolated",
            },
            user.tenant_id,
        )
    except Exception as e:
        log.warning("WS broadcast failed for unisolate device: %s", e)

    return {"status": "ok", "message": f"Device {device.hostname} unisolated"}
