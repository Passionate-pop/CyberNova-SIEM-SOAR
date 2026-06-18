"""
CyberNova — Device Router
POST /api/v1/devices/register
POST /api/v1/devices/heartbeat
POST /api/v1/devices/logs
POST /api/v1/devices/alerts
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, Request, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device, Tenant
from cybernova.database.repository.repositories import DeviceRepository
from cybernova.audit.service import audit_service
from cybernova.pipeline.device_processor import device_event_handler

log = logging.getLogger("cybernova.devices")

router = APIRouter(prefix="/api/v1/devices", tags=["Devices"])


def add_device_routes(app: Optional[object] = None) -> None:
    """Register device management routes with the FastAPI application.

    Call this from main.py to include the device router and ensure
    all device management endpoints are registered with proper ordering.

    Args:
        app: Optional FastAPI application instance. If provided, the router
             is included directly. If None, the module-level router can be
             included by the caller via app.include_router().
    """
    if app is not None:
        app.include_router(router, prefix="/api/v1/devices", tags=["Devices"])
        log.info("Device routes registered: /api/v1/devices/*")
    else:
        log.info("Device routes available via module-level router")


def _utcnow():
    return datetime.now(timezone.utc)


# ── Schemas ───────────────────────────────────────────────────────────────────

class DeviceRegisterRequest(BaseModel):
    org_key: str = Field(default="", description="Organization key for tenant association (org mode)")
    tenant_id: str = Field(default="", description="Tenant ID for individual mode")
    device_name: str = Field(..., description="Device hostname")
    system_info: dict = Field(default_factory=dict, description="System information")


class DeviceRegisterResponse(BaseModel):
    device_id: str
    device_token: str
    tenant_id: str
    message: str


class DeviceHeartbeatRequest(BaseModel):
    device_id: str
    status: str = Field(default="online")


class DeviceLogsRequest(BaseModel):
    device_id: str
    logs: List[dict]


class DeviceAlertsRequest(BaseModel):
    device_id: str
    alerts: List[dict]


class DeviceAuthResponse(BaseModel):
    device_id: str
    hostname: str
    tenant_id: str
    status: str


# ── Helpers ─────────────────────────────────────────────────────────────────

async def authenticate_device(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> Device:
    """Authenticate device via device_token header."""
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )

    device_token = auth_header.replace("Bearer ", "")
    token_hash = hashlib.sha256(device_token.encode()).hexdigest()

    device_repo = DeviceRepository(db)
    device = await device_repo.get_by_token_hash(token_hash)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device token"
        )

    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is disabled"
        )

    return device


async def validate_org_key(db: AsyncSession, org_key: str) -> Optional[Tenant]:
    """Validate org_key and return associated tenant."""
    org_key_hash = hashlib.sha256(org_key.encode()).hexdigest()

    from sqlalchemy import select
    from cybernova.database.postgres.models import OrganizationKey

    stmt = select(OrganizationKey).where(
        OrganizationKey.key_hash == org_key_hash,
        OrganizationKey.is_active
    )
    result = await db.execute(stmt)
    org_key_obj = result.scalar_one_or_none()

    if not org_key_obj:
        return None

    stmt = select(Tenant).where(Tenant.id == org_key_obj.tenant_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def validate_tenant_id(db: AsyncSession, tenant_id: str) -> Optional[Tenant]:
    """Validate tenant_id directly (individual mode)."""
    from sqlalchemy import select
    stmt = select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


# ── Routes ────────────────────────────────────────────────────────────────

@router.post("/register", summary="Register new device", response_model=DeviceRegisterResponse)
async def register_device(
    request: Request,
    payload: DeviceRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new device using org_key (org mode) or tenant_id (individual mode)."""

    tenant = None
    if payload.org_key:
        # Organization mode: validate via org_key
        tenant = await validate_org_key(db, payload.org_key)
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid organization key"
            )
    elif payload.tenant_id:
        # Individual mode: validate via tenant_id directly
        tenant = await validate_tenant_id(db, payload.tenant_id)
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid tenant ID"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either org_key or tenant_id is required"
        )

    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is not active"
        )

    device_id = secrets.token_urlsafe(16)
    device_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(device_token.encode()).hexdigest()

    system_info = payload.system_info or {}

    device = Device(
        id=device_id,
        tenant_id=tenant.id,
        hostname=payload.device_name,
        ip_address=system_info.get("ip", "0.0.0.0"),  # nosec - default value, overridden by actual device IP
        os_type=system_info.get("os", "unknown"),
        os_version=system_info.get("os_version", ""),
        agent_version=system_info.get("agent_version", "1.0.0"),
        status="active",
        device_token_hash=token_hash,
        last_heartbeat=_utcnow(),
    )

    db.add(device)
    await db.commit()
    await db.refresh(device)

    await audit_service.log(
        db=db,
        action="device_registered",
        tenant_id=tenant.id,
        resource_type="device",
        resource_id=device_id,
        details={"hostname": payload.device_name, "ip": system_info.get("ip")},
    )

    return DeviceRegisterResponse(
        device_id=device_id,
        device_token=device_token,
        tenant_id=tenant.id,
        message="Device registered successfully"
    )


@router.post("/heartbeat", summary="Device heartbeat")
async def heartbeat(
    request: Request,
    payload: DeviceHeartbeatRequest,
    db: AsyncSession = Depends(get_db),
    device: Device = Depends(authenticate_device)
):
    """Update device heartbeat and status."""

    device.last_heartbeat = _utcnow()
    device.status = payload.status
    device.is_active = True

    await db.commit()

    try:
        await device_event_handler.update_device_status(
            device.id, payload.status, device.tenant_id
        )
    except Exception as e:
        log.warning("Failed to broadcast status: %s", e)

    return {"status": "ok", "last_seen": device.last_heartbeat.isoformat()}


@router.post("/logs", summary="Submit device logs")
async def submit_logs(
    request: Request,
    payload: DeviceLogsRequest,
    db: AsyncSession = Depends(get_db),
    device: Device = Depends(authenticate_device)
):
    """Ingest logs from device."""

    device.last_heartbeat = _utcnow()
    await db.commit()

    try:
        await device_event_handler.submit_logs(
            device.id, device.tenant_id, payload.logs
        )
    except Exception as e:
        log.warning("Failed to process logs: %s", e)

    return {"status": "ok", "ingested": len(payload.logs)}


@router.post("/alerts", summary="Submit device alerts")
async def submit_alerts(
    request: Request,
    payload: DeviceAlertsRequest,
    db: AsyncSession = Depends(get_db),
    device: Device = Depends(authenticate_device)
):
    """Ingest alerts from device."""

    device.last_heartbeat = _utcnow()
    await db.commit()

    try:
        await device_event_handler.submit_alerts(
            device.id, device.tenant_id, payload.alerts
        )
    except Exception as e:
        log.warning("Failed to process alerts: %s", e)

    return {"status": "ok", "ingested": len(payload.alerts)}


@router.get("/me", summary="Get device info", response_model=DeviceAuthResponse)
async def get_device_info(
    device: Device = Depends(authenticate_device)
):
    """Get current device info."""

    return DeviceAuthResponse(
        device_id=device.id,
        hostname=device.hostname,
        tenant_id=device.tenant_id,
        status=device.status
    )


# ── Background Task ───────────────────────────────────────────────────────

async def update_offline_devices(db: AsyncSession):
    """Mark devices as offline if no heartbeat > 5 minutes."""

    cutoff = _utcnow() - timedelta(minutes=5)

    from sqlalchemy import update
    stmt = update(Device).where(
        Device.last_heartbeat < cutoff,
        Device.status == "active"
    ).values(status="offline")

    await db.execute(stmt)
    await db.commit()
