"""CyberNova — Device Commands  
API for sending commands to agents and handling execution.
"""
import logging
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device, DeviceCommand
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_devices_manage
from cybernova.audit.service import audit_service
from cybernova.database.repository.repositories import DeviceRepository

log = logging.getLogger("cybernova.devices.commands")

router = APIRouter(prefix="/api/v1/agent", tags=["Device Commands"])
agent_router = APIRouter(prefix="/api/v1/devices", tags=["Agent Commands"])

COMMAND_EXPIRY_MINUTES = 30


def _utcnow():
    return datetime.now(timezone.utc)


async def _authenticate_from_request(request: Request, db: AsyncSession) -> Device:
    """Authenticate device from request headers."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    
    token = auth_header.replace("Bearer ", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    device_repo = DeviceRepository(db)
    device = await device_repo.get_by_token_hash(token_hash)
    if not device:
        raise HTTPException(status_code=401, detail="Invalid device token")
    if not device.is_active:
        raise HTTPException(status_code=403, detail="Device is disabled")
    return device


# === Admin Commands ===

class CommandCreate(BaseModel):
    action: str = Field(..., pattern="^(isolate|unisolate|run_scan|update_blocklist|clear_blocklist)$")
    payload: dict = Field(default_factory=dict)


class CommandResponse(BaseModel):
    command_id: str
    action: str
    status: str
    created_at: str


@router.post("/{device_id}/command", response_model=CommandResponse, summary="Send command to device")
async def create_command(
    device_id: str,
    payload: CommandCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_devices_manage),
):
    """Admin creates a command for a device."""
    
    query = select(Device).where(
        Device.id == device_id,
        Device.tenant_id == user.tenant_id
    )
    result = await db.execute(query)
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    command = DeviceCommand(
        id=secrets.token_urlsafe(16),
        tenant_id=user.tenant_id,
        device_id=device_id,
        action=payload.action,
        payload=payload.payload,
        status="pending",
        created_by=user.id,
        expires_at=_utcnow() + timedelta(minutes=COMMAND_EXPIRY_MINUTES),
    )
    
    db.add(command)
    await db.commit()
    await db.refresh(command)
    
    from cybernova.api.websocket import connection_manager, WebSocketMessage, EventType
    try:
        msg = WebSocketMessage(
            event_type=EventType.SYSTEM_NOTIFICATION,
            data={
                "type": "new_command",
                "device_id": device_id,
                "action": payload.action,
            },
            tenant_id=user.tenant_id
        )
        await connection_manager.send_to_tenant(user.tenant_id, msg)
    except Exception as e:
        log.error("Failed to send command to device %s: %s", device_id, e)
        raise
    
    await audit_service.log(
        db=db,
        action="command_created",
        tenant_id=user.tenant_id,
        user_id=user.id,
        resource_type="device_command",
        resource_id=command.id,
        details={"device_id": device_id, "action": payload.action},
    )
    
    return CommandResponse(
        command_id=command.id,
        action=command.action,
        status=command.status,
        created_at=command.created_at.isoformat(),
    )


@router.get("/history", summary="Get command history")
async def get_command_history(
    device_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_devices_manage),
    limit: int = 50,
):
    """Get command history for tenant or device."""
    
    query = select(DeviceCommand).where(
        DeviceCommand.tenant_id == user.tenant_id
    )
    
    if device_id:
        query = query.where(DeviceCommand.device_id == device_id)
    
    query = query.order_by(DeviceCommand.created_at.desc()).limit(limit)
    result = await db.execute(query)
    commands = result.scalars().all()
    
    return [
        {
            "command_id": c.id,
            "device_id": c.device_id,
            "action": c.action,
            "status": c.status,
            "error": c.error,
            "created_at": c.created_at.isoformat(),
            "executed_at": c.executed_at.isoformat() if c.executed_at else None,
        }
        for c in commands
    ]


# === Agent Commands (uses device_token) - separate router for device auth ===

agent_router = APIRouter(prefix="/api/v1/devices", tags=["Agent Commands"])


class CommandAck(BaseModel):
    status: str = Field(..., pattern="^(completed|failed)$")
    error: Optional[str] = None
    result: Optional[dict] = None


@agent_router.get("/commands", summary="Agent: Get pending commands")
async def agent_get_commands(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent polls for pending commands."""
    device = await _authenticate_from_request(request, db)
    
    query = select(DeviceCommand).where(
        DeviceCommand.device_id == device.id,
        DeviceCommand.status == "pending",
    )
    result = await db.execute(query)
    commands = result.scalars().all()
    
    pending = []
    for cmd in commands:
        if cmd.expires_at and cmd.expires_at < _utcnow():
            cmd.status = "expired"
            pending.append({"command_id": cmd.id, "action": cmd.action, "status": "expired"})
        else:
            cmd.status = "sent"
            pending.append({
                "command_id": cmd.id,
                "action": cmd.action,
                "payload": cmd.payload or {},
            })
    
    await db.commit()
    return pending


@agent_router.post("/commands/{command_id}/ack", summary="Agent: Acknowledge command")
async def agent_ack_command(
    command_id: str,
    ack: CommandAck,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent acknowledges command execution."""
    device = await _authenticate_from_request(request, db)
    
    query = select(DeviceCommand).where(
        DeviceCommand.id == command_id,
        DeviceCommand.device_id == device.id,
    )
    result = await db.execute(query)
    command = result.scalar_one_or_none()
    
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    
    command.status = ack.status
    command.executed_at = _utcnow()
    
    if ack.status == "completed":
        if command.action == "isolate":
            device.status = "isolated"
        elif command.action == "unisolate":
            device.status = "active"
        device.last_heartbeat = _utcnow()
    
    if ack.error:
        command.error = ack.error
    
    await db.commit()
    
    from cybernova.audit.service import audit_service
    await audit_service.log(
        db=db,
        action=f"command_{ack.status}",
        tenant_id=device.tenant_id,
        user_id="system",
        resource_type="device_command",
        resource_id=command_id,
        details={"device_id": device.id, "action": command.action, "error": ack.error},
    )
    
    return {"status": "ok"}