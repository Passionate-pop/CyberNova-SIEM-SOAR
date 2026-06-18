from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Device, DeviceCommand
from cybernova.database.postgres.session import get_db
from cybernova.api.routes.agent_auth import get_current_agent, CurrentAgent

log = logging.getLogger("cybernova.agent_commands")
router = APIRouter(prefix="/api/v1/agent", tags=["Agent Commands"])

COMMAND_EXPIRY_MINUTES = 30


# ── Schemas ──


class PendingCommand(BaseModel):
    command_id: str
    action: str
    payload: Dict[str, Any]
    expires_at: Optional[str] = None


class CommandResultRequest(BaseModel):
    status: str = Field(..., pattern="^(completed|failed)$")
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    duration_secs: Optional[float] = Field(None, description="Execution duration in seconds")


# ── Routes ──


@router.get(
    "/{device_id}/commands",
    summary="Agent: poll for pending commands",
)
async def poll_commands(
    device_id: str,
    agent: CurrentAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Return all pending (not yet sent) commands for this agent.

    Commands are atomically marked as 'sent' on read to prevent redelivery.
    Expired commands are marked as 'expired' and returned as such.
    """
    if agent.device_id != device_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    now = datetime.now(timezone.utc)

    stmt = select(DeviceCommand).where(
        DeviceCommand.device_id == device_id,
        DeviceCommand.status == "pending",
    )
    result = await db.execute(stmt)
    commands = result.scalars().all()

    pending: List[PendingCommand] = []
    for cmd in commands:
        if cmd.expires_at and cmd.expires_at < now:
            cmd.status = "expired"
            pending.append(
                PendingCommand(
                    command_id=cmd.id,
                    action=cmd.action,
                    payload=cmd.payload or {},
                    status="expired",
                )
            )
        else:
            cmd.status = "sent"
            pending.append(
                PendingCommand(
                    command_id=cmd.id,
                    action=cmd.action,
                    payload=cmd.payload or {},
                    expires_at=cmd.expires_at.isoformat() if cmd.expires_at else None,
                )
            )

    await db.commit()

    log.debug("poll_commands: agent=%s returned=%d", device_id, len(pending))
    return pending


@router.post(
    "/{device_id}/commands/{command_id}/result",
    summary="Agent: report command execution result",
)
async def report_command_result(
    device_id: str,
    command_id: str,
    body: CommandResultRequest,
    agent: CurrentAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Report the result of a command execution back to the server."""
    if agent.device_id != device_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    stmt = select(DeviceCommand).where(
        DeviceCommand.id == command_id,
        DeviceCommand.device_id == device_id,
    )
    result = await db.execute(stmt)
    command = result.scalar_one_or_none()

    if not command:
        raise HTTPException(status_code=404, detail="Command not found")

    command.status = body.status
    command.executed_at = datetime.now(timezone.utc)
    if body.error:
        command.error = body.error

    if body.status == "completed":
        if command.action == "isolate":
            stmt = select(Device).where(Device.id == device_id)
            device = (await db.execute(stmt)).scalar_one_or_none()
            if device:
                device.status = "isolated"
                device.is_isolated = True
        elif command.action == "unisolate":
            stmt = select(Device).where(Device.id == device_id)
            device = (await db.execute(stmt)).scalar_one_or_none()
            if device:
                device.status = "active"
                device.is_isolated = False

    await db.commit()

    log.info(
        "command_result: agent=%s command=%s action=%s status=%s",
        device_id, command_id, command.action, body.status,
    )

    return {"ok": True, "command_id": command_id, "status": body.status}
