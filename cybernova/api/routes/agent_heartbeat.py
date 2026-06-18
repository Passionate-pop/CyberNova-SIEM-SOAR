from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Device
from cybernova.database.postgres.session import get_db
from cybernova.api.routes.agent_auth import get_current_agent, CurrentAgent

log = logging.getLogger("cybernova.agent_heartbeat")
router = APIRouter(prefix="/api/v1/agent", tags=["Agent Heartbeat"])


@router.post("/heartbeat", summary="Send agent heartbeat")
async def agent_heartbeat(
    agent: CurrentAgent = Depends(get_current_agent),
    x_forwarded_for: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Update Device.last_heartbeat and Device.ip_address for the calling agent.

    The ip_address is taken from X-Forwarded-For (if behind proxy) or the
    connecting IP stored in CurrentAgent.ip_address (set at registration time).
    """
    stmt = select(Device).where(Device.id == agent.device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()
    if not device:
        return {"ok": False, "error": "Device not found"}

    now = datetime.now(timezone.utc)

    source_ip = (x_forwarded_for or "").split(",")[0].strip() or agent.ip_address
    changed = []

    device.last_heartbeat = now
    changed.append("last_heartbeat")

    if source_ip and source_ip != device.ip_address:
        device.ip_address = source_ip
        changed.append("ip_address")

    device.status = "online"
    changed.append("status")

    await db.commit()

    log.debug("heartbeat: agent=%s ip=%s fields=%s", agent.device_id, source_ip, changed)

    return {
        "ok": True,
        "agent_id": agent.device_id,
        "timestamp": now.isoformat(),
        "updated_fields": changed,
    }
