"""
CyberNova — Agent Ingest Endpoint
POST /api/v1/ingest/event
Auth: X-API-Key header or Bearer token (device/user JWT)
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.database.postgres.models import Device, APIKey, Tenant
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.ingestion.agent")
router = APIRouter(prefix="/api/v1/ingest", tags=["Agent Ingest"])


class AgentEvent(BaseModel):
    source: str = "agent"
    hostname: Optional[str] = None
    log_type: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = "info"
    message: str
    timestamp: Optional[str] = None
    ip_address: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    os_type: Optional[str] = None


async def resolve_tenant_from_api_key(
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> str:
    """Resolve tenant_id from API key or Bearer token. Returns 'default' for demo."""
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        result = await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active)
        )
        key_obj = result.scalar_one_or_none()
        if key_obj:
            key_obj.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            return key_obj.tenant_id

    if authorization and authorization.startswith("Bearer "):
        from cybernova.security.encryption.jwt_handler import decode_access_token
        from jose import JWTError
        token = authorization.split(" ", 1)[1]
        try:
            payload = decode_access_token(token)
            if payload.get("tenant_id"):
                return payload["tenant_id"]
        except JWTError:
            pass

    result = await db.execute(select(Tenant).where(Tenant.is_active).limit(1))
    tenant = result.scalar_one_or_none()
    if tenant:
        return tenant.id

    return "default"


@router.post("/event", summary="Agent event ingestion")
async def ingest_agent_event(
    payload: AgentEvent,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(resolve_tenant_from_api_key),
):
    """
    Ingest events from CyberNova agents (Windows/Linux).
    Authenticates via X-API-Key header, Bearer token, or falls back to first active tenant.
    Auto-registers unknown devices by hostname.
    """
    ts = payload.timestamp or datetime.now(timezone.utc).isoformat()
    ip = payload.ip_address or payload.source_ip or (request.client.host if request.client else "unknown")
    hostname = payload.hostname or "unknown"
    log_type = payload.log_type or payload.event_type or "generic"

    result = await db.execute(
        select(Device).where(
            Device.tenant_id == tenant_id,
            Device.hostname == hostname,
        )
    )
    device = result.scalar_one_or_none()

    if not device and hostname != "unknown":
        device = Device(
            id=new_id(),
            tenant_id=tenant_id,
            hostname=hostname,
            ip_address=ip,
            os_type=payload.os_type or "unknown",
            status="active",
            is_active=True,
        )
        db.add(device)
        await db.flush()
        log.info("Device auto-registered: hostname=%s tenant=%s", hostname, tenant_id)

    event_data = {
        "source": payload.source,
        "hostname": hostname,
        "log_type": log_type,
        "message": payload.message,
        "timestamp": ts,
        "device_id": device.id if device else None,
        "ip_address": ip,
        "event_type": payload.event_type,
        "severity": payload.severity,
        "source_ip": payload.source_ip,
        "dest_ip": payload.dest_ip,
        "dest_port": payload.dest_port,
        "protocol": payload.protocol,
    }

    await unified_pipeline.ingest_batch(
        events=[event_data],
        tenant_id=tenant_id,
        source="agent",
        source_type=log_type,
    )

    if device:
        device.last_heartbeat = datetime.now(timezone.utc)
    await db.commit()

    return {"accepted": True, "device_id": device.id if device else None, "tenant_id": tenant_id}
