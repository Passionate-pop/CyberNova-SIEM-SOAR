from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Device, OrganizationKey, Tenant
from cybernova.database.postgres.session import get_db

log = logging.getLogger("cybernova.agent_auth")
router = APIRouter(prefix="/api/v1/agent", tags=["Agent Auth"])


# ── Schemas ──


class AgentRegisterRequest(BaseModel):
    org_key: str = Field(..., description="Organization key for tenant association")
    hostname: str = Field(..., description="Agent hostname")
    os_type: Optional[str] = Field(None, description="Operating system type (linux, windows)")
    os_version: Optional[str] = Field(None, description="OS version string")
    agent_version: Optional[str] = Field(None, description="Agent software version")
    ip_address: Optional[str] = Field(None, description="Agent IP address")
    mac_address: Optional[str] = Field(None, description="Agent MAC address")
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


class AgentRegisterResponse(BaseModel):
    agent_id: str
    device_token: str
    tenant_id: str
    message: str


class AgentInfoResponse(BaseModel):
    agent_id: str
    hostname: str
    tenant_id: str
    status: str
    is_isolated: bool
    is_active: bool
    last_heartbeat: Optional[str]
    agent_version: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    ip_address: str
    tags: List[str]


class AgentTokenRefreshResponse(BaseModel):
    device_token: str
    message: str


# ── Auth Dependency ──


class CurrentAgent:
    """Holds authenticated agent context. Injected by get_current_agent dependency."""

    def __init__(self, device: Device):
        self.device_id: str = device.id
        self.tenant_id: str = device.tenant_id
        self.hostname: str = device.hostname
        self.status: str = device.status
        self.is_isolated: bool = device.is_isolated
        self.is_active: bool = device.is_active
        self.os_type: Optional[str] = device.os_type
        self.os_version: Optional[str] = device.os_version
        self.agent_version: Optional[str] = device.agent_version
        self.ip_address: str = device.ip_address
        self.tags: List[str] = device.tags or []

    def __str__(self) -> str:
        return f"Agent({self.device_id}, {self.hostname}, tenant={self.tenant_id})"


async def get_current_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> CurrentAgent:
    """Authenticate agent via Bearer device_token.

    Usage:
        @router.get("/some-resource")
        async def handler(agent: CurrentAgent = Depends(get_current_agent)):
            ...
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Use: Authorization: Bearer <device_token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    device_token = auth.removeprefix("Bearer ")
    token_hash = hashlib.sha256(device_token.encode()).hexdigest()

    stmt = select(Device).where(
        Device.device_token_hash == token_hash,
        Device.is_active,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is disabled",
        )

    return CurrentAgent(device)


# ── Routes ──


@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    summary="Register a new agent and receive device token",
)
async def register_agent(
    payload: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    org_key_hash = hashlib.sha256(payload.org_key.encode()).hexdigest()

    stmt = select(OrganizationKey).where(
        OrganizationKey.key_hash == org_key_hash,
        OrganizationKey.is_active,
    )
    result = await db.execute(stmt)
    org_key_obj = result.scalar_one_or_none()
    if not org_key_obj:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid organization key",
        )

    stmt = select(Tenant).where(Tenant.id == org_key_obj.tenant_id, Tenant.is_active)
    result = await db.execute(stmt)
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant not found or inactive",
        )

    device_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(device_token.encode()).hexdigest()

    device = Device(
        tenant_id=tenant.id,
        hostname=payload.hostname,
        ip_address=payload.ip_address or "",
        mac_address=payload.mac_address or "",
        os_type=payload.os_type or "",
        os_version=payload.os_version or "",
        agent_version=payload.agent_version or "",
        device_token_hash=token_hash,
        tags=payload.tags or {},
        status="active",
        is_active=True,
    )
    db.add(device)
    await db.commit()
    await db.refresh(device)

    log.info("agent registered: id=%s hostname=%s tenant=%s", device.id, device.hostname, tenant.id)

    return AgentRegisterResponse(
        agent_id=device.id,
        device_token=device_token,
        tenant_id=tenant.id,
        message="Agent registered. Save this device_token — it will not be shown again.",
    )


@router.get(
    "/me",
    response_model=AgentInfoResponse,
    summary="Get info about the currently authenticated agent",
)
async def agent_info(
    agent: CurrentAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Device).where(Device.id == agent.device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    last_hb = device.last_heartbeat.isoformat() if device and device.last_heartbeat else None

    return AgentInfoResponse(
        agent_id=agent.device_id,
        hostname=agent.hostname,
        tenant_id=agent.tenant_id,
        status=agent.status,
        is_isolated=agent.is_isolated,
        is_active=agent.is_active,
        last_heartbeat=last_hb,
        agent_version=agent.agent_version,
        os_type=agent.os_type,
        os_version=agent.os_version,
        ip_address=agent.ip_address,
        tags=agent.tags,
    )


@router.post(
    "/token/refresh",
    response_model=AgentTokenRefreshResponse,
    summary="Refresh device token (old token remains valid until explicitly revoked)",
)
async def refresh_device_token(
    agent: CurrentAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Device).where(Device.id == agent.device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    new_token = secrets.token_urlsafe(32)
    new_hash = hashlib.sha256(new_token.encode()).hexdigest()
    device.device_token_hash = new_hash
    await db.commit()

    log.info("agent token refreshed: id=%s", device.id)

    return AgentTokenRefreshResponse(
        device_token=new_token,
        message="Token refreshed. Save this device_token — it will not be shown again.",
    )
