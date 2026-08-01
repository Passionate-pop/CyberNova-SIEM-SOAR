from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_agent_view, require_agent_manage
from cybernova.core.utils.helpers import new_id
from cybernova.ingestion.agent.schemas import (
    TelemetryBatch, AgentConfiguration,
)
from cybernova.ingestion.agent.manager import agent_manager

log = logging.getLogger("cybernova.agent.router")
router = APIRouter(prefix="/api/v1/agent", tags=["Agent Telemetry"])


@router.post("/telemetry", summary="Agent batch telemetry ingest")
async def agent_telemetry(
    batch: TelemetryBatch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None),
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_agent_view),
):
    hostname = batch.system.hostname if batch.system else "unknown"
    ip = request.client.host if request.client else "unknown"

    result = await db.execute(
        select(Device).where(
            Device.tenant_id == tenant_id,
            Device.hostname == hostname,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        device = Device(
            id=new_id(),
            tenant_id=tenant_id,
            hostname=hostname,
            ip_address=ip,
            os_type=batch.system.os_type if batch.system else "unknown",
            os_version=batch.system.os_version if batch.system else "",
            status="active",
            is_active=True,
        )
        db.add(device)
        await db.flush()
        log.info("Agent auto-registered: hostname=%s tenant=%s", hostname, tenant_id)

    config = await agent_manager.process_telemetry(device.id, tenant_id, batch)
    device.last_heartbeat = datetime.now(timezone.utc)
    await db.commit()

    total_events = (
        len(batch.processes) + len(batch.connections) +
        len(batch.file_events) + len(batch.security_events)
    )

    # Pipe ALL telemetry through the detection pipeline — not just security_events
    for se in batch.security_events:
        await unified_pipeline.ingest(
            raw_data={
                **se.model_dump(exclude_none=True),
                "device_id": device.id,
                "hostname": hostname,
                "ip_address": ip,
            },
            tenant_id=tenant_id,
            source="agent",
            source_type=se.event_type,
        )
    for proc in batch.processes:
        await unified_pipeline.ingest(
            raw_data={
                "event_type": "process_telemetry",
                "severity": "info",
                "device_id": device.id,
                "hostname": hostname,
                "ip_address": ip,
                **proc.model_dump(exclude_none=True),
            },
            tenant_id=tenant_id,
            source="agent",
            source_type="process_telemetry",
        )
    for conn in batch.connections:
        await unified_pipeline.ingest(
            raw_data={
                "event_type": "network_telemetry",
                "severity": "info",
                "device_id": device.id,
                "hostname": hostname,
                "ip_address": ip,
                **conn.model_dump(exclude_none=True),
            },
            tenant_id=tenant_id,
            source="agent",
            source_type="network_telemetry",
        )
    for fe in batch.file_events:
        await unified_pipeline.ingest(
            raw_data={
                "event_type": "file_telemetry",
                "severity": "info",
                "device_id": device.id,
                "hostname": hostname,
                "ip_address": ip,
                **fe.model_dump(exclude_none=True),
            },
            tenant_id=tenant_id,
            source="agent",
            source_type="file_telemetry",
        )

    return {
        "accepted": True,
        "device_id": device.id,
        "events_ingested": total_events,
        "config": config.model_dump(exclude_none=True),
        "config_version": config.config_version,
    }


@router.get("/config", summary="Get agent configuration")
async def get_agent_config(
    device_id: str,
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_agent_view),
):
    agent = await agent_manager.get_agent(tenant_id, device_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent.config.model_dump(exclude_none=True)


@router.put("/config", summary="Push configuration to agent")
async def push_agent_config(
    device_id: str,
    config: AgentConfiguration,
    user: CurrentUser = Depends(require_agent_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    success = await agent_manager.update_config(tenant_id, device_id, config)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    log.info("Config pushed to agent %s by %s", device_id, user.username)
    return {"accepted": True, "config_version": config.config_version}


@router.get("/status", summary="Get agent status overview")
async def agent_status(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_agent_view),
):
    agents = await agent_manager.get_agents_by_tenant(tenant_id)
    return {
        "total": len(agents),
        "healthy": sum(1 for a in agents if a.is_healthy),
        "unhealthy": sum(1 for a in agents if not a.is_healthy),
        "agents": [a.to_dict() for a in agents],
    }


@router.get("/health", summary="Get agent manager health metrics")
async def agent_health(
    user: CurrentUser = Depends(get_current_user),
):
    return await agent_manager.get_metrics()


@router.get("/status/all", summary="Get status for all agents (admin)")
async def all_agents_status(
    user: CurrentUser = Depends(get_current_user),
):
    if "admin" not in (user.roles or []):
        raise HTTPException(status_code=403, detail="Admin access required")
    return await agent_manager.get_metrics()
