"""
CyberNova — Agent Telemetry Endpoint
POST /api/v1/agent/telemetry

Accepts batch telemetry from the host agent (Windows/Linux PowerShell/Python),
auto-registers devices, updates heartbeats, and forwards telemetry to the pipeline.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device, Tenant
from cybernova.core.utils.helpers import new_id
from cybernova.pipeline.unified_pipeline import unified_pipeline

log = logging.getLogger("cybernova.agent.telemetry")
router = APIRouter(prefix="/api/v1/agent", tags=["Agent Telemetry"])


async def _resolve_tenant(
    authorization: str | None,
    db: AsyncSession,
) -> str:
    """Resolve tenant_id from Bearer token.

    Tries in order:
      1. Decode as user JWT (validates signature + expiry)
      2. Extract tenant_id from expired JWT claims (safe — only used for tenant resolution)
      3. Lookup as device token (SHA256 hash match)
      4. Fallback to first active tenant (legacy no-auth mode)
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        # Strategy 1: Standard JWT decode (validates signature + expiry)
        try:
            from cybernova.security.encryption.jwt_handler import decode_access_token
            from jose import JWTError
            payload = decode_access_token(token)
            tid = payload.get("tenant_id")
            if tid:
                return tid
        except JWTError:
            pass
        except Exception as exc:
            log.warning("JWT decode failed: %s", exc)

        # Strategy 2: JWT might be expired — extract tenant_id from claims anyway
        try:
            from jose import jwt as jose_jwt
            unverified = jose_jwt.get_unverified_claims(token)
            tid = unverified.get("tenant_id")
            if tid:
                log.info("Telemetry: using tenant_id %s from expired JWT claims", tid)
                return tid
        except Exception as exc:
            log.warning("Failed to extract claims from expired JWT: %s", exc)

        # Strategy 3: Try as a device token (hashed SHA256)
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            result = await db.execute(
                select(Device).where(
                    Device.device_token_hash == token_hash,
                    Device.is_active,
                ).limit(1)
            )
            device_match = result.scalar_one_or_none()
            if device_match:
                log.info("Telemetry: authenticated via device token for tenant %s", device_match.tenant_id)
                return device_match.tenant_id
        except Exception as exc:
            log.warning("Device token lookup failed: %s", exc)

    # Strategy 4: Fallback to first active tenant (legacy/no-auth mode)
    result = await db.execute(select(Tenant).where(Tenant.is_active).limit(1))
    tenant = result.scalar_one_or_none()
    if tenant:
        log.warning("Telemetry: no valid auth — falling back to tenant %s", tenant.id)
        return tenant.id

    raise HTTPException(status_code=401, detail="No valid authentication or active tenant found")


class SystemInfo(BaseModel):
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    ip_addresses: List[str] = []
    mac_addresses: List[str] = []
    kernel_version: str = ""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    agent_version: str = ""


class TelemetryPayload(BaseModel):
    system: Optional[SystemInfo] = None
    heartbeat_interval: int = 30
    sequence_number: int = 0
    timestamp: str = ""
    processes: Optional[List[Dict[str, Any]]] = None
    connections: Optional[List[Dict[str, Any]]] = None


@router.post("/telemetry", summary="Ingest agent batch telemetry")
async def ingest_agent_telemetry(
    payload: TelemetryPayload,
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    Accept batch telemetry from the CyberNova host agent.

    The agent sends system info, heartbeat, processes, and connections
    every few seconds. This endpoint:
      1. Resolves the tenant from the Bearer JWT or API key
      2. Auto-registers the device by hostname if it doesn't exist
      3. Updates device system info and last_heartbeat
      4. Forwards processes and connections as pipeline events
    """
    # 1. Resolve tenant
    tenant_id = await _resolve_tenant(authorization=authorization, db=db)

    # 1b. Validate tenant actually exists in the database.
    #     Stale device_tokens/JWTs from deleted tenants can cause ForeignKeyViolationError.
    tenant_exists = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active).limit(1)
    )
    if not tenant_exists.scalar_one_or_none():
        log.warning("Telemetry from deleted tenant %s — rejecting.", tenant_id)
        return {"ok": False, "error": "tenant_not_found", "device_registered": False}

    # 2. Extract system info
    sysinfo = payload.system
    hostname = (sysinfo.hostname or "unknown").strip()
    if hostname == "unknown":
        log.warning("Telemetry from unknown hostname — skipping device registration")
        return {"ok": True, "device_registered": False, "tenant_id": tenant_id}

    ip_address = ""
    if sysinfo and sysinfo.ip_addresses:
        ip_address = sysinfo.ip_addresses[0]
    if not ip_address and request.client:
        ip_address = request.client.host or ""

    os_type = (sysinfo.os_type or "unknown").lower() if sysinfo else "unknown"
    agent_version = sysinfo.agent_version or "" if sysinfo else ""

    # 3. Find or create device
    result = await db.execute(
        select(Device).where(
            Device.tenant_id == tenant_id,
            Device.hostname == hostname,
        )
    )
    device = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    is_new_device = False
    new_device_token: str | None = None

    if not device:
        device_id = new_id()
        # Generate device token so the agent can authenticate itself going forward
        new_device_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(new_device_token.encode()).hexdigest()

        device = Device(
            id=device_id,
            tenant_id=tenant_id,
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type,
            os_version=sysinfo.os_version if sysinfo else "",
            agent_version=agent_version,
            status="active",
            is_active=True,
            last_heartbeat=now,
            device_token_hash=token_hash,
        )
        db.add(device)
        is_new_device = True
        log.info(
            "Device auto-registered via telemetry: hostname=%s tenant=%s id=%s token_generated=%s",
            hostname, tenant_id, device_id, bool(new_device_token),
        )
    else:
        # Update existing device
        device.last_heartbeat = now
        device.status = "active"
        device.is_active = True
        if ip_address:
            device.ip_address = ip_address
        if os_type and os_type != "unknown":
            device.os_type = os_type
        if sysinfo and sysinfo.os_version:
            device.os_version = sysinfo.os_version
        if agent_version:
            device.agent_version = agent_version

    await db.commit()

    # 4. Forward processes and connections as pipeline events
    pipeline_events: List[Dict[str, Any]] = []
    ts = payload.timestamp or now.isoformat()

    if payload.processes:
        for proc in payload.processes[:200]:  # cap at 200
            pipeline_events.append({
                "source": "agent",
                "hostname": hostname,
                "log_type": "process_telemetry",
                "message": f"Process running: {proc.get('name', '')} (PID {proc.get('pid', '')})",
                "timestamp": ts,
                "device_id": device.id,
                "ip_address": ip_address,
                "event_type": "process_running",
                "severity": "info",
                "extra_data": {
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "memory_mb": proc.get("memory_mb", proc.get("memory", 0)),
                    "cpu_percent": proc.get("cpu_percent", 0.0),
                    "path": proc.get("path", ""),
                    "command_line": proc.get("command_line", ""),
                    "user": proc.get("user", ""),
                },
            })

    if payload.connections:
        for conn in payload.connections[:200]:  # cap at 200
            pipeline_events.append({
                "source": "agent",
                "hostname": hostname,
                "log_type": "network_telemetry",
                "message": f"Connection: {conn.get('local_ip', '')}:{conn.get('local_port', '')} -> {conn.get('remote_ip', '')}:{conn.get('remote_port', '')}",
                "timestamp": ts,
                "device_id": device.id,
                "ip_address": ip_address,
                "event_type": "network_connection",
                "severity": "info",
                "extra_data": {
                    "local_ip": conn.get("local_ip"),
                    "local_port": conn.get("local_port"),
                    "remote_ip": conn.get("remote_ip"),
                    "remote_port": conn.get("remote_port"),
                    "state": conn.get("state"),
                    "protocol": conn.get("protocol", "tcp"),
                },
            })

    if pipeline_events:
        if not unified_pipeline._running:
            log.error(
                "Telemetry: pipeline NOT RUNNING — %d events from %s will be DROPPED. "
                "Check GET /api/v1/pipeline/status",
                len(pipeline_events), hostname,
            )
        try:
            accepted = await unified_pipeline.ingest_batch(
                events=pipeline_events,
                tenant_id=tenant_id,
                source="agent",
                source_type="telemetry_batch",
            )
            if accepted == 0 and len(pipeline_events) > 0:
                log.warning(
                    "Telemetry: 0/%d events accepted for %s — pipeline may be stopped!",
                    len(pipeline_events), hostname,
                )
            else:
                log.debug("Telemetry: %d/%d pipeline events accepted for %s", accepted, len(pipeline_events), hostname)
        except Exception as exc:
            log.warning("Telemetry pipeline ingest failed for %s: %s", hostname, exc)

    return {
        "ok": True,
        "device_id": device.id,
        "device_token": new_device_token or "",  # empty for existing devices
        "device_registered": is_new_device,
        "hostname": hostname,
        "tenant_id": tenant_id,
        "timestamp": now.isoformat(),
        "events_forwarded": len(pipeline_events),
    }
