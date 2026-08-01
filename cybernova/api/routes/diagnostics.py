"""
CyberNova — Onboarding Diagnostics Endpoint
GET /api/v1/diagnostics/onboarding

Returns real-time diagnostic information to help debug agent connection issues.
Used by the frontend onboarding page to show meaningful error messages.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Device, Tenant
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.diagnostics")
router = APIRouter(prefix="/api/v1/diagnostics", tags=["Diagnostics"])


@router.get("/onboarding", summary="Check onboarding prerequisites and agent connection status")
async def onboarding_diagnostics(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Real-time diagnostics for the onboarding flow.

    Returns:
      - user: your user/tenant info
      - devices: devices already registered in your tenant
      - connectivity: DB and Redis health
      - agent_endpoint: whether the agent telemetry endpoint is reachable
      - recommendations: actionable tips if something is misconfigured
    """
    now = datetime.now(timezone.utc)
    recommendations: list[str] = []

    # ── 1. DB health ──
    db_ok = False
    try:
        await db.execute(select(func.now()))
        db_ok = True
    except Exception as e:
        recommendations.append(f"Database connection failed: {e}")

    # ── 2. Redis health ──
    redis_ok = False
    try:
        redis = await get_redis()
        redis_ok = redis is not None
    except Exception:
        recommendations.append("Redis is unreachable — pipeline requires Redis")

    # ── 3. Tenant info ──
    tenant_ok = False
    tenant_name = ""
    try:
        result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = result.scalar_one_or_none()
        if tenant:
            tenant_ok = True
            tenant_name = tenant.name
        else:
            recommendations.append(f"Tenant {user.tenant_id} not found in database")
    except Exception as e:
        recommendations.append(f"Tenant lookup failed: {e}")

    # ── 4. Device count for this tenant ──
    device_count = 0
    recent_devices: list[dict] = []
    try:
        result = await db.execute(
            select(Device)
            .where(Device.tenant_id == user.tenant_id)
            .order_by(Device.last_heartbeat.desc().nullslast())
            .limit(10)
        )
        devices = result.scalars().all()
        device_count = len(devices)
        for d in devices:
            recent_devices.append({
                "id": d.id,
                "hostname": d.hostname,
                "ip_address": d.ip_address,
                "status": d.status,
                "os_type": d.os_type,
                "agent_version": d.agent_version,
                "last_heartbeat": d.last_heartbeat.isoformat() if d.last_heartbeat else None,
                "registered_at": d.registered_at.isoformat() if d.registered_at else None,
            })
    except Exception as e:
        recommendations.append(f"Device lookup failed: {e}")

    # ── 5. Build recommendations ──
    if device_count == 0 and tenant_ok:
        recommendations.append(
            "No devices registered yet. "
            "Make sure you ran the install command on your device with Administrator privileges. "
            "The agent needs to reach the backend API URL shown below."
        )

    if device_count == 0:
        recommendations.append(
            "The frontend is polling every 3 seconds. "
            "If you ran the install command but see no device here, "
            "check that the agent can reach the backend URL. "
            "Run this on your device to test: curl -s <backend_url>/health"
        )

    # ── 6. API endpoint info ──
    # The JWT dependency (get_current_user) already validated the token.
    token_ok = True
    api_endpoints = {
        "health": "/health",
        "agent_telemetry": "POST /api/v1/agent/telemetry",
        "agent_download_windows": "GET /agent.ps1",
        "agent_download_linux": "GET /agent.sh",
        "device_list": "GET /api/v1/devices/list",
    }

    return {
        "status": "ok" if (db_ok and tenant_ok) else "degraded",
        "timestamp": now.isoformat(),
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id,
            "roles": user.roles,
        },
        "connectivity": {
            "database": "connected" if db_ok else "failed",
            "redis": "connected" if redis_ok else "unavailable",
            "token_valid": token_ok,
        },
        "tenant": {
            "id": user.tenant_id,
            "name": tenant_name,
            "exists": tenant_ok,
        },
        "devices": {
            "total": device_count,
            "recent": recent_devices,
        },
        "api_endpoints": api_endpoints,
        "recommendations": recommendations,
    }
