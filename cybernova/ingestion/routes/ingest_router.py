"""
CyberNova — Ingestion Router
POST /api/v1/ingest — Batch event ingestion
POST /api/v1/ingest/agent — Host Agent ingestion (auto-registers devices)
POST /api/v1/ingest/webhook — Webhook receiver
POST /api/v1/normalize/pending — Normalize pending events
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.schemas.event_schema import EventIngest, NormalizationResult
from cybernova.ingestion.normalizers import normalization_service
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.database.postgres.models import Device
from cybernova.core.utils.helpers import new_id
from cybernova.streaming.streams import STREAM_RAW_EVENTS
from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.ingestion.router")
router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


@router.post("/", summary="Batch ingest events")
async def ingest_events(
    body: EventIngest,
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    count = await unified_pipeline.ingest_batch(
        events=body.events,
        tenant_id=tenant_id,
        source=body.source,
        source_type=body.source_type,
    )
    return {"accepted": count}


@router.post("/agent", summary="Host Agent ingestion (token auth, auto-registers device)")
async def ingest_from_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Dedicated endpoint for the CyberNova Host Agent.
    Accepts Bearer token from login or API key.
    Auto-registers the device by hostname if it doesn't exist.
    
    Body format:
    {
        "events": [...],
        "source": "host_agent",
        "source_type": "agent"
    }
    
    Each event should contain at least:
    {
        "hostname": "...",
        "event_type": "...",
        ...
    }
    """
    
    # Try to get JWT from Authorization header
    auth_header = request.headers.get("Authorization", "")
    tenant_id = "default"
    hostname = None
    ip_address = None
    
    # If Bearer token provided, validate and get tenant_id
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from cybernova.security.encryption.jwt_handler import decode_access_token
            payload = decode_access_token(token)
            t = payload.get("tenant_id")
            if t:
                tenant_id = t
        except Exception as e:
            log.warning("Agent JWT decode failed: %s", e)
        
        # If JWT decode didn't yield a tenant_id, try device token lookup
        if tenant_id == "default" or not tenant_id:
            try:
                import hashlib
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                result = await db.execute(
                    select(Device).where(
                        Device.device_token_hash == token_hash,
                        Device.is_active,
                    ).limit(1)
                )
                device_match = result.scalar_one_or_none()
                if device_match:
                    tenant_id = device_match.tenant_id
                    log.info("Agent ingest: resolved tenant %s from device token hash", tenant_id)
            except Exception as e2:
                log.warning("Device token hash lookup failed: %s", e2)
    
    # If tenant_id is still the literal string "default", resolve it to the actual
    # Default tenant UUID from the database. This ensures foreign-key constraints
    # on alerts/events tables are satisfied.
    if tenant_id == "default" or not tenant_id:
        try:
            from sqlalchemy import text as sql_text
            result = await db.execute(
                sql_text("SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1")
            )
            row = result.scalar_one_or_none()
            if row:
                tenant_id = str(row)
                log.info("Agent ingest: resolved 'default' to tenant UUID %s", tenant_id)
        except Exception as e:
            log.warning("Default tenant lookup failed: %s — using literal 'default'", e)
    
    # Get request body
    body = await request.json()
    events = body.get("events", [])
    source = body.get("source", "host_agent")
    source_type = body.get("source_type", "agent")
    
    # Extract hostname from first event for device registration
    if events:
        first_event = events[0]
        hostname = first_event.get("hostname", None)
        ip_address = first_event.get("ip_address", None) or first_event.get("source_ip", None)
        if request.client and not ip_address:
            ip_address = request.client.host
    
    # Auto-register device if hostname is present
    device_id = None
    if hostname and hostname != "unknown":
        try:
            # Look up device by hostname (any tenant) to find correct tenant_id
            result = await db.execute(
                select(Device).where(
                    Device.hostname == hostname,
                ).order_by(Device.last_heartbeat.desc()).limit(1)
            )
            device = result.scalar_one_or_none()
            
            now = datetime.now(timezone.utc)
            if device:
                # Device exists — use its tenant_id and update heartbeat
                tenant_id = device.tenant_id
                device.last_heartbeat = now
                device.status = "active"
                if ip_address:
                    device.ip_address = ip_address
                log.info("Agent ingest: found device %s under tenant %s — using tenant_id for events", hostname, tenant_id)
            else:
                # No existing device — create one under resolved tenant
                device = Device(
                    id=new_id(),
                    tenant_id=tenant_id,
                    hostname=hostname,
                    ip_address=ip_address or "",
                    os_type="",
                    status="active",
                    is_active=True,
                    last_heartbeat=now,
                )
                db.add(device)
                await db.flush()
                log.info("Device auto-registered via agent ingest: hostname=%s tenant=%s id=%s", hostname, tenant_id, device.id)
            
            device_id = device.id
            await db.commit()
        except Exception as e:
            log.error("Device auto-registration failed for %s: %s", hostname, e)
    
    if not events:
        return {"accepted": 0, "device_id": device_id}
    
    # Publish to BOTH pipeline systems:
    # 1. UnifiedPipeline bus (cybernova:pipeline:* streams)
    # 2. Pipeline worker streams (cybernova:raw_events etc.)
    
    bus_count = await unified_pipeline.ingest_batch(
        events=events,
        tenant_id=tenant_id,
        source=source,
        source_type=source_type,
    )
    
    # Also publish to STREAM_RAW_EVENTS for the pipeline worker to consume
    raw_stream_count = 0
    try:
        redis = await get_redis()
        if redis:
            for event in events:
                envelope = {
                    "data": json.dumps(event),
                    "tenant_id": tenant_id,
                    "source": source,
                    "source_type": source_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                await redis.xadd(STREAM_RAW_EVENTS, envelope, maxlen=100000)
                raw_stream_count += 1
            log.info("Host agent: %d events published to %s for tenant %s", raw_stream_count, STREAM_RAW_EVENTS, tenant_id)
    except Exception as e:
        log.error("Host agent: failed to publish to raw events stream: %s", e)
    
    total_accepted = max(bus_count, raw_stream_count)
    if total_accepted == 0:
        log.error("Host agent: 0/%d events accepted for tenant %s — pipeline may be stopped!", len(events), tenant_id)
        raise HTTPException(status_code=502, detail=f"0/{len(events)} events accepted — pipeline may not be running.")
    
    log.info("Host agent ingested %d/%d events for tenant %s (device=%s)", total_accepted, len(events), tenant_id, hostname or "?")
    return {"accepted": total_accepted, "total": len(events), "device_id": device_id}


@router.post("/webhook", summary="Webhook receiver")
async def ingest_webhook(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    payload: Dict[str, Any] = await request.json()
    signature = request.headers.get("X-CyberNova-Signature", "")
    timestamp = request.headers.get("X-CyberNova-Timestamp", "")

    if signature and timestamp:
        from cybernova.security.webhook_security import WebhookSigner
        verifier = WebhookSigner()
        valid, reason = verifier.verify(payload, signature, timestamp)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Invalid HMAC signature: {reason}")

    count = await unified_pipeline.ingest_batch(
        events=[payload],
        tenant_id=tenant_id,
        source=request.headers.get("X-Source", "webhook"),
        source_type="webhook",
    )
    return {"accepted": True, "count": count}


@router.post("/normalize/pending", summary="Normalize pending events")
async def normalize_pending(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    results = await normalization_service.normalize_pending(db, tenant_id, limit=limit)
    return {"normalized": len(results)}


@router.post("/normalize", summary="Normalize raw events by IDs")
async def normalize_events(
    event_ids: List[str],
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    results = await normalization_service.normalize_batch(event_ids, db, tenant_id)
    return {
        "normalized": len(results),
        "results": [
            NormalizationResult(
                event_id=r.id, event_type=r.event_type,
                severity=r.severity or "info",
                fields_extracted=sum(1 for v in [r.source_ip, r.dest_ip, r.user, r.protocol] if v),
            ) for r in results
        ],
    }
