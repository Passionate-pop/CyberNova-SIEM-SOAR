"""
CyberNova — Ingestion Router
POST /api/v1/ingest — Batch event ingestion
POST /api/v1/ingest/webhook — Webhook receiver
POST /api/v1/normalize/pending — Normalize pending events
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.schemas.event_schema import EventIngest, NormalizationResult
from cybernova.ingestion.normalizers import normalization_service
from cybernova.pipeline.unified_pipeline import unified_pipeline

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


@router.post("/agent", summary="Host Agent ingestion (token auth)")
async def ingest_from_agent(
    request: Request,
):
    """
    Dedicated endpoint for the CyberNova Host Agent.
    Accepts Bearer token from login or API key.
    
    Body format:
    {
        "events": [...],
        "source": "host_agent",
        "source_type": "agent"
    }
    """
    
    # Try to get JWT from Authorization header
    auth_header = request.headers.get("Authorization", "")
    tenant_id = "default"
    
    # If Bearer token provided, validate and get tenant_id
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from cybernova.security.encryption.jwt_handler import decode_access_token
            payload = decode_access_token(token)
            tenant_id = payload.get("tenant_id", "default")
        except Exception as e:
            log.warning("Agent JWT decode failed, using default tenant: %s", e)
            tenant_id = "default"
    
    # Get request body
    body = await request.json()
    events = body.get("events", [])
    source = body.get("source", "host_agent")
    source_type = body.get("source_type", "agent")
    
    if not events:
        return {"accepted": 0}
    
    count = await unified_pipeline.ingest_batch(
        events=events,
        tenant_id=tenant_id,
        source=source,
        source_type=source_type,
    )
    
    if count == 0:
        log.error("Host agent: 0/%d events accepted for tenant %s — pipeline may be stopped!", len(events), tenant_id)
        from fastapi import HTTPException
        raise HTTPException(status_code=502, detail=f"0/{len(events)} events accepted — pipeline may not be running. Check GET /api/v1/pipeline/status")
    
    log.info("Host agent ingested %d/%d events for tenant %s", count, len(events), tenant_id)
    return {"accepted": count, "total": len(events)}


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
