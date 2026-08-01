"""
CyberNova — Real-Time Pipeline API Router
REST endpoints for pipeline control and monitoring.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import NormalizedEvent, Alert, Incident, ResponseAction, RawEvent
from cybernova.api.websocket import ws_handler
from cybernova.pipeline import queue_manager
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.pipeline.queue_manager import QueueName
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_pipeline_view, require_pipeline_manage
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.audit.service import audit_service

log = logging.getLogger("cybernova.pipeline.api")

router = APIRouter(prefix="/api/v1/pipeline", tags=["Pipeline (Real-Time)"])


# ── Request/Response Models ───────────────────────────────────────────────────

class PipelineIngestRequest(BaseModel):
    source: str = Field(..., description="Event source name (e.g., 'firewall', 'ids', 'syslog')")
    source_type: str = Field(default="api", description="Source type")
    events: list[dict] = Field(..., description="List of events to ingest")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "source": "firewall",
                "source_type": "syslog",
                "events": [
                    {
                        "message": "SSH brute force from 192.168.1.100",
                        "severity": "high",
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.5",
                        "protocol": "TCP",
                        "dst_port": 22,
                    }
                ]
            }
        }
    }


class PipelineStatusResponse(BaseModel):
    running: bool
    stats: Dict[str, Any]
    queue_stats: Dict[str, Any]
    uptime_seconds: float


class PipelineActionRequest(BaseModel):
    action: str = Field(..., description="Action to perform: start, stop, restart, flush")
    queue: Optional[str] = Field(None, description="Specific queue to target")


# ── Pipeline Control Endpoints ─────────────────────────────────────────────────

@router.post("/start", summary="Start the real-time pipeline")
async def start_pipeline(
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
    db = Depends(get_db),
):
    """Start all pipeline consumers and begin real-time processing."""
    if unified_pipeline._running:
        return {"status": "already_running", "message": "Pipeline is already running"}

    await unified_pipeline.start()
    log.info(f"Unified pipeline started by user: {user.username}")
    
    await audit_service.log(
        db=db,
        action="pipeline_started",
        tenant_id=tenant_id,
        user_id=user.id,
        resource_type="pipeline",
        details={"user": user.username},
    )
    await db.commit()
    
    return {
        "status": "started",
        "message": "Real-time pipeline started successfully",
        "pipeline": "unified_pipeline",
    }


@router.post("/stop", summary="Stop the real-time pipeline")
async def stop_pipeline(
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
    db = Depends(get_db),
):
    """Stop all pipeline consumers."""
    if not unified_pipeline._running:
        return {"status": "already_stopped", "message": "Pipeline is not running"}

    await unified_pipeline.close()
    log.info(f"Unified pipeline stopped by user: {user.username}")
    
    await audit_service.log(
        db=db,
        action="pipeline_stopped",
        tenant_id=tenant_id,
        user_id=user.id,
        resource_type="pipeline",
        details={"user": user.username},
    )
    await db.commit()
    
    return {
        "status": "stopped",
        "message": "Unified pipeline stopped",
    }


@router.post("/action", summary="Execute pipeline action")
async def pipeline_action(
    body: PipelineActionRequest,
    user: CurrentUser = Depends(require_pipeline_manage),
):
    """Execute a pipeline action (start, stop, restart, flush)."""
    import asyncio
    action = body.action.lower()
    
    if action == "start":
        if unified_pipeline._running:
            return {"status": "already_running"}
        await unified_pipeline.start()
        return {"status": "started", "message": "Unified pipeline started"}
    
    elif action == "stop":
        if not unified_pipeline._running:
            return {"status": "already_stopped"}
        await unified_pipeline.close()
        return {"status": "stopped", "message": "Unified pipeline stopped"}
    
    elif action == "restart":
        await unified_pipeline.close()
        await asyncio.sleep(1)
        await unified_pipeline.start()
        return {"status": "restarted", "message": "Unified pipeline restarted"}
    
    elif action == "flush":
        for queue in QueueName:
            if queue_manager._redis:
                await queue_manager._redis.delete(queue.value)
        return {"status": "flushed", "message": "All queues cleared"}
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


# ── Real-Time Ingestion Endpoint ──────────────────────────────────────────────

@router.post("/ingest", summary="Ingest events into real-time pipeline")
async def ingest_to_pipeline(
    body: PipelineIngestRequest,
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    """
    **Main entry point for real-time data ingestion.**
    
    Send events directly to the pipeline-worker stream for async processing.
    Events flow through: raw -> normalize -> enrich -> detect -> alert -> notify
    Each stage is processed by the pipeline-worker container with realistic timing.
    
    This is the ONLY endpoint needed to feed data into CyberNova.
    """
    if not body.events:
        raise HTTPException(status_code=400, detail="No events provided")

    # Store events in DB (raw + normalized) for record keeping
    event_ids = await _direct_ingest(db, tenant_id, body.source, body.source_type, body.events)
    
    # Publish normalized events to pipeline-worker stream for async stage-by-stage processing.
    # The pipeline-worker chain: normalized_events -> enrichment -> detection -> alert -> notify
    # Each stage runs in the pipeline-worker container with realistic async timing.
    worker_published = 0
    try:
        from cybernova.database.redis import get_redis
        from cybernova.streaming.producer import StreamProducer
        from uuid import uuid4
        redis = await get_redis()
        if redis:
            producer = StreamProducer(redis)
            for event_data in body.events:
                # Construct normalized event dict that enrichment_worker expects
                norm_event = {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "event_type": event_data.get("event_type") or event_data.get("type") or "unknown",
                    "severity": _normalize_severity(event_data.get("severity", "info")),
                    "source_ip": event_data.get("source_ip") or event_data.get("src_ip", ""),
                    "dest_ip": event_data.get("dest_ip") or event_data.get("dst_ip", ""),
                    "source_port": event_data.get("source_port", 0),
                    "dest_port": event_data.get("dest_port", 0),
                    "protocol": event_data.get("protocol", ""),
                    "user": event_data.get("user", ""),
                    "message": event_data.get("message", ""),
                    "risk_score": event_data.get("risk_score", 0),
                    "source": body.source,
                    "source_type": body.source_type,
                }
                await producer.produce_normalized_event(norm_event, tenant_id, str(uuid4()))
                worker_published += 1
            log.info("Published %d/%d events to normalized_events stream for async pipeline processing",
                     worker_published, len(body.events))
    except Exception as e:
        log.warning("Worker stream publish failed: %s — events stored in DB only", e)
    
    log.info(f"User {user.username} ingested {len(event_ids)} events "
             f"(DB stored: {len(event_ids)}, pipeline queued: {worker_published})")
    
    return {
        "status": "accepted",
        "events_queued": len(body.events),
        "task_ids": event_ids[:10],
        "message": f"{len(body.events)} events queued for async pipeline processing (enrichment -> detection -> alert)",
    }


async def _direct_ingest(
    db: AsyncSession,
    tenant_id: str,
    source: str,
    source_type: str,
    events: List[Dict[str, Any]],
) -> List[str]:
    """Direct ingestion without Redis - stores events and normalizes them."""
    event_ids = []
    
    for event_data in events:
        # Create raw event
        raw_event = RawEvent(
            id=new_id(),
            tenant_id=tenant_id,
            source=source,
            source_type=source_type,
            payload=event_data,
            received_at=utcnow(),
        )
        db.add(raw_event)
        
        # Create normalized event directly
        normalized = NormalizedEvent(
            id=new_id(),
            tenant_id=tenant_id,
            raw_event_id=raw_event.id,
            event_type=event_data.get("event_type") or event_data.get("type") or "unknown",
            severity=_normalize_severity(event_data.get("severity", "info")),
            source_ip=event_data.get("source_ip") or event_data.get("src_ip", ""),
            dest_ip=event_data.get("dest_ip") or event_data.get("dst_ip", ""),
            source_port=event_data.get("source_port", 0),
            dest_port=event_data.get("dest_port", 0),
            protocol=event_data.get("protocol", ""),
            user=event_data.get("user", ""),
            message=event_data.get("message", ""),
            timestamp=utcnow(),
        )
        db.add(normalized)
        event_ids.append(raw_event.id)
    
    await db.flush()
    return event_ids


def _normalize_severity(severity: str) -> str:
    """Normalize severity string. Maps to canonical levels without elevation."""
    severity = str(severity).lower().strip()
    mapping = {
        "crit": "critical", "fatal": "critical", "emerg": "critical",
        "error": "high", "err": "high",
        "warn": "medium", "warning": "medium",
        "notice": "low",
        "info": "info", "debug": "info", "trace": "info",
    }
    return mapping.get(severity, "info")


@router.post("/ingest/stream", summary="Stream events via SSE")
async def ingest_stream(
    body: PipelineIngestRequest,
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Ingest events with streaming progress updates.
    Returns a task ID that can be used to track processing status.
    """
    if not unified_pipeline._running:
        raise HTTPException(status_code=503, detail="Pipeline not running")

    # Queue all events
    event_ids = await unified_pipeline.ingest_batch(
        events=body.events,
        tenant_id=tenant_id,
        source=body.source,
        source_type=body.source_type,
    )

    return {
        "batch_id": event_ids[0] if event_ids else None,
        "events_count": len(event_ids),
        "status": "processing",
    }


# ── Manual Pipeline Step Endpoints ─────────────────────────────────────────────

@router.post("/normalize", summary="Manually normalize pending events")
async def manual_normalize(
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """Manually trigger normalization for pending events."""
    from cybernova.ingestion.services.ingestion_service import ingestion_service

    count = await ingestion_service.normalize_pending(db, tenant_id, limit)
    
    return {
        "status": "completed",
        "normalized_count": count,
        "message": f"Normalized {count} events",
    }


@router.post("/enrich", summary="Manually enrich pending events")
async def manual_enrich(
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """Manually trigger enrichment for pending events."""
    from cybernova.ingestion.services.ingestion_service import ingestion_service

    count = await ingestion_service.enrich_batch(db, tenant_id, limit)
    
    return {
        "status": "completed",
        "enriched_count": count,
        "message": f"Enriched {count} events",
    }


@router.post("/detect", summary="Manually run detection on pending events")
async def manual_detect(
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """Manually trigger detection for pending events."""
    from cybernova.detection.services.detection_service import detection_service

    alerts = await detection_service.scan_pending(db, tenant_id, limit)
    
    return {
        "status": "completed",
        "alerts_created": len(alerts),
        "message": f"Created {len(alerts)} alerts",
    }


@router.post("/correlate", summary="Manually correlate pending alerts")
async def manual_correlate(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """Manually trigger alert correlation."""
    from cybernova.detection.correlation_engine.correlation_service import correlation_service

    incidents = await correlation_service.correlate_pending(db, tenant_id)
    
    return {
        "status": "completed",
        "incidents_created": len(incidents),
        "message": f"Created/updated {len(incidents)} incidents",
    }


# ── Full Pipeline Run ──────────────────────────────────────────────────────────

@router.post("/run", summary="Run full pipeline on pending data")
async def run_full_pipeline(
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_manage),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Run the FULL pipeline manually: normalize → enrich → detect → correlate.
    
    Use this to process all pending events in the database.
    For real-time streaming, use POST /api/v1/pipeline/ingest instead.
    """
    from cybernova.ingestion.services.ingestion_service import ingestion_service
    from cybernova.detection.services.detection_service import detection_service
    from cybernova.detection.correlation_engine.correlation_service import correlation_service

    # Step 1: Normalize
    normalized = await ingestion_service.normalize_pending(db, tenant_id, limit)
    
    # Step 2: Enrich
    enriched = await ingestion_service.enrich_batch(db, tenant_id, limit)
    
    # Step 3: Detect
    alerts = await detection_service.scan_pending(db, tenant_id, limit)
    
    # Step 4: Correlate
    incidents = await correlation_service.correlate_pending(db, tenant_id)

    log.info(f"Pipeline run completed by {user.username}: {normalized} normalized, {enriched} enriched, {len(alerts)} alerts, {len(incidents)} incidents")

    return {
        "status": "completed",
        "steps": {
            "normalized": normalized,
            "enriched": enriched,
            "alerts_created": len(alerts),
            "incidents_created": len(incidents),
        },
        "total_processed": normalized,
        "message": "Full pipeline completed successfully",
    }


# ── Pipeline Status & Monitoring ────────────────────────────────────────────────

@router.get("/status", summary="Get pipeline status and statistics")
async def get_pipeline_status(
    user: CurrentUser = Depends(require_pipeline_view),
):
    """
    Get real-time pipeline status including:
    - Running state
    - Processing statistics
    - Queue depths
    - Processing latency
    """
    metrics = await unified_pipeline.get_metrics()
    
    return PipelineStatusResponse(
        running=unified_pipeline._running,
        stats=metrics,
        queue_stats=metrics.get("pending", {}),
        uptime_seconds=0,
    )


@router.get("/metrics", summary="Get pipeline metrics for monitoring")
async def get_pipeline_metrics(
    user: CurrentUser = Depends(require_pipeline_view),
):
    """Get detailed pipeline metrics for Grafana/Dashboard."""
    metrics = await unified_pipeline.get_metrics()
    
    return {
        # Event processing rates
        "events_ingested_total": metrics["ingested"],
        "events_normalized_total": metrics["normalized"],
        "events_enriched_total": metrics["enriched"],
        
        # Alert metrics
        "alerts_created_total": metrics["alerted"],
        "incidents_created_total": metrics["correlated"],
        
        # SOAR metrics
        "soar_actions_triggered_total": metrics["soared"],
        
        # Error tracking
        "errors_total": metrics["errors"],
        
        # Queue depths
        "queue_ingestion_depth": metrics["pending"].get("normalization", 0),
        "queue_detection_depth": metrics["pending"].get("detection", 0),
        "queue_soar_depth": metrics["pending"].get("soar", 0),
        
        # Latency
        "avg_processing_latency_ms": metrics["avg_latency_ms"],
        
        # Timestamps (not available in unified metrics at top level)
        "last_event_time": None,
        "last_alert_time": None,
    }


@router.get("/queue/{queue_name}", summary="Get specific queue statistics")
async def get_queue_stats(
    queue_name: str,
    user: CurrentUser = Depends(require_pipeline_view),
):
    """Get statistics for a specific queue."""
    try:
        queue = QueueName(queue_name)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown queue: {queue_name}")
    
    stats = await queue_manager.get_queue_stats()
    
    if queue_name not in stats:
        raise HTTPException(status_code=404, detail=f"Queue not found: {queue_name}")
    
    return {
        "queue": queue_name,
        "length": stats[queue_name]["length"],
        "priority": queue.value,
    }


# ── Real-Time Updates (SSE) ────────────────────────────────────────────────────

@router.get("/stream/{event_type}", summary="Subscribe to real-time pipeline events")
async def pipeline_event_stream(
    event_type: str,
    user: CurrentUser = Depends(require_pipeline_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Server-Sent Events stream for real-time pipeline updates.
    
    Subscribe to: alerts, incidents, actions
    
    Returns an SSE stream that pushes updates as they happen.
    """
    from fastapi.responses import StreamingResponse
    import asyncio
    
    async def event_generator():
        redis = queue_manager._redis
        if not redis:
            # Fallback to polling
            while True:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Redis not available'})}\n\n"
                await asyncio.sleep(5)
        
        pubsub = redis.pubsub()
        await pubsub.subscribe(f"cybernova:{event_type}:{tenant_id}")
        
        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message:
                    yield f"data: {message['data']}\n\n"
                await asyncio.sleep(0.1)
        except Exception as e:
            log.error(f"SSE stream error: {e}")
        finally:
            await pubsub.unsubscribe()
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


