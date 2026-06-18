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


# ── Seed Demo Data ──────────────────────────────────────────────────────────────

@router.post("/seed-demo", summary="Seed realistic demo data for first-time users")
async def seed_demo_data(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_pipeline_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Seed realistic demo data for new users so they don't see an empty system.
    Only runs if tenant has no existing alerts (prevents double-seeding).
    """
    from sqlalchemy import select, func

    # Check if tenant already has alerts — skip if data exists
    result = await db.execute(select(func.count()).select_from(Alert).where(Alert.tenant_id == tenant_id))
    alert_count = result.scalar()
    if alert_count > 0:
        return {"status": "skipped", "message": "Tenant already has data"}

    now = utcnow()
    from datetime import timedelta

    # Seed demo device
    from cybernova.database.postgres.models import Device
    device = Device(
        id=new_id(),
        tenant_id=tenant_id,
        hostname="WORKSTATION-001",
        ip_address="192.168.1.100",
        mac_address="00:1A:2B:3C:4D:5E",
        os_type="Windows 11",
        os_version="23H2",
        agent_version="1.0.0",
        status="active",
        is_active=True,
        last_heartbeat=now - timedelta(minutes=2),
        registered_at=now - timedelta(hours=1),
    )
    db.add(device)
    await db.flush()

    # Seed realistic alerts
    demo_alerts = [
        {
            "rule_name": "brute_force_detection",
            "severity": "high",
            "risk_score": 75.0,
            "description": "Multiple failed SSH login attempts from 203.0.113.45 to server 192.168.1.10",
            "status": "new",
            "extra_data": {
                "source_ip": "203.0.113.45",
                "dest_ip": "192.168.1.10",
                "source_port": 54321,
                "dest_port": 22,
                "protocol": "TCP",
                "user": "root",
                "event_type": "brute_force",
                "threat_intel": {"is_malicious": False, "sources": ["abuseipdb"], "abuseipdb": {"abuse_confidence_score": 45, "country_code": "CN", "usage_type": "hosting"}},
                "geo": {"country": "China", "country_code": "CN", "city": "Beijing", "region": "Beijing"},
                "alert_reason": "15 failed login attempts in 5 minutes",
            },
        },
        {
            "rule_name": "suspicious_outbound",
            "severity": "medium",
            "risk_score": 55.0,
            "description": "Unusual outbound DNS traffic to known suspicious domain resolver",
            "status": "new",
            "extra_data": {
                "source_ip": "192.168.1.100",
                "dest_ip": "198.51.100.77",
                "source_port": 49152,
                "dest_port": 53,
                "protocol": "UDP",
                "event_type": "dns_tunneling",
                "threat_intel": {"is_malicious": False, "sources": ["otx"], "otx": {"pulses": 2, "is_malicious": False}},
                "geo": {"country": "Russia", "country_code": "RU", "city": "Moscow", "region": "Moscow"},
                "alert_reason": "DNS queries to domain associated with known C2 infrastructure",
            },
        },
        {
            "rule_name": "privilege_escalation",
            "severity": "critical",
            "risk_score": 95.0,
            "description": "Unauthorized sudo execution detected — non-admin user attempted root access",
            "status": "new",
            "extra_data": {
                "source_ip": "192.168.1.100",
                "dest_ip": "",
                "source_port": 0,
                "dest_port": 0,
                "protocol": "",
                "user": "jsmith",
                "hostname": "WORKSTATION-001",
                "event_type": "privilege_escalation",
                "threat_intel": {},
                "geo": {},
                "alert_reason": "User jsmith (non-admin) executed sudo command outside business hours",
            },
        },
        {
            "rule_name": "malware_signature",
            "severity": "critical",
            "risk_score": 98.0,
            "description": "Trojan.Gen.2 detected in downloaded executable — file quarantined",
            "status": "new",
            "extra_data": {
                "source_ip": "10.0.0.50",
                "dest_ip": "192.168.1.100",
                "source_port": 443,
                "dest_port": 49200,
                "protocol": "TCP",
                "event_type": "malware_detected",
                "threat_intel": {"is_malicious": True, "sources": ["virustotal"], "virustotal": {"malicious": True, "detections": 42}},
                "geo": {"country": "United States", "country_code": "US", "city": "San Jose", "region": "CA"},
                "alert_reason": "File hash matches known Trojan.Gen.2 signature (VT: 42/68 detections)",
            },
        },
        {
            "rule_name": "policy_violation",
            "severity": "low",
            "risk_score": 25.0,
            "description": "USB storage device connected — policy requires encrypted media only",
            "status": "resolved",
            "extra_data": {
                "source_ip": "",
                "dest_ip": "",
                "source_port": 0,
                "dest_port": 0,
                "protocol": "",
                "user": "jsmith",
                "hostname": "WORKSTATION-001",
                "event_type": "policy_violation",
                "threat_intel": {},
                "geo": {},
                "alert_reason": "Unencrypted USB device (Serial: SN12345678) connected to managed workstation",
            },
        },
    ]

    created_alerts = []
    for alert_data in demo_alerts:
        alert = Alert(
            id=new_id(),
            tenant_id=tenant_id,
            device_id=device.id,
            rule_name=alert_data["rule_name"],
            severity=alert_data["severity"],
            risk_score=alert_data["risk_score"],
            description=alert_data["description"],
            status=alert_data["status"],
            extra_data=alert_data["extra_data"],
            created_at=now - timedelta(minutes=len(created_alerts) * 15),
        )
        db.add(alert)
        created_alerts.append(alert)

    # Seed one resolved incident
    incident = Incident(
        id=new_id(),
        tenant_id=tenant_id,
        title="Brute force attack from external IP",
        severity="high",
        status="resolved",
        risk_score=75.0,
        description="Multiple failed login attempts detected from 203.0.113.45. IP was blocked by firewall rule.",
        escalation_level=1,
        created_at=now - timedelta(hours=2),
        resolved_at=now - timedelta(minutes=30),
    )
    db.add(incident)

    await db.flush()

    log.info(f"Seeded demo data for tenant {tenant_id}: 1 device, {len(created_alerts)} alerts, 1 incident")

    return {
        "status": "seeded",
        "device": device.hostname,
        "alerts_created": len(created_alerts),
        "incidents_created": 1,
        "message": "Demo data seeded successfully — explore your dashboard to see simulated threats",
    }


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
    
    Send events directly to the real-time pipeline. Events will be:
    1. Normalized → 2. Enriched → 3. Evaluated by detection rules → 4. Alerts created
    5. Correlated into incidents → 6. SOAR playbooks triggered automatically
    
    This is the ONLY endpoint needed to feed data into CyberNova.
    """
    if not body.events:
        raise HTTPException(status_code=400, detail="No events provided")

    # Try unified pipeline first
    if unified_pipeline._running:
        try:
            event_ids = await unified_pipeline.ingest_batch(
                events=body.events,
                tenant_id=tenant_id,
                source=body.source,
                source_type=body.source_type,
            )
            log.info(f"User {user.username} ingested {len(body.events)} events via unified pipeline")
            return {
                "status": "accepted",
                "events_queued": len(body.events),
                "task_ids": event_ids[:10],
                "message": f"{len(body.events)} events queued for processing",
            }
        except Exception as e:
            log.warning(f"Unified pipeline failed: {e}, falling back to direct processing")

    # Direct processing (no pipeline available)
    event_ids = await _direct_ingest(db, tenant_id, body.source, body.source_type, body.events)
    
    log.info(f"User {user.username} ingested {len(event_ids)} events directly")
    
    return {
        "status": "accepted",
        "events_queued": len(event_ids),
        "task_ids": event_ids[:10],
        "message": f"{len(event_ids)} events ingested directly",
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


# ── Attack Simulation ────────────────────────────────────────────────────────────

ATTACK_STAGES = [
    {
        "stage": "Reconnaissance",
        "severity": "low",
        "risk_score": 25.0,
        "rule_name": "port_scan_detected",
        "description": "Sequential port scanning detected from 203.0.113.45 targeting internal servers.",
        "extra_data": {
            "source_ip": "203.0.113.45",
            "dest_ip": "10.0.0.0/24",
            "protocol": "TCP",
            "event_type": "reconnaissance",
            "threat_intel": {"is_malicious": False, "sources": ["abuseipdb"], "abuseipdb": {"abuse_confidence_score": 12, "country_code": "CN", "usage_type": "hosting"}},
            "geo": {"country": "China", "country_code": "CN", "city": "Beijing", "region": "Beijing"},
            "alert_reason": "50+ ports scanned in 30 seconds from single source",
        },
    },
    {
        "stage": "Suspicious Login",
        "severity": "medium",
        "risk_score": 55.0,
        "rule_name": "brute_force_attempt",
        "description": "Multiple failed SSH login attempts from external IP followed by successful authentication.",
        "extra_data": {
            "source_ip": "203.0.113.45",
            "dest_ip": "192.168.1.10",
            "source_port": 54321,
            "dest_port": 22,
            "protocol": "TCP",
            "user": "admin",
            "event_type": "brute_force",
            "threat_intel": {"is_malicious": False, "sources": ["abuseipdb"], "abuseipdb": {"abuse_confidence_score": 45, "country_code": "CN", "usage_type": "hosting"}},
            "geo": {"country": "China", "country_code": "CN", "city": "Beijing", "region": "Beijing"},
            "alert_reason": "12 failed login attempts followed by successful authentication",
        },
    },
    {
        "stage": "Privilege Escalation",
        "severity": "high",
        "risk_score": 75.0,
        "rule_name": "privilege_escalation_attempt",
        "description": "Unauthorized sudo execution detected — compromised user attempting root access.",
        "extra_data": {
            "source_ip": "192.168.1.10",
            "dest_ip": "",
            "source_port": 0,
            "dest_port": 0,
            "protocol": "",
            "user": "jsmith",
            "hostname": "SRV-WEB-01",
            "event_type": "privilege_escalation",
            "threat_intel": {},
            "geo": {},
            "alert_reason": "User jsmith (non-admin) executed sudo command outside business hours",
        },
    },
    {
        "stage": "Data Exfiltration",
        "severity": "critical",
        "risk_score": 98.0,
        "rule_name": "data_exfiltration_detected",
        "description": "Massive outbound data transfer to external IP — potential data exfiltration in progress.",
        "extra_data": {
            "source_ip": "192.168.1.10",
            "dest_ip": "198.51.100.99",
            "source_port": 443,
            "dest_port": 49200,
            "protocol": "TCP",
            "event_type": "exfiltration",
            "threat_intel": {"is_malicious": True, "sources": ["virustotal"], "virustotal": {"malicious": True, "detections": 42}},
            "geo": {"country": "Russia", "country_code": "RU", "city": "Moscow", "region": "Moscow"},
            "alert_reason": "2.5GB outbound transfer to unknown external IP within 5 minutes",
        },
    },
]


@router.post("/simulate-attack", summary="Simulate a staged attack timeline")
async def simulate_attack(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_pipeline_manage),
):
    """
    Simulate a multi-stage attack with staged alerts appearing one-by-one.
    Alerts are emitted via WebSocket for real-time dashboard updates.
    """
    from cybernova.api.websocket import connection_manager, WebSocketMessage, EventType
    from cybernova.database.postgres.session import engine
    from cybernova.pipeline.unified_pipeline import unified_pipeline
    from sqlalchemy.ext.asyncio import AsyncSession

    async def run_simulation(target_tenant_id: str):
        """Run the full attack timeline."""
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for i, stage in enumerate(ATTACK_STAGES):
                if i > 0:
                    await asyncio.sleep(1.5)  # 1.5 second delay between stages
                
                # Track pipeline stage activity for visualization
                unified_pipeline._metrics["ingested"] += 1
                unified_pipeline._metrics["normalized"] += 1
                unified_pipeline._metrics["enriched"] += 1
                
                now = utcnow()
                alert_id = new_id()
                
                alert = Alert(
                    id=alert_id,
                    tenant_id=target_tenant_id,
                    device_id=None,
                    rule_name=stage["rule_name"],
                    severity=stage["severity"],
                    risk_score=stage["risk_score"],
                    description=stage["description"],
                    status="new",
                    extra_data=stage["extra_data"],
                    created_at=now,
                )
                
                session.add(alert)
                await session.commit()
                
                # Track alert creation for visualization
                unified_pipeline._metrics["alerted"] += 1
                unified_pipeline._metrics["detected"] += 1
                
                alert_dict = {
                    "alert_id": alert.id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "description": alert.description,
                    "status": alert.status,
                    "timestamp": now.isoformat(),
                    "source_ip": stage["extra_data"].get("source_ip", ""),
                    "dest_ip": stage["extra_data"].get("dest_ip", ""),
                    "affected_system": stage["extra_data"].get("hostname", "Unknown"),
                }
                
                message = WebSocketMessage(
                    event_type=EventType.NEW_ALERT,
                    data={"alert": alert_dict},
                    tenant_id=target_tenant_id,
                )
                
                await connection_manager.send_to_tenant(
                    target_tenant_id,
                    message,
                    {EventType.NEW_ALERT, EventType.ALERT_UPDATED},
                )
                
                log.info(f"Attack simulation stage {i+1}/{len(ATTACK_STAGES)}: {stage['stage']} ({stage['severity']})")

    asyncio.create_task(run_simulation(tenant_id))

    return {
        "status": "simulation_started",
        "stages": len(ATTACK_STAGES),
        "message": "Attack simulation in progress — watch your dashboard for real-time alerts",
    }


# ── SOAR Test Event Injection ────────────────────────────────────────────────

SOAR_TEST_ACTIONS = [
    {
        "action_type": "block_ip",
        "target": "203.0.113.45",
        "status": "completed",
        "result": "IP 203.0.113.45 blocked via firewall rule",
    },
    {
        "action_type": "block_ip",
        "target": "198.51.100.77",
        "status": "completed",
        "result": "IP 198.51.100.77 blocked via firewall rule",
    },
    {
        "action_type": "isolate_device",
        "target": "WORKSTATION-001",
        "status": "completed",
        "result": "Device WORKSTATION-001 isolated from network",
    },
    {
        "action_type": "block_ip",
        "target": "10.0.0.50",
        "status": "failed",
        "result": "Firewall rule application failed: rule already exists",
    },
    {
        "action_type": "isolate_device",
        "target": "SRV-WEB-01",
        "status": "pending",
        "result": "Device SRV-WEB-01 queued for isolation",
    },
    {
        "action_type": "trigger_automation",
        "target": "incident_response_workflow",
        "status": "completed",
        "result": "Automation workflow triggered for incident IR-2026-0042",
    },
]


@router.post("/test-soar-actions", summary="Inject test SOAR actions for verification")
async def test_soar_actions(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_pipeline_manage),
    db: AsyncSession = Depends(get_db),
):
    """
    Inject realistic test SOAR actions directly into the DB and push them
    via WebSocket to verify the full AlertsPage → ResponsePage flow works.
    """
    from datetime import timedelta

    created = []
    for i, action_data in enumerate(SOAR_TEST_ACTIONS):
        ra = ResponseAction(
            id=new_id(),
            tenant_id=tenant_id,
            action_type=action_data["action_type"],
            parameters={"target": action_data["target"]},
            status=action_data["status"],
            initiated_by=user.id,
            result=action_data["result"],
            created_at=utcnow() - timedelta(minutes=i * 5),
            updated_at=utcnow() - timedelta(minutes=i * 5),
        )
        db.add(ra)
        created.append(ra)

    await db.commit()

    # Broadcast each action via WebSocket so ResponsePage auto-refreshes
    for ra in created:
        await ws_handler.broadcast_soar_action(
            {
                "action": ra.action_type,
                "target": ra.parameters.get("target", ""),
                "status": ra.status,
                "message": ra.result,
            },
            tenant_id,
        )

    log.info(f"User {user.username} injected {len(created)} test SOAR actions for tenant {tenant_id}")

    return {
        "status": "injected",
        "actions_created": len(created),
        "message": f"{len(created)} test SOAR actions injected and broadcast via WebSocket",
    }


