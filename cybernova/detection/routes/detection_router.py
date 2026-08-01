"""
CyberNova — Detection Router
POST /api/v1/detect/scan              — Scan pending events
GET  /api/v1/detect/alerts             — List alerts
PUT  /api/v1/detect/alerts/{id}        — Update alert status
GET  /api/v1/detect/rules              — List rules
POST /api/v1/detect/correlate          — Correlate alerts
GET  /api/v1/detect/incidents          — List incidents
PUT  /api/v1/detect/incidents/{id}     — Update incident
POST /api/v1/detect/enrich             — Enrich pending events
GET  /api/v1/detect/mitre/coverage     — MITRE ATT&CK coverage
GET  /api/v1/detect/mitre/summary      — MITRE coverage summary
GET  /api/v1/detect/mitre/tactics      — List tactics
GET  /api/v1/detect/mitre/techniques   — List techniques for tactic
POST /api/v1/detect/sigma/upload       — Upload Sigma YAML rule
GET  /api/v1/detect/stats              — Detection statistics
"""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime, timezone

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.detection.services.detection_service import detection_service
from cybernova.detection.rules_engine.rules import rule_engine
from cybernova.detection.correlation_engine.correlation_service import correlation_service
from cybernova.detection.pipelines.enrichment import enrichment_service
from cybernova.schemas.alert_schema import AlertResponse, AlertDetailResponse
from cybernova.schemas.incident_schema import IncidentResponse
from cybernova.database.repository.repositories import AlertRepository, IncidentRepository
from cybernova.audit.service import audit_service
from cybernova.database.postgres.models import Alert, Incident

router = APIRouter(prefix="/api/v1/detect", tags=["Detection"])


class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None


@router.post("/scan", summary="Scan pending events for threats")
async def scan_pending(
    limit: int = Query(100, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    alerts = await detection_service.scan_pending(db, tenant_id, limit=limit)

    for alert in alerts:
        await audit_service.log(
            db=db,
            action="alert_created",
            tenant_id=tenant_id,
            user_id=user.id,
            resource_type="alert",
            resource_id=alert.id,
            details={"rule_name": alert.rule_name, "severity": alert.severity},
        )
    await db.commit()

    return {"alerts_created": len(alerts)}


@router.get("/alerts", summary="List alerts")
async def list_alerts(
    status: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = AlertRepository(db, tenant_id)
    filters = {}
    if status:
        filters["status"] = status
    alerts = await repo.list_all(limit=limit, filters=filters if filters else None)
    return {"alerts": [AlertResponse.model_validate(a) for a in alerts]}


@router.get("/alerts/{alert_id}", summary="Get alert detail")
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertDetailResponse.model_validate(alert)


@router.put("/alerts/{alert_id}", summary="Update alert status")
async def update_alert(
    alert_id: str,
    update: AlertUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes = {}
    if update.status and update.status != alert.status:
        changes["status"] = {"old": alert.status, "new": update.status}
        alert.status = update.status

        if update.status == "resolved":
            await audit_service.log(
                db=db,
                action="alert_resolved",
                tenant_id=tenant_id,
                user_id=user.id,
                resource_type="alert",
                resource_id=alert_id,
                details={"previous_status": changes["status"]["old"]},
            )
        else:
            await audit_service.log(
                db=db,
                action="alert_updated",
                tenant_id=tenant_id,
                user_id=user.id,
                resource_type="alert",
                resource_id=alert_id,
                details={"changes": changes},
            )

    if update.assigned_to:
        changes["assigned_to"] = {"new": update.assigned_to}
        await audit_service.log(
            db=db,
            action="alert_assigned",
            tenant_id=tenant_id,
            user_id=user.id,
            resource_type="alert",
            resource_id=alert_id,
            details={"assigned_to": update.assigned_to},
        )

    await db.commit()
    return {"alert_id": alert_id, "updated": True, "changes": changes}


@router.get("/rules", summary="List detection rules")
async def list_rules(
    user: CurrentUser = Depends(get_current_user),
):
    return {"rules": rule_engine.list_rules()}


@router.patch("/rules/{rule_id}", summary="Update a detection rule")
async def update_rule(
    rule_id: str,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
):
    """
    Update a detection rule's properties (e.g., enable/disable).
    
    Example: PATCH /api/v1/detect/rules/suspicious_file  {"enabled": false}
    
    Returns the updated rule or 404 if not found.
    """
    # Filter to only allowed fields
    allowed = {"enabled", "severity", "risk_score", "description"}
    updates = {k: v for k, v in body.items() if k in allowed}
    
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update. Allowed: enabled, severity, risk_score, description")
    
    result = rule_engine.update_rule(rule_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    
    return result


@router.post("/correlate", summary="Correlate alerts into incidents")
async def correlate(
    window_minutes: int = 15,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    incidents = await correlation_service.correlate_alerts(db, tenant_id, window_minutes)
    return {"incidents_created": len(incidents)}


@router.get("/incidents", summary="List incidents")
async def list_incidents(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = IncidentRepository(db, tenant_id)
    incidents = await repo.list_all(limit=limit)
    return {"incidents": [IncidentResponse.model_validate(i) for i in incidents]}


@router.put("/incidents/{incident_id}", summary="Update incident")
async def update_incident(
    incident_id: str,
    update: IncidentUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes = {}
    if update.status and update.status != incident.status:
        changes["status"] = {"old": incident.status, "new": update.status}
        incident.status = update.status

        if update.status == "resolved":
            await audit_service.log(
                db=db,
                action="incident_resolved",
                tenant_id=tenant_id,
                user_id=user.id,
                resource_type="incident",
                resource_id=incident_id,
                details={"previous_status": changes["status"]["old"]},
            )
        else:
            await audit_service.log(
                db=db,
                action="incident_updated",
                tenant_id=tenant_id,
                user_id=user.id,
                resource_type="incident",
                resource_id=incident_id,
                details={"changes": changes},
            )

    if update.assigned_to:
        changes["assigned_to"] = {"new": update.assigned_to}
        await audit_service.log(
            db=db,
            action="incident_assigned",
            tenant_id=tenant_id,
            user_id=user.id,
            resource_type="incident",
            resource_id=incident_id,
            details={"assigned_to": update.assigned_to},
        )

    if update.severity and update.severity != incident.severity:
        changes["severity"] = {"old": incident.severity, "new": update.severity}
        incident.severity = update.severity

    await db.commit()
    return {"incident_id": incident_id, "updated": True, "changes": changes}


@router.post("/incidents/{incident_id}/resolve", summary="Resolve an incident")
async def resolve_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    incident.status = "resolved"
    from datetime import datetime as _datetime
    incident.resolved_at = _datetime.now(timezone.utc)

    await audit_service.log(
        db=db, action="incident_resolved", tenant_id=tenant_id, user_id=user.id,
        resource_type="incident", resource_id=incident_id,
        details={"previous_status": old_status, "resolved_by": user.email},
    )

    # Broadcast via WebSocket
    from cybernova.api.websocket import ws_handler
    await ws_handler.broadcast_soar_action(
        {"action": "incident_resolved", "target": incident_id, "status": "completed",
         "message": f"Incident {incident.title} resolved by {user.email}"},
        tenant_id,
    )

    await db.commit()
    return {"incident_id": incident_id, "status": "resolved", "updated": True}


@router.post("/incidents/{incident_id}/escalate", summary="Escalate an incident")
async def escalate_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "escalated"
    incident.escalation_level = (incident.escalation_level or 0) + 1

    await audit_service.log(
        db=db, action="incident_escalated", tenant_id=tenant_id, user_id=user.id,
        resource_type="incident", resource_id=incident_id,
        details={"escalation_level": incident.escalation_level, "escalated_by": user.email},
    )

    from cybernova.api.websocket import ws_handler
    await ws_handler.broadcast_soar_action(
        {"action": "incident_escalated", "target": incident_id, "status": "completed",
         "message": f"Incident {incident.title} escalated to level {incident.escalation_level} by {user.email}"},
        tenant_id,
    )

    await db.commit()
    return {"incident_id": incident_id, "status": "escalated", "escalation_level": incident.escalation_level, "updated": True}


@router.get("/incidents/{incident_id}/export", summary="Export incident report as JSON")
async def export_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Export an incident and its related alerts as a downloadable JSON report."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch related alerts
    alerts_result = await db.execute(
        select(Alert).where(Alert.tenant_id == tenant_id, Alert.incident_id == incident_id).order_by(Alert.created_at.desc()).limit(50)
    )
    related_alerts = alerts_result.scalars().all()

    report = {
        "incident": {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "description": incident.description,
            "escalation_level": incident.escalation_level,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        },
        "related_alerts": [
            {
                "alert_id": a.id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "status": a.status,
                "description": a.description,
                "source_ip": a.source_ip or (a.extra_data or {}).get("source_ip", "") if a.extra_data else "",
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in related_alerts
        ],
        "exported_by": user.email,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
    }

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.json"},
    )


@router.post("/enrich", summary="Enrich pending events")
async def enrich_pending(
    limit: int = Query(100, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    count = await enrichment_service.enrich_pending(db, tenant_id, limit=limit)
    return {"enriched": count}


# ── MITRE ATT&CK Endpoints ──────────────────────────────────────────────────


@router.get("/mitre/coverage", summary="MITRE ATT&CK coverage per tactic")
async def mitre_coverage(
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.detection.mitre.mitre_coverage import mitre_coverage as mc
    return {"coverage": mc.get_coverage()}


@router.get("/mitre/summary", summary="MITRE ATT&CK coverage summary")
async def mitre_coverage_summary(
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.detection.mitre.mitre_coverage import mitre_coverage as mc
    return mc.get_summary()


@router.get("/mitre/tactics", summary="List all MITRE ATT&CK tactics")
async def mitre_tactics(
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.detection.mitre.mitre import MITRE_TACTICS
    return {
        "tactics": [
            {"id": tid, "name": name}
            for tid, name in MITRE_TACTICS.items()
        ]
    }


@router.get("/mitre/techniques", summary="List techniques for a tactic")
async def mitre_techniques(
    tactic_id: str = Query(..., description="MITRE tactic ID (e.g. TA0001)"),
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.detection.mitre.mitre import get_techniques_for_tactic
    return {"tactic_id": tactic_id, "techniques": get_techniques_for_tactic(tactic_id)}


# ── Sigma Rule Endpoints ────────────────────────────────────────────────────


class SigmaUploadRequest(BaseModel):
    yaml_content: str
    description: Optional[str] = None


class SigmaUploadResponse(BaseModel):
    rule_name: str
    severity: str
    risk_score: float
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


@router.post("/sigma/upload", summary="Upload and register a Sigma YAML rule")
async def sigma_upload(
    request: SigmaUploadRequest,
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.detection.sigma.sigma_loader import sigma_loader
    rule = sigma_loader.from_yaml_str(request.yaml_content)
    if not rule:
        raise HTTPException(status_code=400, detail="Failed to parse Sigma rule — check YAML format")
    rule_engine.register_rule(rule)
    return SigmaUploadResponse(
        rule_name=rule.name,
        severity=rule.severity,
        risk_score=rule.risk_score,
        description=rule.description,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
    )


@router.get("/stats", summary="Detection statistics")
async def detection_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    from sqlalchemy import func
    from cybernova.database.postgres.models import Alert
    total_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)
    )
    total = total_result.scalar() or 0
    open_result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tenant_id,
            Alert.status.in_(["new", "open", "in_progress"]),
        )
    )
    open_count = open_result.scalar() or 0
    critical_result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tenant_id,
            Alert.severity == "critical",
        )
    )
    critical_count = critical_result.scalar() or 0
    resolved_result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tenant_id,
            Alert.status == "resolved",
        )
    )
    resolved = resolved_result.scalar() or 0
    return {
        "total_alerts": total,
        "open_alerts": open_count,
        "critical_alerts": critical_count,
        "resolved_alerts": resolved,
        "active_rules": len(rule_engine.rules),
        "active_stateful_rules": len(rule_engine.stateful_rules),
    }
