"""
CyberNova — Suppression Router
API for managing suppression rules and checking alert suppression status.
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import (
    require_alerts_view, require_settings_view, require_settings_update,
)
from cybernova.suppression.engine import suppression_engine
from cybernova.suppression.models import (
    SuppressionRule, SuppressionType, SuppressionScope,
)

log = logging.getLogger("cybernova.suppression.router")
router = APIRouter(prefix="/api/v1/suppression", tags=["Alert Suppression"])


class SuppressionRuleResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str = ""
    type: str
    scope: str = "tenant"
    pattern: str = ""
    severity_threshold: Optional[str] = None
    risk_score_min: float = 0.0
    risk_score_max: float = 100.0
    window_minutes: int = 60
    max_count: int = 0
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""


class CreateSuppressionRequest(BaseModel):
    name: str
    description: str = ""
    type: str = "rule"
    scope: str = "tenant"
    pattern: str = ""
    severity_threshold: Optional[str] = None
    risk_score_min: float = 0.0
    risk_score_max: float = 100.0
    window_minutes: int = 60
    max_count: int = 0
    enabled: bool = True


class UpdateSuppressionRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    pattern: Optional[str] = None
    severity_threshold: Optional[str] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None
    window_minutes: Optional[int] = None
    max_count: Optional[int] = None
    enabled: Optional[bool] = None


class SuppressionCheckRequest(BaseModel):
    rule_name: str
    source_ip: str = ""
    severity: str = "info"
    risk_score: float = 0.0
    event_type: str = ""
    description: str = ""
    tenant_id: str = "default"


@router.get("/rules", summary="List suppression rules")
async def list_suppression_rules(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_settings_view),
):
    rules = await suppression_engine.list_rules(tenant_id)
    return {"rules": [r.to_dict() for r in rules], "total": len(rules)}


@router.post("/rules", summary="Create suppression rule")
async def create_suppression_rule(
    req: CreateSuppressionRequest,
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_settings_update),
):
    try:
        rule_type = SuppressionType(req.type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid type: {req.type}")

    try:
        scope = SuppressionScope(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")

    now = datetime.now(timezone.utc).isoformat()
    rule = SuppressionRule(
        id=str(uuid4()),
        tenant_id=tenant_id,
        name=req.name,
        description=req.description,
        type=rule_type,
        scope=scope,
        pattern=req.pattern,
        severity_threshold=req.severity_threshold,
        risk_score_min=req.risk_score_min,
        risk_score_max=req.risk_score_max,
        window_minutes=req.window_minutes,
        max_count=req.max_count,
        enabled=req.enabled,
        created_at=now,
        updated_at=now,
    )
    await suppression_engine.add_rule(rule)
    log.info("Created suppression rule '%s' (%s) for tenant %s", rule.name, rule.type.value, tenant_id)
    return rule.to_dict()


@router.get("/rules/{rule_id}", summary="Get suppression rule")
async def get_suppression_rule(
    rule_id: str,
    user: CurrentUser = Depends(require_settings_view),
):
    rule = await suppression_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    return rule.to_dict()


@router.put("/rules/{rule_id}", summary="Update suppression rule")
async def update_suppression_rule(
    rule_id: str,
    req: UpdateSuppressionRequest,
    user: CurrentUser = Depends(require_settings_update),
):
    rule = await suppression_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    if req.name is not None:
        rule.name = req.name
    if req.description is not None:
        rule.description = req.description
    if req.type is not None:
        try:
            rule.type = SuppressionType(req.type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid type: {req.type}")
    if req.pattern is not None:
        rule.pattern = req.pattern
    if req.severity_threshold is not None:
        rule.severity_threshold = req.severity_threshold
    if req.risk_score_min is not None:
        rule.risk_score_min = req.risk_score_min
    if req.risk_score_max is not None:
        rule.risk_score_max = req.risk_score_max
    if req.window_minutes is not None:
        rule.window_minutes = req.window_minutes
    if req.max_count is not None:
        rule.max_count = req.max_count
    if req.enabled is not None:
        rule.enabled = req.enabled

    rule.updated_at = datetime.now(timezone.utc).isoformat()
    await suppression_engine.update_rule(rule)
    return rule.to_dict()


@router.delete("/rules/{rule_id}", summary="Delete suppression rule")
async def delete_suppression_rule(
    rule_id: str,
    user: CurrentUser = Depends(require_settings_update),
):
    deleted = await suppression_engine.remove_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    return {"deleted": True, "rule_id": rule_id}


@router.post("/check", summary="Check if an alert would be suppressed")
async def check_suppression(
    req: SuppressionCheckRequest,
    user: CurrentUser = Depends(require_alerts_view),
):
    alert = {
        "rule_name": req.rule_name,
        "source_ip": req.source_ip,
        "severity": req.severity,
        "risk_score": req.risk_score,
        "event_type": req.event_type,
        "description": req.description,
    }
    match = await suppression_engine.evaluate(alert, req.tenant_id)
    return {
        "suppressed": match.suppressed,
        "rule_id": match.rule_id,
        "reason": match.reason,
        "suppressed_count": match.suppressed_count,
    }


@router.get("/stats", summary="Suppression statistics")
async def suppression_stats(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_settings_view),
):
    rules = await suppression_engine.list_rules(tenant_id)
    enabled = sum(1 for r in rules if r.enabled)
    by_type = {}
    for r in rules:
        by_type[r.type.value] = by_type.get(r.type.value, 0) + 1
    return {
        "total_rules": len(rules),
        "enabled": enabled,
        "disabled": len(rules) - enabled,
        "by_type": by_type,
    }
