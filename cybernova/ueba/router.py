from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_audit_view, require_admin
from cybernova.ueba.detector import ueba_detector
from cybernova.ueba.models import EntityType, profile_store
from cybernova.ueba.profiler import ueba_profiler
from cybernova.ueba.risk_scorer import recompute_all_risks

log = logging.getLogger("cybernova.ueba.router")
router = APIRouter(prefix="/api/v1/ueba", tags=["UEBA"])


@router.post("/analyze/login", summary="Analyze login behavior")
async def analyze_login(
    body: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = ueba_detector.analyze_login(
        entity_id=body.get("entity_id", user.id),
        entity_type=EntityType(body.get("entity_type", "user")),
        tenant_id=user.tenant_id,
        login_events=body.get("events", []),
        source_ip=body.get("source_ip", ""),
    )
    return result or {"message": "No anomalies detected"}


@router.post("/analyze/network", summary="Analyze network behavior")
async def analyze_network(
    body: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = ueba_detector.analyze_network(
        entity_id=body.get("entity_id", user.id),
        entity_type=EntityType(body.get("entity_type", "user")),
        tenant_id=user.tenant_id,
        network_events=body.get("events", []),
        source_ip=body.get("source_ip", ""),
    )
    return result or {"message": "No anomalies detected"}


@router.post("/analyze/resource", summary="Analyze resource access behavior")
async def analyze_resource(
    body: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = ueba_detector.analyze_resource(
        entity_id=body.get("entity_id", user.id),
        entity_type=EntityType(body.get("entity_type", "user")),
        tenant_id=user.tenant_id,
        resource_events=body.get("events", []),
        source_ip=body.get("source_ip", ""),
    )
    return result or {"message": "No anomalies detected"}


@router.post("/analyze/auth", summary="Analyze authentication behavior")
async def analyze_auth(
    body: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = ueba_detector.analyze_auth(
        entity_id=body.get("entity_id", user.id),
        entity_type=EntityType(body.get("entity_type", "user")),
        tenant_id=user.tenant_id,
        auth_events=body.get("events", []),
        source_ip=body.get("source_ip", ""),
    )
    return result or {"message": "No anomalies detected"}


@router.get("/profiles", summary="List entity profiles")
async def list_profiles(
    entity_type: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_audit_view),
):
    etype = EntityType(entity_type) if entity_type else None
    profiles = profile_store.list_profiles(tenant_id=user.tenant_id, entity_type=etype)
    return {
        "profiles": [
            {
                "entity_id": p.entity_id,
                "entity_type": p.entity_type.value,
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "risk_score": round(p.current_risk_score, 3),
                "risk_level": p.risk_level.value,
                "anomaly_count": p.anomaly_count,
                "total_events": p.total_events,
            }
            for p in profiles
        ]
    }


@router.get("/profiles/{entity_id}", summary="Get entity profile details")
async def get_profile(
    entity_id: str,
    user: CurrentUser = Depends(require_audit_view),
):
    profile = profile_store.get_profile(entity_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {
        "entity_id": profile.entity_id,
        "entity_type": profile.entity_type.value,
        "tenant_id": profile.tenant_id,
        "first_seen": profile.first_seen,
        "last_seen": profile.last_seen,
        "risk_score": round(profile.current_risk_score, 3),
        "risk_level": profile.risk_level.value,
        "anomaly_count": profile.anomaly_count,
        "total_events": profile.total_events,
        "baselines": {
            k: {"mean": round(b.mean, 3), "std": round(b.std, 3), "samples": b.sample_count}
            for k, b in profile.baselines.items()
        },
    }


@router.get("/alerts", summary="Get UEBA alerts")
async def get_alerts(
    limit: int = Query(100, le=500),
    user: CurrentUser = Depends(require_audit_view),
):
    return {"alerts": ueba_profiler.get_alerts(user.tenant_id, limit)}


@router.get("/timeline/{entity_id}", summary="Get entity behavior timeline")
async def get_timeline(
    entity_id: str,
    limit: int = Query(50, le=200),
    user: CurrentUser = Depends(require_audit_view),
):
    return {"events": ueba_profiler.get_entity_timeline(entity_id, limit)}


@router.post("/recompute-risk", summary="Recompute risk scores for all entities")
async def recompute_risk(
    user: CurrentUser = Depends(require_admin),
):
    results = recompute_all_risks(tenant_id=user.tenant_id)
    return {"recomputed": len(results), "results": results[:50]}


@router.get("/stats", summary="UEBA statistics")
async def ueba_stats(
    user: CurrentUser = Depends(require_audit_view),
):
    return ueba_profiler.get_stats(user.tenant_id)
