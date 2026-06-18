from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_audit_view, require_admin
from cybernova.detection.ransomware.chain import ransomware_chain
from cybernova.detection.ransomware.indicators import (
    ALL_INDICATORS, STAGE_NAMES,
)

log = logging.getLogger("cybernova.detection.ransomware.router")
router = APIRouter(prefix="/api/v1/detection/ransomware", tags=["Ransomware Detection"])


@router.post("/analyze", summary="Analyze event for ransomware indicators")
async def analyze_event(
    event: Dict[str, Any],
    tenant_id: str = "default",
    user: CurrentUser = Depends(require_audit_view),
):
    result = ransomware_chain.analyze_event(event, tenant_id)
    if not result:
        return {"message": "No ransomware indicators detected", "indicators_fired": 0}
    return result


@router.get("/chains/active", summary="Get active ransomware detection chains")
async def get_active_chains(
    user: CurrentUser = Depends(require_audit_view),
):
    return {"chains": ransomware_chain.get_active_chains(user.tenant_id)}


@router.get("/chains/concluded", summary="Get concluded ransomware cases")
async def get_concluded_chains(
    limit: int = Query(50, le=200),
    user: CurrentUser = Depends(require_audit_view),
):
    return {"chains": ransomware_chain.get_concluded_chains(user.tenant_id, limit)}


@router.get("/chains/{entity_id}", summary="Get ransomware chain for entity")
async def get_chain(
    entity_id: str,
    user: CurrentUser = Depends(require_audit_view),
):
    chain = ransomware_chain.get_chain(entity_id)
    if not chain:
        raise HTTPException(status_code=404, detail="No active chain found for entity")
    return chain


@router.post("/chains/{entity_id}/conclude", summary="Conclude a ransomware detection chain")
async def conclude_chain(
    entity_id: str,
    user: CurrentUser = Depends(require_admin),
):
    verdict = ransomware_chain.conclude_chain(entity_id)
    if not verdict:
        raise HTTPException(status_code=404, detail="No active chain found for entity")
    return verdict


@router.get("/indicators", summary="List all ransomware indicators")
async def list_indicators(
    stage: Optional[int] = Query(None),
    user: CurrentUser = Depends(require_audit_view),
):
    indicators = ALL_INDICATORS
    if stage is not None:
        indicators = [i for i in indicators if i.stage == stage]
    return {
        "indicators": [
            {
                "name": i.name,
                "description": i.description,
                "stage": i.stage,
                "stage_name": STAGE_NAMES.get(i.stage, ""),
                "weight": i.weight,
                "mitre_technique": i.mitre_technique,
                "mitre_id": i.mitre_id,
            }
            for i in indicators
        ]
    }


@router.get("/stats", summary="Ransomware detection statistics")
async def ransomware_stats(
    user: CurrentUser = Depends(require_audit_view),
):
    return ransomware_chain.get_stats()
