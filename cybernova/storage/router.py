from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_retention_view, require_retention_manage
from cybernova.storage.retention import retention_manager, RetentionPolicy

log = logging.getLogger("cybernova.storage.router")
router = APIRouter(prefix="/api/v1/retention", tags=["Retention & Cold Storage"])


@router.get("/policies", summary="Get retention policies")
async def get_policies(
    user: CurrentUser = Depends(require_retention_view),
):
    return {k: v.to_dict() for k, v in retention_manager.get_policies().items()}


@router.put("/policies/{entity_type}", summary="Update retention policy")
async def update_policy(
    entity_type: str,
    policy: RetentionPolicy,
    user: CurrentUser = Depends(require_retention_manage),
):
    retention_manager.update_policy(entity_type, policy)
    return {"accepted": True, "entity_type": entity_type, "policy": policy.to_dict()}


@router.post("/run", summary="Run retention now")
async def run_retention(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_retention_manage),
):
    stats = await retention_manager.run_once(tenant_id)
    return {"accepted": True, "stats": stats}


@router.get("/stats", summary="Retention and cold storage stats")
async def retention_stats(
    user: CurrentUser = Depends(get_current_user),
):
    return retention_manager.get_stats()
