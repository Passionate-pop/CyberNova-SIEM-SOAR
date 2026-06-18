from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_isolation_view, require_isolation_manage
from cybernova.detection.isolation.manager import tenant_isolation

log = logging.getLogger("cybernova.detection.isolation.router")
router = APIRouter(prefix="/api/v1/isolation", tags=["Multi-Tenant Isolation"])


@router.get("/status", summary="Tenant isolation status")
async def isolation_status(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_isolation_view),
):
    return await tenant_isolation.get_tenant_status(tenant_id)


@router.get("/status/all", summary="All tenant isolation status (admin)")
async def all_isolation_status(
    user: CurrentUser = Depends(require_isolation_view),
):
    return {"tenants": await tenant_isolation.get_all_status()}


@router.post("/reset", summary="Reset tenant circuit breaker")
async def reset_circuit(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_isolation_manage),
):
    await tenant_isolation.register_tenant(tenant_id)
    log.info("Tenant %s circuit breaker reset by %s", tenant_id, user.username)
    return {"accepted": True, "tenant_id": tenant_id}
