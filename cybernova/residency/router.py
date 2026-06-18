from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_residency_view, require_residency_admin
from cybernova.residency.controls import data_residency

log = logging.getLogger("cybernova.residency.router")
router = APIRouter(prefix="/api/v1/residency", tags=["Data Residency"])


@router.get("/regions", summary="List data regions")
async def list_regions(
    user: CurrentUser = Depends(require_residency_view),
):
    return {"regions": data_residency.list_regions()}


@router.get("/policies", summary="List residency policies")
async def list_policies(
    user: CurrentUser = Depends(require_residency_view),
):
    return {"policies": data_residency.get_policies()}


@router.post("/validate", summary="Validate data operation against residency rules")
async def validate_operation(
    data_classification: str,
    source_region: str,
    target_region: str,
    operation: str = Query("store"),
    user: CurrentUser = Depends(require_residency_view),
):
    result = data_residency.validate_data_operation(
        data_classification, source_region, target_region, operation,
    )
    return result


@router.post("/retention/check", summary="Check retention compliance")
async def check_retention(
    data_classification: str,
    current_retention_days: int,
    user: CurrentUser = Depends(require_residency_admin),
):
    result = data_residency.check_retention_compliance(data_classification, current_retention_days)
    return result


@router.get("/jurisdiction", summary="Get jurisdiction for a region")
async def get_jurisdiction(
    region: str,
    user: CurrentUser = Depends(require_residency_view),
):
    jurisdiction = data_residency.get_jurisdiction(region)
    return {"region": region, "jurisdiction": jurisdiction}
