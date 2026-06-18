from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_cspm_view, require_cspm_scan
from cybernova.cspm.scanner import cspm_scanner

log = logging.getLogger("cybernova.cspm.router")
router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])


@router.get("/providers", summary="List supported providers")
async def list_providers(
    user: CurrentUser = Depends(require_cspm_view),
):
    return {"providers": cspm_scanner.get_providers()}


@router.get("/rules", summary="List CSPM rules")
async def list_rules(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    user: CurrentUser = Depends(require_cspm_view),
):
    return {"rules": cspm_scanner.get_rules(provider)}


@router.post("/scan", summary="Run a CSPM scan")
async def run_cspm_scan(
    provider: str = Query("kubernetes", description="Provider to scan"),
    region: str = Query("local", description="Region to scan"),
    user: CurrentUser = Depends(require_cspm_scan),
):
    result = await cspm_scanner.run_scan(provider, region)
    return result


@router.get("/history", summary="Get scan history")
async def scan_history(
    user: CurrentUser = Depends(require_cspm_view),
):
    return {"scans": cspm_scanner.get_scan_history()}


@router.get("/stats", summary="CSPM statistics")
async def cspm_stats(
    user: CurrentUser = Depends(require_cspm_view),
):
    return cspm_scanner.get_stats()
