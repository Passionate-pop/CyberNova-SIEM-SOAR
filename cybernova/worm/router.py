from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_worm_write, require_worm_view, require_worm_verify
from cybernova.worm.storage import worm_storage

log = logging.getLogger("cybernova.worm.router")
router = APIRouter(prefix="/api/v1/worm", tags=["WORM Storage"])


@router.post("/write", summary="Write audit log to WORM storage")
async def write_worm_log(
    log_entry: dict,
    tenant_id: str = "default",
    user: CurrentUser = Depends(require_worm_write),
):
    entry_hash = await worm_storage.write_log(log_entry, tenant_id)
    return {"hash": entry_hash, "written": True}


@router.get("/entries", summary="List WORM entries")
async def list_worm_entries(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    user: CurrentUser = Depends(require_worm_view),
):
    return {
        "entries": worm_storage.get_entries(tenant_id or "", limit, offset),
        "total": len(worm_storage.get_entries(tenant_id or "")),
    }


@router.get("/entries/{entry_hash}", summary="Get WORM entry by hash")
async def get_worm_entry(
    entry_hash: str,
    user: CurrentUser = Depends(require_worm_view),
):
    entry = worm_storage.get_entry_by_hash(entry_hash)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry


@router.post("/verify", summary="Verify WORM chain integrity")
async def verify_worm_chain(
    user: CurrentUser = Depends(require_worm_verify),
):
    result = await worm_storage.verify_chain_integrity()
    return result


@router.get("/stats", summary="WORM storage statistics")
async def worm_stats(
    user: CurrentUser = Depends(require_worm_view),
):
    return worm_storage.get_stats()
