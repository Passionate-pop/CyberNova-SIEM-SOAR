from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.auth.dependencies import require_admin, require_pipeline_manage
from cybernova.marketplace.registry import marketplace_registry, PACKAGE_TYPES

log = logging.getLogger("cybernova.marketplace.router")
router = APIRouter(prefix="/api/v1/marketplace", tags=["Marketplace"])


@router.get("/packages", summary="List marketplace packages")
async def list_packages(
    type: Optional[str] = Query(None, description="Filter by package type"),
    user: CurrentUser = Depends(get_current_user),
):
    if type and type not in PACKAGE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type: {type}. Valid types: {PACKAGE_TYPES}")
    return {"packages": marketplace_registry.list_packages(type)}


@router.get("/packages/{pkg_id}", summary="Get package details")
async def get_package(
    pkg_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    pkg = marketplace_registry.get_package(pkg_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    return pkg


@router.post("/packages/install", summary="Install a package")
async def install_package(
    package_data: Dict[str, Any],
    user: CurrentUser = Depends(require_admin),
):
    try:
        result = await marketplace_registry.install_package(package_data)
        return {"installed": True, "package": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/packages/{pkg_id}/uninstall", summary="Uninstall a package")
async def uninstall_package(
    pkg_id: str,
    user: CurrentUser = Depends(require_admin),
):
    await marketplace_registry.uninstall_package(pkg_id)
    return {"uninstalled": True}


@router.post("/packages/{pkg_id}/apply", summary="Apply a package to the system")
async def apply_package(
    pkg_id: str,
    tenant_id: str = "default",
    user: CurrentUser = Depends(require_pipeline_manage),
):
    try:
        results = await marketplace_registry.apply_package(pkg_id, tenant_id)
        return {"applied": True, "results": results}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/sync", summary="Sync packages from remote marketplace")
async def sync_marketplace(
    marketplace_url: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_admin),
):
    url = marketplace_url or "https://marketplace.cybernova.io/api/v1/packages"
    await marketplace_registry.sync_remote(url)
    return {"synced": True}
