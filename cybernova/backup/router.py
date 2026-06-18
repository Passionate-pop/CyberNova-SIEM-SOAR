from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin
from cybernova.backup.manager import backup_manager

log = logging.getLogger("cybernova.backup.router")
router = APIRouter(prefix="/api/v1/backup", tags=["Backup & Disaster Recovery"])


@router.post("/db", summary="Run database backup now")
async def run_db_backup(
    user: CurrentUser = Depends(require_admin),
):
    result = await backup_manager.run_db_backup()
    if result.get("status") == "failed":
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result


@router.post("/restore", summary="Restore database from backup")
async def restore_db(
    backup_file: str,
    user: CurrentUser = Depends(require_admin),
):
    result = await backup_manager.restore_db(backup_file)
    if result.get("status") == "failed":
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result


@router.get("/list", summary="List available backups")
async def list_backups(
    user: CurrentUser = Depends(require_admin),
):
    backups = await backup_manager.list_backups()
    return {"backups": backups}


@router.get("/stats", summary="Backup statistics")
async def backup_stats(
    user: CurrentUser = Depends(require_admin),
):
    return backup_manager.get_stats()
