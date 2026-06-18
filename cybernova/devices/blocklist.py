"""
CyberNova — Blocklist Manager
Stores and serves the file hash blocklist for kernel-level AV.
Blocklist entries are SHA-256 hashes with severity and description.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.repository.repositories import DeviceRepository
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.auth.dependencies import require_devices_manage

log = logging.getLogger("cybernova.blocklist")

BLOCKLIST_PATH = os.environ.get("BLOCKLIST_PATH", "/data/blocklist.json")

router = APIRouter(prefix="/api/v1/blocklist", tags=["Blocklist"])
agent_router = APIRouter(prefix="/api/v1/blocklist", tags=["Agent Blocklist"])


class BlocklistEntry(BaseModel):
    hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hex hash")
    severity: int = Field(default=50, ge=0, le=100)
    description: str = Field(default="", max_length=256)


class BlocklistUpdateRequest(BaseModel):
    entries: List[BlocklistEntry]
    replace_all: bool = Field(default=True, description="Replace all existing entries")


class BlocklistResponse(BaseModel):
    version: int
    updated_at: str
    entries: List[BlocklistEntry]


def _load_blocklist() -> dict:
    path = Path(BLOCKLIST_PATH)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"version": 0, "updated_at": "", "entries": []}


def _save_blocklist(data: dict):
    path = Path(BLOCKLIST_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


@router.get("", response_model=BlocklistResponse, summary="Get current blocklist")
async def get_blocklist(
    user: CurrentUser = Depends(get_current_user),
):
    """Get the full blocklist."""
    return _load_blocklist()


@router.put("", summary="Update blocklist")
async def update_blocklist(
    request: BlocklistUpdateRequest,
    user: CurrentUser = Depends(require_devices_manage),
):
    """Replace or append to the blocklist."""
    data = _load_blocklist()
    existing = {e["hash"] for e in data["entries"]} if not request.replace_all else set()

    new_entries = []
    for entry in request.entries:
        if entry.hash not in existing or request.replace_all:
            new_entries.append(entry.model_dump())
            existing.add(entry.hash)

    data["version"] = data.get("version", 0) + 1
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    data["entries"] = new_entries if request.replace_all else data["entries"] + new_entries

    _save_blocklist(data)

    log.info("Blocklist updated: version=%d entries=%d", data["version"], len(data["entries"]))
    return {
        "status": "ok",
        "version": data["version"],
        "entries": len(data["entries"]),
    }


@router.delete("", summary="Clear blocklist")
async def clear_blocklist(
    user: CurrentUser = Depends(require_devices_manage),
):
    """Clear all entries from the blocklist."""
    data = {"version": 0, "updated_at": datetime.now(timezone.utc).isoformat(), "entries": []}
    _save_blocklist(data)
    log.info("Blocklist cleared")
    return {"status": "ok"}


# ── Agent-facing endpoint (authenticated via device token) ───────────────────


async def _authenticate_device(request, db):
    """Authenticate device from request headers (same pattern as commands.py)."""
    import hashlib
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = auth.replace("Bearer ", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    repo = DeviceRepository(db)
    device = await repo.get_by_token_hash(token_hash)
    if not device:
        raise HTTPException(status_code=401, detail="Invalid device token")
    return device


@agent_router.get("/agent", summary="Agent: Get blocklist for driver update")
async def agent_get_blocklist(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent fetches the blocklist to update the local kernel driver."""
    await _authenticate_device(request, db)
    return _load_blocklist()
