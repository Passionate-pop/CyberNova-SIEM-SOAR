from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.auth.dependencies import require_admin
from cybernova.multi_region.config import region_config, REGIONS
from cybernova.multi_region.replication import cross_region_replicator

log = logging.getLogger("cybernova.multi_region.router")
router = APIRouter(prefix="/api/v1/multi-region", tags=["Multi-Region Deployment"])


class EventsPayload(BaseModel):
    source_region: str
    events: List[Dict[str, Any]]
    forwarded_at: str = ""


@router.get("/status", summary="Multi-region deployment status")
async def multi_region_status(
    user: CurrentUser = Depends(require_admin),
):
    return {
        "enabled": region_config.enabled,
        "current_region": region_config.current_region,
        "region_name": REGIONS.get(region_config.current_region, "Unknown"),
        "peer_regions": [
            {"id": r, "name": REGIONS.get(r, "Unknown")}
            for r in region_config.peer_regions
        ],
        "replication": cross_region_replicator.get_stats(),
    }


@router.post("/events", summary="Receive replicated events from peer region")
async def receive_replicated_events(
    payload: EventsPayload,
):
    count = await cross_region_replicator.receive_events(payload.events)
    return {
        "accepted": count,
        "source_region": payload.source_region,
        "region": region_config.current_region,
    }


@router.get("/regions", summary="List all known regions")
async def list_regions(
    user: CurrentUser = Depends(get_current_user),
):
    return {
        "regions": [{"id": k, "name": v} for k, v in REGIONS.items()],
        "current": region_config.current_region,
    }


@router.post("/forward", summary="Forward an event to peer regions")
async def forward_event(
    event: Dict[str, Any],
    user: CurrentUser = Depends(require_admin),
):
    await cross_region_replicator.forward_event(event)
    return {"forwarded": True}
