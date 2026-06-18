from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.auth.dependencies import require_threat_intel_manage
from cybernova.network.feeds.scheduler import feed_scheduler
from cybernova.network.threat_intel import threat_intel_service, IOC_DATABASE
from cybernova.network.feeds.stix_taxii import poll_taxii_feed
from cybernova.network.feeds.misp import poll_misp_feed

log = logging.getLogger("cybernova.network.feeds.router")
router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence Feeds"])


@router.get("/iocs", summary="List all IOCs in database")
async def list_iocs(
    limit: int = Query(100, le=1000),
    user: CurrentUser = Depends(get_current_user),
):
    iocs = await threat_intel_service.list_iocs()
    return {"total": len(iocs), "iocs": iocs[:limit]}


@router.post("/iocs", summary="Add IOC manually")
async def add_ioc(
    indicator: str,
    ioc_type: str,
    description: str = "",
    user: CurrentUser = Depends(require_threat_intel_manage),
):
    await threat_intel_service.add_ioc(
        indicator=indicator,
        ioc_type=ioc_type,
        metadata={"description": description, "source": "manual", "added_by": user.username},
    )
    log.info("IOC added manually by %s: %s (%s)", user.username, indicator, ioc_type)
    return {"accepted": True, "indicator": indicator, "type": ioc_type}


@router.delete("/iocs", summary="Remove IOC")
async def remove_ioc(
    indicator: str,
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.network.threat_intel import _ioc_lock
    async with _ioc_lock:
        if indicator in IOC_DATABASE:
            del IOC_DATABASE[indicator]
            log.info("IOC removed by %s: %s", user.username, indicator)
            return {"accepted": True, "indicator": indicator}
    raise HTTPException(status_code=404, detail="IOC not found")


@router.post("/feeds/poll", summary="Poll all threat intel feeds now")
async def poll_feeds(
    user: CurrentUser = Depends(require_threat_intel_manage),
):
    total = await feed_scheduler.poll_now()
    return {"accepted": True, "iocs_ingested": total, "stats": feed_scheduler.get_stats()}


@router.get("/feeds/status", summary="Feed scheduler status")
async def feed_status(
    user: CurrentUser = Depends(get_current_user),
):
    return {"running": feed_scheduler._running, **feed_scheduler.get_stats()}


@router.post("/feeds/taxii", summary="Poll specific TAXII feed")
async def poll_taxii(
    discovery_url: str,
    username: str = "",
    password: str = "",
    user: CurrentUser = Depends(require_threat_intel_manage),
):
    total = await poll_taxii_feed(discovery_url, username, password)
    return {"accepted": True, "iocs_ingested": total}


@router.post("/feeds/misp", summary="Poll specific MISP instance")
async def poll_misp(
    url: str,
    api_key: str,
    user: CurrentUser = Depends(require_threat_intel_manage),
):
    total = await poll_misp_feed(url, api_key)
    return {"accepted": True, "iocs_ingested": total}
