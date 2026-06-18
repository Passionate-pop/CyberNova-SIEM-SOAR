"""
CyberNova — AI Router
POST /api/v1/ai/investigate/alert/<id>
POST /api/v1/ai/investigate/incident/<id>
POST /api/v1/ai/ask
GET  /api/v1/network/iocs
POST /api/v1/network/ioc
GET  /api/v1/network/reputation/<ip>
GET  /api/v1/plugins
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.ai.investigation import investigation_service
from cybernova.ai.assistant import assistant_service
from cybernova.network.threat_intel import threat_intel_service
from cybernova.plugins.registry import plugin_registry

log = logging.getLogger("cybernova.api.routes")

router = APIRouter(prefix="/api/v1", tags=["AI & Network"])


@router.post("/ai/investigate/alert/{alert_id}", summary="AI investigate alert")
async def investigate_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    return await investigation_service.investigate_alert(alert_id, db, tenant_id)


@router.post("/ai/investigate/incident/{incident_id}", summary="AI investigate incident")
async def investigate_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    return await investigation_service.investigate_incident(incident_id, db, tenant_id)


@router.post("/ai/ask", summary="Ask AI assistant")
async def ask_ai(
    body: Dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
):
    return await assistant_service.ask(body.get("question", ""), body.get("context"))


@router.get("/network/iocs", summary="List IOCs (redirects to /api/v1/threat-intel/iocs)")
async def list_iocs(user: CurrentUser = Depends(get_current_user)):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/api/v1/threat-intel/iocs")


@router.post("/network/ioc", summary="Add IOC (deprecated — use POST /api/v1/threat-intel/iocs)")
async def add_ioc(
    body: Dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
):
    log.warning("Deprecated endpoint /api/v1/network/ioc called — use POST /api/v1/threat-intel/iocs instead")
    await threat_intel_service.add_ioc(
        body.get("indicator", ""), body.get("type", "ip"),
        body.get("metadata"),
    )
    return {"status": "added"}


@router.get("/network/reputation/{ip}", summary="IP reputation")
async def reputation(
    ip: str, user: CurrentUser = Depends(get_current_user),
):
    return await threat_intel_service.get_reputation(ip)


@router.get("/plugins", summary="List registered plugins")
async def list_plugins(user: CurrentUser = Depends(get_current_user)):
    return {"plugins": plugin_registry.list_all()}
