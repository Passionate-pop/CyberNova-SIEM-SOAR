"""
CyberNova — Datalake / Dashboard Router
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, require_admin, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.datalake.service import datalake_service
from cybernova.schemas.event_schema import DeviceRegister, DeviceResponse, HeartbeatRequest
from cybernova.database.postgres.models import Device
from cybernova.database.repository.repositories import DeviceRepository
from cybernova.core.utils.helpers import new_id, utcnow

router = APIRouter(prefix="/api/v1", tags=["Datalake / Dashboard"])

@router.get("/dashboard/metrics", summary="Platform metrics")
async def metrics(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    return await datalake_service.get_metrics(db, tenant_id)


@router.get("/dashboard/pipeline", summary="Pipeline status")
async def pipeline(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    return await datalake_service.get_pipeline_status(db, tenant_id)


@router.get("/storage/stats", summary="Storage statistics")
async def storage_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    return await datalake_service.get_storage_stats(db, tenant_id)


@router.post("/storage/retention", summary="Apply retention policy (admin)")
async def apply_retention(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
    tenant_id: str = Depends(get_tenant_id),
):
    deleted = await datalake_service.apply_retention(db, tenant_id)
    return {"deleted": deleted}


# ── Device Management ────────────────────────────────────────────────────────

@router.post("/devices", summary="Register device")
async def register_device(
    body: DeviceRegister,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    device = Device(
        id=new_id(), tenant_id=tenant_id, hostname=body.hostname,
        ip_address=body.ip_address, os_type=body.os_type, os_version=body.os_version,
        agent_version=body.agent_version, tags=body.tags,
        owner_id=user.id, status="active", registered_at=utcnow(),
    )
    repo = DeviceRepository(db, tenant_id)
    await repo.create(device)
    return DeviceResponse.model_validate(device)


@router.get("/devices", summary="List devices")
async def list_devices(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = DeviceRepository(db, tenant_id)
    devices = await repo.list_all()
    return {"devices": [DeviceResponse.model_validate(d) for d in devices]}


@router.post("/devices/heartbeat", summary="Device heartbeat")
async def heartbeat(
    body: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = DeviceRepository(db, tenant_id)
    device = await repo.get_by_id(body.device_id)
    if not device:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Device not found")
    device.last_heartbeat = body.timestamp or utcnow()
    device.status = "active"
    return {"accepted": True, "device_id": body.device_id}
