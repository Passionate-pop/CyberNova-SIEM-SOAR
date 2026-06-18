from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_anomaly_view
from cybernova.detection.anomaly.detector import anomaly_detector
from cybernova.detection.anomaly.baseline import event_baseline

log = logging.getLogger("cybernova.detection.anomaly.router")
router = APIRouter(prefix="/api/v1/anomaly", tags=["Anomaly Detection"])


@router.get("/recent", summary="Recent anomaly detections")
async def recent_anomalies(
    limit: int = Query(50, le=500),
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_anomaly_view),
):
    return {"anomalies": await anomaly_detector.get_recent_anomalies(tenant_id, limit)}


@router.get("/stats", summary="Anomaly detection statistics")
async def anomaly_stats(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_anomaly_view),
):
    return await anomaly_detector.get_anomaly_stats(tenant_id)


@router.get("/baseline", summary="Event baseline stats")
async def baseline_stats(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_anomaly_view),
):
    return await event_baseline.get_stats(tenant_id)


@router.get("/unusual-ips", summary="Unusual source IPs")
async def unusual_ips(
    threshold: float = Query(3.0, ge=1.0),
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_anomaly_view),
):
    ips = await event_baseline.get_unusual_source_ips(tenant_id, threshold)
    return {"unusual_ips": ips, "threshold": threshold}


@router.get("/hourly", summary="Hourly anomaly map")
async def hourly_anomaly(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_anomaly_view),
):
    return {"hourly_anomaly": await event_baseline.get_hourly_anomaly(tenant_id)}
