import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_cloud_view, require_cloud_ingest
from cybernova.cloud.k8s_audit import k8s_audit_ingestion

log = logging.getLogger("cybernova.cloud.router")
router = APIRouter(prefix="/api/v1/cloud", tags=["Cloud Security"])


@router.post("/k8s/audit", summary="Ingest Kubernetes audit event")
async def ingest_k8s_audit(
    event: Dict[str, Any],
    tenant_id: str = "default",
    user: CurrentUser = Depends(require_cloud_ingest),
):
    event_id = await k8s_audit_ingestion.ingest_audit_event(event, tenant_id)
    return {"accepted": True, "event_id": event_id}


@router.post("/k8s/webhook", summary="Kubernetes audit webhook receiver (batch)")
async def k8s_audit_webhook(
    request: Request,
    body: Dict[str, Any],
    tenant_id: str = "default",
):
    signature = request.headers.get("X-CyberNova-Signature", "")
    timestamp = request.headers.get("X-CyberNova-Timestamp", "")
    if signature and timestamp:
        from cybernova.security.webhook_security import WebhookSigner
        verifier = WebhookSigner()
        valid, reason = verifier.verify(body, signature, timestamp)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Invalid HMAC signature: {reason}")

    result = await k8s_audit_ingestion.ingest_from_webhook(body, tenant_id)
    return result


@router.get("/k8s/rules", summary="Get K8s detection rules")
async def get_k8s_rules(
    user: CurrentUser = Depends(require_cloud_view),
):
    return {"rules": k8s_audit_ingestion.get_detection_rules()}


@router.get("/stats", summary="Cloud ingestion statistics")
async def cloud_stats(
    user: CurrentUser = Depends(require_cloud_view),
):
    return {
        "k8s": k8s_audit_ingestion.get_stats(),
    }
