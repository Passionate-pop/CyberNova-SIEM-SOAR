from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin, require_audit_view
from cybernova.ml.models import model_store
from cybernova.ml.service import on_device_ml

log = logging.getLogger("cybernova.ml.router")
router = APIRouter(prefix="/api/v1/ml", tags=["ML Detection"])


@router.post("/train", summary="Train a new ML model")
async def train_ml_model(
    params: Dict[str, Any],
    user: CurrentUser = Depends(require_admin),
):
    model_id = params.get("model_id", "default")
    data = params.get("data", [])
    if not data:
        raise HTTPException(status_code=400, detail="Training data required")
    result = on_device_ml.train(
        model_id=model_id,
        training_data=data,
        contamination=params.get("contamination", 0.1),
        n_trees=params.get("n_trees", 100),
    )
    return result


@router.post("/predict", summary="Run ML inference")
async def predict(
    features: Dict[str, float],
    user: CurrentUser = Depends(require_audit_view),
):
    result = on_device_ml.predict(features)
    if not result:
        raise HTTPException(status_code=400, detail="No active model set")
    return result


@router.post("/predict/telemetry", summary="Run ML inference from telemetry")
async def predict_from_telemetry(
    telemetry: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = on_device_ml.predict_from_telemetry(telemetry)
    if not result:
        raise HTTPException(status_code=400, detail="No active model set")
    return result


@router.get("/models", summary="List available ML models")
async def list_models(
    user: CurrentUser = Depends(require_audit_view),
):
    return {"models": model_store.list_models()}


@router.get("/models/{model_id}", summary="Get model details")
async def get_model(
    model_id: str,
    user: CurrentUser = Depends(require_audit_view),
):
    metadata = model_store.get_metadata(model_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="Model not found")
    model = model_store.get_model(model_id)
    return {
        "metadata": {
            "version": metadata.version,
            "name": metadata.name,
            "algorithm": metadata.algorithm,
            "created_at": metadata.created_at,
            "feature_count": metadata.feature_count,
            "training_samples": metadata.training_samples,
            "accuracy": metadata.accuracy,
        },
        "features": model.feature_names if model else [],
        "anomaly_threshold": model.anomaly_threshold if model else 0,
    }


@router.post("/models/activate", summary="Set active model")
async def activate_model(
    body: Dict[str, str],
    user: CurrentUser = Depends(require_admin),
):
    model_id = body.get("model_id", "")
    if on_device_ml.set_active_model(model_id):
        return {"activated": True, "model_id": model_id}
    raise HTTPException(status_code=404, detail="Model not found")


@router.delete("/models/{model_id}", summary="Delete a model")
async def delete_model(
    model_id: str,
    user: CurrentUser = Depends(require_admin),
):
    if model_store.remove_model(model_id):
        return {"deleted": True, "model_id": model_id}
    raise HTTPException(status_code=404, detail="Model not found")


@router.get("/stats", summary="ML engine statistics")
async def ml_stats(
    user: CurrentUser = Depends(require_audit_view),
):
    return on_device_ml.get_stats()
