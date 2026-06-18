from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.ml.models import (
    InferenceResult, IsolationForestModel, ModelMetadata, model_store,
)

log = logging.getLogger("cybernova.ml.inference")

MODEL_ID = "cybernova-default"


# ── Model Loading ─────────────────────────────────────────────────────────────

async def load_model_from_redis(redis, model_id: str = MODEL_ID) -> bool:
    """Load trained model from Redis into in-memory model_store."""
    try:
        key = f"cybernova:ml:model:{model_id}"
        meta_key = f"cybernova:ml:model:{model_id}:meta"

        raw = await redis.get(key)
        raw_meta = await redis.get(meta_key) if hasattr(redis, "get") else None
        if not raw:
            return False

        data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
        meta = {}
        if raw_meta:
            meta = json.loads(raw_meta) if isinstance(raw_meta, str) else json.loads(raw_meta.decode())

        model = IsolationForestModel(
            version=data.get("version", "unknown"),
            trees=data.get("trees", []),
            feature_names=data.get("feature_names", []),
            contamination=data.get("contamination", 0.1),
            anomaly_threshold=data.get("anomaly_threshold", 0.5),
        )

        metadata = ModelMetadata(
            version=model.version,
            name=model_id,
            description=meta.get("description", ""),
            algorithm=meta.get("algorithm", "isolation_forest"),
            created_at=meta.get("trained_at", datetime.now(timezone.utc).isoformat()),
            feature_count=len(model.feature_names),
            training_samples=meta.get("training_samples", 0),
        )

        model_store.add_model(model_id, model, metadata)
        log.info("Loaded model '%s' v%s from Redis (%d trees, %d features)",
                 model_id, model.version, len(model.trees), len(model.feature_names))
        return True
    except Exception as e:
        log.warning("Failed to load model from Redis: %s", e)
        return False


async def load_model_from_db(db: AsyncSession, model_id: str = MODEL_ID) -> bool:
    """Load active model from PostgreSQL into in-memory model_store."""
    try:
        from cybernova.database.postgres.models import ModelRegistry

        stmt = (
            select(ModelRegistry)
            .where(
                ModelRegistry.model_id == model_id,
                ModelRegistry.is_active,
            )
            .order_by(ModelRegistry.trained_at.desc())
            .limit(1)
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()
        if not entry:
            log.info("No active model '%s' found in database", model_id)
            return False

        model_data = entry.model_data or {}
        model = IsolationForestModel(
            version=entry.version,
            trees=model_data.get("trees", []),
            feature_names=entry.feature_names or [],
            contamination=model_data.get("contamination", 0.1),
            anomaly_threshold=model_data.get("anomaly_threshold", 0.5),
        )

        metadata = ModelMetadata(
            version=entry.version,
            name=model_id,
            description=entry.metadata_json.get("description", ""),
            algorithm=entry.algorithm,
            created_at=entry.trained_at.isoformat() if entry.trained_at else "",
            feature_count=len(model.feature_names),
            training_samples=entry.training_samples,
        )

        model_store.add_model(model_id, model, metadata)
        log.info("Loaded model '%s' v%s from DB (%d trees, %d features)",
                 model_id, model.version, len(model.trees), len(model.feature_names))
        return True
    except Exception as e:
        log.warning("Failed to load model from DB: %s", e)
        return False


async def refresh_active_model(redis=None, db: Optional[AsyncSession] = None,
                               model_id: str = MODEL_ID) -> bool:
    """Refresh the active model in memory — try Redis first, then DB."""
    if redis:
        try:
            if await load_model_from_redis(redis, model_id):
                return True
        except Exception as e:
            log.debug("Redis model refresh failed: %s", e)
    if db:
        try:
            if await load_model_from_db(db, model_id):
                return True
        except Exception as e:
            log.debug("Redis model refresh failed: %s", e)
    return False


# ── Core Inference ────────────────────────────────────────────────────────────

def _path_length_tree(node: Dict[str, Any], point: Dict[str, float], depth: int) -> float:
    if node.get("is_leaf"):
        size = node.get("size", 1)
        if size <= 1:
            return depth
        return depth + 2 * (math.log(size - 1) + 0.5772156649) - 2 * (size - 1) / size

    feature = node["feature"]
    split = node["split"]
    if point.get(feature, 0.0) < split:
        return _path_length_tree(node["left"], point, depth + 1)
    else:
        return _path_length_tree(node["right"], point, depth + 1)


def score_anomaly(model: IsolationForestModel, point: Dict[str, float]) -> float:
    if not model.trees or not model.feature_names:
        return 0.5

    aligned = {name: point.get(name, 0.0) for name in model.feature_names}
    path_len = sum(_path_length_tree(tree, aligned, 0) for tree in model.trees)
    avg_path = path_len / len(model.trees)
    n = model.training_samples if hasattr(model, 'training_samples') else 256
    c = 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n if n > 1 else 1
    return 2 ** (-avg_path / c) if c > 0 else 0.5


def infer(model_id: str, features: Dict[str, float],
          version: Optional[str] = None) -> Optional[InferenceResult]:
    model = model_store.get_model(model_id, version=version)
    if not model:
        log.warning("Model '%s' not found (version=%s)", model_id, version)
        return None

    anomaly_score = score_anomaly(model, features)
    is_anomaly = anomaly_score > model.anomaly_threshold

    contributing = []
    for name in model.feature_names[:10]:
        val = features.get(name, 0.0)
        if val > 0:
            contributing.append({
                "feature": name,
                "value": val,
                "contribution": round(val / max(sum(features.values()), 1), 4),
            })
    contributing.sort(key=lambda x: -x["contribution"])

    confidence = min(1.0, anomaly_score * 1.5) if is_anomaly else max(0.0, 1.0 - anomaly_score * 2)

    return InferenceResult(
        anomaly_score=round(anomaly_score, 4),
        is_anomaly=is_anomaly,
        contributing_features=contributing[:5],
        model_version=model.version,
        confidence=round(confidence, 4),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def infer_batch(model_id: str, batch: List[Dict[str, float]]) -> List[InferenceResult]:
    results = []
    for point in batch:
        result = infer(model_id, point)
        if result:
            results.append(result)
    return results


# ── Event-Level Inference ─────────────────────────────────────────────────────

def extract_features_from_event(event_data: Dict[str, Any]) -> Dict[str, float]:
    """Extract a feature vector from a normalized/enriched event dict.

    Mirrors the training pipeline's feature extraction but operates on
    a single event's extra_data and top-level fields.
    """
    from cybernova.ml.features import (
        extract_system_features, extract_process_features,
        extract_network_features, extract_file_features, combine_features,
    )

    extra = event_data.get("extra_data", {}) or event_data.get("raw_data", {})

    system_feat = extract_system_features(extra)
    process_feat = extract_process_features([])
    network_feat = extract_network_features([])
    file_feat = extract_file_features([])

    procs = []
    pname = extra.get("process_name") or event_data.get("process_name")
    if pname:
        procs.append({"name": str(pname)})
    if procs:
        process_feat = extract_process_features(procs)

    conns = []
    dip = extra.get("dest_ip") or event_data.get("dest_ip")
    if dip:
        conns.append({"remote_ip": str(dip)})
    if conns:
        network_feat = extract_network_features(conns)

    files = []
    fpath = extra.get("file_path") or event_data.get("file_path")
    if fpath:
        files.append({
            "path": str(fpath),
            "action": str(extra.get("file_action", event_data.get("file_action", "modify"))),
        })
    if files:
        file_feat = extract_file_features(files)

    return combine_features(system_feat, process_feat, network_feat, file_feat)


def infer_event(event_data: Dict[str, Any],
                model_id: str = MODEL_ID,
                version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Run ML inference on a single event. Returns serializable result dict.

    The result includes anomaly_score, is_anomaly, confidence, and
    contributing_features — suitable for embedding in pipeline payloads.
    Supports versioned model lookups for A/B testing.
    """
    features = extract_features_from_event(event_data)
    result = infer(model_id, features, version=version)
    if not result:
        return None

    return {
        "anomaly_score": result.anomaly_score,
        "is_anomaly": result.is_anomaly,
        "confidence": result.confidence,
        "model_version": result.model_version,
        "contributing_features": result.contributing_features,
        "features_used": features,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
