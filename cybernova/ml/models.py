from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ModelMetadata:
    version: str
    name: str
    description: str
    algorithm: str
    created_at: str
    feature_count: int
    training_samples: int
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None


@dataclass
class IsolationForestModel:
    version: str
    trees: List[Dict[str, Any]] = field(default_factory=list)
    thresholds: Dict[str, float] = field(default_factory=dict)
    feature_names: List[str] = field(default_factory=list)
    contamination: float = 0.1
    anomaly_threshold: float = 0.0


@dataclass
class InferenceResult:
    anomaly_score: float
    is_anomaly: bool
    contributing_features: List[Dict[str, Any]]
    model_version: str
    confidence: float
    timestamp: str = ""


class MLModelStore:
    def __init__(self):
        self._models: Dict[str, IsolationForestModel] = {}
        self._metadata: Dict[str, ModelMetadata] = {}

    def _key(self, model_id: str, version: Optional[str] = None) -> str:
        return f"{model_id}@{version}" if version else model_id

    def add_model(self, model_id: str, model: IsolationForestModel,
                  metadata: ModelMetadata) -> None:
        key = self._key(model_id, model.version)
        self._models[key] = model
        self._metadata[key] = metadata
        # Also store under bare model_id for backward compat
        if model.version:
            self._models.setdefault(model_id, model)
            self._metadata.setdefault(model_id, metadata)

    def get_model(self, model_id: str,
                  version: Optional[str] = None) -> Optional[IsolationForestModel]:
        key = self._key(model_id, version)
        return self._models.get(key) or self._models.get(model_id)

    def get_metadata(self, model_id: str,
                     version: Optional[str] = None) -> Optional[ModelMetadata]:
        key = self._key(model_id, version)
        return self._metadata.get(key) or self._metadata.get(model_id)

    def list_models(self) -> List[Dict[str, Any]]:
        seen = set()
        result = []
        for mid, meta in self._metadata.items():
            base_id = mid.split("@")[0]
            if base_id not in seen:
                seen.add(base_id)
                result.append({
                    "id": base_id,
                    "version": meta.version,
                    "name": meta.name,
                    "algorithm": meta.algorithm,
                    "created_at": meta.created_at,
                    "feature_count": meta.feature_count,
                    "training_samples": meta.training_samples,
                })
        return result

    def remove_model(self, model_id: str, version: Optional[str] = None) -> bool:
        key = self._key(model_id, version)
        self._models.pop(key, None)
        return self._metadata.pop(key, None) is not None


model_store = MLModelStore()
