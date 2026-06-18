from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from cybernova.ml.features import combine_features, extract_system_features
from cybernova.ml.inference import infer
from cybernova.ml.models import InferenceResult, model_store
from cybernova.ml.trainer import train_model

log = logging.getLogger("cybernova.ml.service")


class OnDeviceMLService:
    def __init__(self):
        self._active_model_id: Optional[str] = None
        self._inference_history: Dict[str, List[InferenceResult]] = defaultdict(list)

    @property
    def active_model_id(self) -> Optional[str]:
        return self._active_model_id

    def set_active_model(self, model_id: str) -> bool:
        if model_store.get_model(model_id):
            self._active_model_id = model_id
            log.info("Active ML model set to '%s'", model_id)
            return True
        return False

    def train(self, model_id: str, training_data: List[Dict[str, float]], **kwargs) -> Dict[str, Any]:
        model = train_model(model_id, training_data, **kwargs)
        metadata = model_store.get_metadata(model_id)
        return {
            "model_id": model_id,
            "version": model.version,
            "features": model.feature_names,
            "samples": metadata.training_samples if metadata else 0,
        }

    def predict(self, features: Dict[str, float]) -> Optional[Dict[str, Any]]:
        if not self._active_model_id:
            return None
        result = infer(self._active_model_id, features)
        if result:
            self._inference_history[self._active_model_id].append(result)
            return {
                "anomaly_score": result.anomaly_score,
                "is_anomaly": result.is_anomaly,
                "contributing_features": result.contributing_features,
                "confidence": result.confidence,
                "model_version": result.model_version,
            }
        return None

    def predict_from_telemetry(self, telemetry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        system = telemetry.get("system", {})
        processes = telemetry.get("processes", [])
        connections = telemetry.get("connections", [])
        file_events = telemetry.get("file_events", [])

        features = combine_features(
            system=extract_system_features(system),
            process={},
            network={},
            file_feat={},
        )
        features["process_count"] = float(len(processes))
        features["connection_count"] = float(len(connections))
        features["file_event_count"] = float(len(file_events))

        return self.predict(features)

    def get_stats(self) -> Dict[str, Any]:
        total = sum(len(v) for v in self._inference_history.values())
        anomalies = sum(
            1 for results in self._inference_history.values()
            for r in results if r.is_anomaly
        )
        return {
            "active_model": self._active_model_id,
            "available_models": len(model_store.list_models()),
            "total_inferences": total,
            "total_anomalies": anomalies,
            "anomaly_rate": round(anomalies / max(total, 1), 4),
        }


on_device_ml = OnDeviceMLService()
ml_service = on_device_ml
