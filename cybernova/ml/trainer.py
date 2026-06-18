from __future__ import annotations

import logging
import math
import random  # nosec - used for train/test split, not security
from datetime import datetime, timezone
from typing import Any, Dict, List

from cybernova.ml.models import (
    IsolationForestModel, ModelMetadata, model_store,
)

log = logging.getLogger("cybernova.ml.trainer")


class IsolationForest:
    def __init__(self, n_trees: int = 100, max_samples: int = 256, contamination: float = 0.1):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees: List[Dict[str, Any]] = []
        self.feature_names: List[str] = []
        self._anomaly_scores: List[float] = []

    def fit(self, X: List[Dict[str, float]]) -> None:
        if not X:
            return
        self.feature_names = list(X[0].keys())
        n_features = len(self.feature_names)

        for _ in range(self.n_trees):
            sample_size = min(self.max_samples, len(X))
            sample = random.sample(X, sample_size)  # nosec
            tree = self._build_tree(sample, 0, int(math.log2(sample_size)) + 1, n_features)
            self.trees.append(tree)

        self._anomaly_scores = [self._path_length(x, 0) for x in X]
        scores = [self.score(x) for x in X]
        scores.sort()
        threshold_idx = int(len(scores) * (1 - self.contamination))
        self._anomaly_threshold = scores[threshold_idx] if threshold_idx < len(scores) else 0.5

    def _build_tree(self, data: List[Dict[str, float]], depth: int, max_depth: int, n_features: int) -> Dict[str, Any]:
        if depth >= max_depth or len(data) <= 1:
            return {"size": len(data), "is_leaf": True}
        feature_idx = random.randrange(n_features)  # nosec
        feature_name = self.feature_names[feature_idx]
        values = [x.get(feature_name, 0.0) for x in data]
        min_val, max_val = min(values), max(values)

        if min_val == max_val:
            return {"size": len(data), "is_leaf": True}

        split_val = random.uniform(min_val, max_val)  # nosec
        left = [x for x in data if x.get(feature_name, 0.0) < split_val]
        right = [x for x in data if x.get(feature_name, 0.0) >= split_val]

        if not left or not right:
            return {"size": len(data), "is_leaf": True}

        return {
            "feature": feature_name,
            "split": split_val,
            "left": self._build_tree(left, depth + 1, max_depth, n_features),
            "right": self._build_tree(right, depth + 1, max_depth, n_features),
            "is_leaf": False,
        }

    def _path_length(self, point: Dict[str, float], depth: int) -> float:
        avg_length = 0.0
        for tree in self.trees:
            avg_length += self._tree_path(tree, point, 0)
        return avg_length / len(self.trees)

    def _tree_path(self, node: Dict[str, Any], point: Dict[str, float], depth: int) -> float:
        if node.get("is_leaf"):
            size = node.get("size", 1)
            if size <= 1:
                return depth
            return depth + 2 * (math.log(size - 1) + 0.5772156649) - 2 * (size - 1) / size

        feature = node["feature"]
        split = node["split"]

        if point.get(feature, 0.0) < split:
            return self._tree_path(node["left"], point, depth + 1)
        else:
            return self._tree_path(node["right"], point, depth + 1)

    def score(self, point: Dict[str, float]) -> float:
        path_len = self._path_length(point, 0)
        n = len(self._anomaly_scores) if self._anomaly_scores else 1
        c = 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n if n > 1 else 1
        return 2 ** (-path_len / c) if c > 0 else 0.5


def train_model(
    model_id: str,
    training_data: List[Dict[str, float]],
    contamination: float = 0.1,
    n_trees: int = 100,
) -> IsolationForestModel:
    forest = IsolationForest(n_trees=n_trees, contamination=contamination)
    forest.fit(training_data)

    model = IsolationForestModel(
        version=f"1.0.{len(model_store.list_models()) + 1}",
        trees=forest.trees,
        feature_names=forest.feature_names,
        contamination=contamination,
        anomaly_threshold=0.5,
    )

    metadata = ModelMetadata(
        version=model.version,
        name=model_id,
        description=f"Isolation Forest model with {n_trees} trees",
        algorithm="isolation_forest",
        created_at=datetime.now(timezone.utc).isoformat(),
        feature_count=len(forest.feature_names),
        training_samples=len(training_data),
    )

    model_store.add_model(model_id, model, metadata)
    log.info("Trained model '%s' v%s on %d samples with %d features",
             model_id, model.version, len(training_data), len(forest.feature_names))
    return model
