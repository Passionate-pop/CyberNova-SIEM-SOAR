from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import ModelRegistry, ABTest, ABTestResult

log = logging.getLogger("cybernova.ml.model_registry")

DEFAULT_MODEL_ID = "cybernova-default"
DEFAULT_TENANT_ID = "default"


# ── Version Helpers ───────────────────────────────────────────────────────────

def _semver_sort_key(version: str) -> Tuple[int, ...]:
    """Parse semver-like '1.0.3' into sortable tuple."""
    try:
        parts = version.replace("v", "").split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return (0,)


def _compute_model_hash(model_data: Dict[str, Any]) -> str:
    """Deterministic hash of model data for change detection."""
    raw = json.dumps(model_data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Registry Manager ──────────────────────────────────────────────────────────

class ModelRegistryManager:
    """Versioned model registry with rollback and A/B testing support."""

    # ── Version Management ─────────────────────────────────────────────────

    async def list_versions(
        self,
        db: AsyncSession,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> List[Dict[str, Any]]:
        """List all registered versions for a model, newest first."""
        stmt = (
            select(ModelRegistry)
            .where(
                ModelRegistry.model_id == model_id,
                ModelRegistry.tenant_id == tenant_id,
            )
            .order_by(ModelRegistry.trained_at.desc())
        )
        result = await db.execute(stmt)
        entries = result.scalars().all()
        return [
            {
                "id": e.id,
                "version": e.version,
                "algorithm": e.algorithm,
                "feature_count": len(e.feature_names or []),
                "training_samples": e.training_samples,
                "is_active": e.is_active,
                "metrics": e.metrics or {},
                "hash": _compute_model_hash(e.model_data or {}),
                "trained_at": e.trained_at.isoformat() if e.trained_at else None,
                "metadata": e.metadata_json or {},
            }
            for e in entries
        ]

    async def get_version(
        self,
        db: AsyncSession,
        version: str,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> Optional[ModelRegistry]:
        stmt = (
            select(ModelRegistry)
            .where(
                ModelRegistry.model_id == model_id,
                ModelRegistry.tenant_id == tenant_id,
                ModelRegistry.version == version,
            )
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_version(
        self,
        db: AsyncSession,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> Optional[ModelRegistry]:
        stmt = (
            select(ModelRegistry)
            .where(
                ModelRegistry.model_id == model_id,
                ModelRegistry.tenant_id == tenant_id,
                ModelRegistry.is_active,
            )
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def register_version(
        self,
        db: AsyncSession,
        model_id: str,
        version: str,
        algorithm: str,
        feature_names: List[str],
        model_data: Dict[str, Any],
        training_samples: int,
        tenant_id: str = DEFAULT_TENANT_ID,
        metadata_json: Optional[Dict[str, Any]] = None,
        metrics: Optional[Dict[str, Any]] = None,
        activate: bool = True,
    ) -> ModelRegistry:
        """Register a new model version. Optionally activate it."""
        if activate:
            await db.execute(
                sa_update(ModelRegistry)
                .where(
                    ModelRegistry.model_id == model_id,
                    ModelRegistry.tenant_id == tenant_id,
                )
                .values(is_active=False)
            )

        entry = ModelRegistry(
            tenant_id=tenant_id,
            model_id=model_id,
            version=version,
            algorithm=algorithm,
            feature_names=feature_names,
            model_data=model_data,
            metadata_json=metadata_json or {},
            training_samples=training_samples,
            is_active=activate,
            metrics=metrics or {},
            trained_at=datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.flush()
        await db.refresh(entry)
        log.info(
            "Registered model '%s' v%s (samples=%d, features=%d, active=%s)",
            model_id, version, training_samples, len(feature_names), activate,
        )
        return entry

    async def activate_version(
        self,
        db: AsyncSession,
        version: str,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> bool:
        """Activate a specific version (rollback). Returns False if version not found."""
        target = await self.get_version(db, version, model_id, tenant_id)
        if not target:
            return False

        await db.execute(
            sa_update(ModelRegistry)
            .where(
                ModelRegistry.model_id == model_id,
                ModelRegistry.tenant_id == tenant_id,
            )
            .values(is_active=False)
        )
        target.is_active = True
        await db.flush()

        from cybernova.ml.models import model_store, IsolationForestModel, ModelMetadata

        model_data = target.model_data or {}
        model = IsolationForestModel(
            version=target.version,
            trees=model_data.get("trees", []),
            feature_names=target.feature_names or [],
            contamination=model_data.get("contamination", 0.1),
            anomaly_threshold=model_data.get("anomaly_threshold", 0.5),
        )
        metadata = ModelMetadata(
            version=target.version,
            name=model_id,
            description=target.metadata_json.get("description", ""),
            algorithm=target.algorithm,
            created_at=target.trained_at.isoformat() if target.trained_at else "",
            feature_count=len(model.feature_names),
            training_samples=target.training_samples,
        )
        model_store.add_model(model_id, model, metadata)
        log.info("Activated model '%s' v%s (rollback)", model_id, version)
        return True

    async def compare_versions(
        self,
        db: AsyncSession,
        version_a: str,
        version_b: str,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> Dict[str, Any]:
        """Compare two versions: features, params, samples, hash."""
        a = await self.get_version(db, version_a, model_id, tenant_id)
        b = await self.get_version(db, version_b, model_id, tenant_id)
        if not a or not b:
            return {"error": "One or both versions not found"}

        a_data = a.model_data or {}
        b_data = b.model_data or {}

        return {
            "version_a": {
                "version": a.version,
                "features": a.feature_names or [],
                "training_samples": a.training_samples,
                "algorithm": a.algorithm,
                "trees": len(a_data.get("trees", [])),
                "contamination": a_data.get("contamination"),
                "anomaly_threshold": a_data.get("anomaly_threshold"),
                "hash": _compute_model_hash(a_data),
                "metrics": a.metrics or {},
                "trained_at": a.trained_at.isoformat() if a.trained_at else None,
            },
            "version_b": {
                "version": b.version,
                "features": b.feature_names or [],
                "training_samples": b.training_samples,
                "algorithm": b.algorithm,
                "trees": len(b_data.get("trees", [])),
                "contamination": b_data.get("contamination"),
                "anomaly_threshold": b_data.get("anomaly_threshold"),
                "hash": _compute_model_hash(b_data),
                "metrics": b.metrics or {},
                "trained_at": b.trained_at.isoformat() if b.trained_at else None,
            },
            "differences": {
                "features_added": list(set(b.feature_names or []) - set(a.feature_names or [])),
                "features_removed": list(set(a.feature_names or []) - set(b.feature_names or [])),
                "samples_delta": (b.training_samples or 0) - (a.training_samples or 0),
                "trees_delta": len(b_data.get("trees", [])) - len(a_data.get("trees", [])),
                "contamination_changed": a_data.get("contamination") != b_data.get("contamination"),
                "threshold_changed": a_data.get("anomaly_threshold") != b_data.get("anomaly_threshold"),
                "hash_match": _compute_model_hash(a_data) == _compute_model_hash(b_data),
            },
        }

    # ── A/B Testing ────────────────────────────────────────────────────────

    async def start_ab_test(
        self,
        db: AsyncSession,
        model_id: str,
        version_a: str,
        version_b: str,
        tenant_id: str = DEFAULT_TENANT_ID,
        split_ratio: float = 0.5,
    ) -> Optional[ABTest]:
        """Start an A/B test between two model versions."""
        va = await self.get_version(db, version_a, model_id, tenant_id)
        vb = await self.get_version(db, version_b, model_id, tenant_id)
        if not va or not vb:
            log.warning("A/B test start failed: version(s) not found")
            return None

        existing = await self._get_active_ab_test(db, model_id, tenant_id)
        if existing:
            log.warning("An active A/B test already exists for model '%s'", model_id)
            return None

        test = ABTest(
            tenant_id=tenant_id,
            model_id=model_id,
            version_a=version_a,
            version_b=version_b,
            split_ratio=max(0.1, min(0.9, split_ratio)),
            is_active=True,
            started_at=datetime.now(timezone.utc),
        )
        db.add(test)
        await db.flush()
        await db.refresh(test)
        log.info(
            "A/B test %s started: %s v%s vs v%s (split=%.2f)",
            test.id, model_id, version_a, version_b, split_ratio,
        )
        return test

    async def stop_ab_test(
        self,
        db: AsyncSession,
        test_id: str,
    ) -> bool:
        """Stop an A/B test and compute final metrics."""
        stmt = select(ABTest).where(ABTest.id == test_id)
        result = await db.execute(stmt)
        test = result.scalar_one_or_none()
        if not test:
            return False

        test.is_active = False
        test.ended_at = datetime.now(timezone.utc)

        results_stmt = select(ABTestResult).where(ABTestResult.test_id == test_id)
        results_result = await db.execute(results_stmt)
        results = results_result.scalars().all()

        a_results = [r for r in results if r.model_version == test.version_a]
        b_results = [r for r in results if r.model_version == test.version_b]

        test.total_a = len(a_results)
        test.total_b = len(b_results)
        test.anomaly_rate_a = round(
            sum(1 for r in a_results if r.is_anomaly) / max(len(a_results), 1), 4,
        )
        test.anomaly_rate_b = round(
            sum(1 for r in b_results if r.is_anomaly) / max(len(b_results), 1), 4,
        )
        await db.flush()
        log.info(
            "A/B test %s stopped: A=%d(%.1f%%) B=%d(%.1f%%)",
            test_id, test.total_a, test.anomaly_rate_a * 100,
            test.total_b, test.anomaly_rate_b * 100,
        )
        return True

    async def record_ab_result(
        self,
        db: AsyncSession,
        test_id: str,
        event_id: str,
        model_version: str,
        anomaly_score: float,
        is_anomaly: bool,
        confidence: float,
        actual_outcome: Optional[str] = None,
    ) -> ABTestResult:
        result = ABTestResult(
            test_id=test_id,
            event_id=event_id,
            model_version=model_version,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            actual_outcome=actual_outcome,
        )
        db.add(result)
        return result

    async def get_ab_results(
        self,
        db: AsyncSession,
        test_id: str,
    ) -> Dict[str, Any]:
        stmt = select(ABTest).where(ABTest.id == test_id)
        result = await db.execute(stmt)
        test = result.scalar_one_or_none()
        if not test:
            return {"error": "A/B test not found"}

        results_stmt = select(ABTestResult).where(ABTestResult.test_id == test_id)
        results_result = await db.execute(results_stmt)
        results = results_result.scalars().all()

        a_entries = [r for r in results if r.model_version == test.version_a]
        b_entries = [r for r in results if r.model_version == test.version_b]

        a_scores = [r.anomaly_score for r in a_entries]
        b_scores = [r.anomaly_score for r in b_entries]

        a_mean = sum(a_scores) / max(len(a_scores), 1)
        b_mean = sum(b_scores) / max(len(b_scores), 1)

        return {
            "test_id": test_id,
            "model_id": test.model_id,
            "version_a": test.version_a,
            "version_b": test.version_b,
            "split_ratio": test.split_ratio,
            "is_active": test.is_active,
            "started_at": test.started_at.isoformat() if test.started_at else None,
            "ended_at": test.ended_at.isoformat() if test.ended_at else None,
            "results": {
                "version_a": {
                    "total": test.total_a or len(a_entries),
                    "anomaly_count": sum(1 for r in a_entries if r.is_anomaly),
                    "anomaly_rate": test.anomaly_rate_a,
                    "mean_score": round(a_mean, 4),
                },
                "version_b": {
                    "total": test.total_b or len(b_entries),
                    "anomaly_count": sum(1 for r in b_entries if r.is_anomaly),
                    "anomaly_rate": test.anomaly_rate_b,
                    "mean_score": round(b_mean, 4),
                },
            },
            "comparison": {
                "anomaly_rate_delta": round(test.anomaly_rate_a - test.anomaly_rate_b, 4),
                "winner": (
                    "version_a" if test.anomaly_rate_a < test.anomaly_rate_b
                    else "version_b" if test.anomaly_rate_b < test.anomaly_rate_a
                    else "tie"
                ),
            },
        }

    async def resolve_ab_for_event(
        self,
        db: AsyncSession,
        event_id: str,
        model_id: str = DEFAULT_MODEL_ID,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Resolve which model version to use for an event.

        If an active A/B test exists, route based on split ratio.
        Otherwise use the active model version.
        Returns (model_version, test_id).
        """
        test = await self._get_active_ab_test(db, model_id, tenant_id)
        if test:
            idx = int(hashlib.sha256(event_id.encode()).hexdigest(), 16) % 1000
            threshold = int(test.split_ratio * 1000)
            chosen = test.version_a if idx < threshold else test.version_b
            return chosen, test.id

        active = await self.get_active_version(db, model_id, tenant_id)
        if active:
            return active.version, None
        return None, None

    async def _get_active_ab_test(
        self,
        db: AsyncSession,
        model_id: str,
        tenant_id: str,
    ) -> Optional[ABTest]:
        stmt = (
            select(ABTest)
            .where(
                ABTest.model_id == model_id,
                ABTest.tenant_id == tenant_id,
                ABTest.is_active,
            )
            .order_by(ABTest.started_at.desc())
            .limit(1)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    # ── List Active A/B Tests ─────────────────────────────────────────────

    async def list_active_tests(
        self,
        db: AsyncSession,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> List[Dict[str, Any]]:
        stmt = (
            select(ABTest)
            .where(
                ABTest.tenant_id == tenant_id,
                ABTest.is_active,
            )
            .order_by(ABTest.started_at.desc())
        )
        result = await db.execute(stmt)
        tests = result.scalars().all()
        return [
            {
                "id": t.id,
                "model_id": t.model_id,
                "version_a": t.version_a,
                "version_b": t.version_b,
                "split_ratio": t.split_ratio,
                "total_a": t.total_a,
                "total_b": t.total_b,
                "started_at": t.started_at.isoformat() if t.started_at else None,
            }
            for t in tests
        ]


model_registry = ModelRegistryManager()
