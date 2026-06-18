from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import TrainingRecord, ModelRegistry
from cybernova.ml.trainer import train_model
from cybernova.ml.models import model_store, IsolationForestModel

log = logging.getLogger("cybernova.ml.scheduler")

MODEL_ID = "cybernova-default"
REDIS_MODEL_KEY = f"cybernova:ml:model:{MODEL_ID}"
REDIS_META_KEY = f"cybernova:ml:model:{MODEL_ID}:meta"
TRAINING_WINDOW_DAYS = 7
MIN_SAMPLES = 50


class TrainingScheduler:
    """Periodically trains ML models from accumulated training records.

    Runs every 24h. Pulls training_records from the last 7 days,
    trains an Isolation Forest, and persists to Redis + model_registry table.
    """

    def __init__(self):
        self._last_run: Optional[datetime] = None
        self._run_count: int = 0
        self._task = None

    async def train_once(self, db: AsyncSession, redis=None) -> Optional[str]:
        """Execute one training cycle. Returns model version or None."""
        stmt = (
            select(TrainingRecord)
            .where(
                TrainingRecord.recorded_at >= datetime.now(timezone.utc) - timedelta(days=TRAINING_WINDOW_DAYS),
            )
            .order_by(TrainingRecord.recorded_at.desc())
        )
        result = await db.execute(stmt)
        records = result.scalars().all()

        if len(records) < MIN_SAMPLES:
            log.info(
                "training skipped: %d records < %d minimum",
                len(records), MIN_SAMPLES,
            )
            return None

        training_data = []
        for r in records:
            fv = r.feature_vector or {}
            training_data.append(fv)

        version = f"1.0.{self._run_count + 1}"
        model: IsolationForestModel = train_model(
            model_id=MODEL_ID,
            training_data=training_data,
            contamination=0.1,
            n_trees=100,
        )

        await self._persist_to_db(db, records, model, version)
        if redis:
            await self._persist_to_redis(redis, model, version, records)

        self._last_run = datetime.now(timezone.utc)
        self._run_count += 1
        log.info(
            "model trained: version=%s samples=%d features=%d trees=%d",
            version, len(training_data), len(model.feature_names), len(model.trees),
        )
        return version

    async def _persist_to_db(
        self,
        db: AsyncSession,
        records: List[TrainingRecord],
        model: IsolationForestModel,
        version: str,
    ) -> None:
        model_data = {
            "trees": model.trees,
            "feature_names": model.feature_names,
            "contamination": model.contamination,
            "anomaly_threshold": model.anomaly_threshold,
        }
        model_store.get_metadata(MODEL_ID)

        entry = ModelRegistry(
            tenant_id="default",
            model_id=MODEL_ID,
            version=version,
            algorithm="isolation_forest",
            feature_names=model.feature_names,
            model_data=model_data,
            metadata_json={
                "name": MODEL_ID,
                "description": f"Isolation Forest trained on {len(records)} records",
                "trees": len(model.trees),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            training_samples=len(records),
            is_active=True,
            metrics={
                "contamination": model.contamination,
                "feature_count": len(model.feature_names),
                "training_window_days": TRAINING_WINDOW_DAYS,
            },
        )

        await db.execute(
            select(ModelRegistry).where(
                ModelRegistry.model_id == MODEL_ID,
                ModelRegistry.is_active,
            )
        )
        await db.execute(
            ModelRegistry.__table__.update()
            .where(ModelRegistry.model_id == MODEL_ID)
            .values(is_active=False)
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)

    async def _persist_to_redis(
        self,
        redis,
        model: IsolationForestModel,
        version: str,
        records: List[TrainingRecord],
    ) -> None:
        try:
            model_payload = {
                "version": version,
                "trees": model.trees,
                "feature_names": model.feature_names,
                "contamination": model.contamination,
                "anomaly_threshold": model.anomaly_threshold,
            }
            meta_payload = {
                "model_id": MODEL_ID,
                "version": version,
                "training_samples": len(records),
                "feature_count": len(model.feature_names),
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "algorithm": "isolation_forest",
            }
            await redis.set(REDIS_MODEL_KEY, json.dumps(model_payload))
            await redis.set(REDIS_META_KEY, json.dumps(meta_payload))
            log.info("model persisted to Redis: key=%s", REDIS_MODEL_KEY)
        except Exception as e:
            log.warning("Redis persistence failed: %s", e)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "run_count": self._run_count,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "model_id": MODEL_ID,
            "training_window_days": TRAINING_WINDOW_DAYS,
            "min_samples": MIN_SAMPLES,
        }


training_scheduler = TrainingScheduler()
