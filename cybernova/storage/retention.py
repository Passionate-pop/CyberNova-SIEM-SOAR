from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.storage.retention")


@dataclass
class RetentionPolicy:
    entity_type: str
    retention_days: int
    action: str = "delete"
    cold_storage_path: str = ""
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "retention_days": self.retention_days,
            "action": self.action,
            "cold_storage_path": self.cold_storage_path,
            "enabled": self.enabled,
        }


DEFAULT_POLICIES: List[RetentionPolicy] = [
    RetentionPolicy(entity_type="raw_events", retention_days=7, action="delete"),
    RetentionPolicy(entity_type="normalized_events", retention_days=14, action="delete"),
    RetentionPolicy(entity_type="enriched_events", retention_days=14, action="delete"),
    RetentionPolicy(entity_type="alerts", retention_days=90, action="archive"),
    RetentionPolicy(entity_type="incidents", retention_days=365, action="archive"),
    RetentionPolicy(entity_type="response_actions", retention_days=365, action="archive"),
    RetentionPolicy(entity_type="audit_logs", retention_days=365, action="archive"),
    RetentionPolicy(entity_type="ioc_database", retention_days=180, action="archive"),
]


class ColdStorage:
    def __init__(self, base_path: str = "data/cold_storage"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    async def store(self, entity_type: str, tenant_id: str, records: List[Dict[str, Any]]) -> int:
        date_str = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        dest = self.base_path / entity_type / tenant_id / date_str
        dest.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
        filepath = dest / f"archive_{timestamp}.jsonl"
        count = 0
        loop = asyncio.get_running_loop()
        try:
            def _write():
                with open(filepath, "a") as f:
                    for record in records:
                        f.write(json.dumps(record, default=str) + "\n")
                return len(records)
            count = await loop.run_in_executor(None, _write)
        except Exception as e:
            log.error("Cold storage write failed: %s", e)
        return count

    async def get_archive_path(self, entity_type: str, tenant_id: str) -> str:
        path = self.base_path / entity_type / tenant_id
        return str(path)

    def get_stats(self) -> Dict[str, Any]:
        total_size = 0
        total_files = 0
        for f in self.base_path.rglob("*.jsonl"):
            try:
                total_size += f.stat().st_size
                total_files += 1
            except OSError:
                pass
        return {
            "base_path": str(self.base_path),
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }


cold_storage = ColdStorage()


ASYNC_TABLE_MAP = {
    "raw_events": "raw_events",
    "normalized_events": "normalized_events",
    "enriched_events": "enriched_events",
    "alerts": "alerts",
    "incidents": "incidents",
    "response_actions": "response_actions",
    "audit_logs": "audit_logs",
}


# Some tables use different timestamp column names than created_at
TIMESTAMP_COLUMN_MAP = {
    "raw_events": "received_at",
    "normalized_events": "timestamp",
    "enriched_events": "enriched_at",
    "alerts": "created_at",
    "incidents": "created_at",
    "response_actions": "created_at",
    "audit_logs": "timestamp",
}


class RetentionManager:
    def __init__(self):
        self._policies: Dict[str, RetentionPolicy] = {
            p.entity_type: p for p in DEFAULT_POLICIES
        }
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._stats = {
            "total_archived": 0,
            "total_deleted": 0,
            "last_run": None,
            "errors": 0,
        }

    def get_policies(self) -> Dict[str, RetentionPolicy]:
        return self._policies

    async def update_policy(self, entity_type: str, policy: RetentionPolicy) -> None:
        self._policies[entity_type] = policy
        log.info("Retention policy updated for %s: %d days (%s)", entity_type, policy.retention_days, policy.action)

    async def run_once(self, tenant_id: str = "default") -> Dict[str, int]:
        stats = {"archived": 0, "deleted": 0, "errors": 0}
        try:
            from cybernova.database.postgres.session import get_db_session
            from sqlalchemy import text

            async for db in get_db_session():
                for entity_type, policy in self._policies.items():
                    if not policy.enabled:
                        continue
                    table = ASYNC_TABLE_MAP.get(entity_type)
                    if not table:
                        continue
                    cutoff = datetime.now(timezone.utc) - timedelta(days=policy.retention_days)

                    # Use the correct timestamp column for each table
                    ts_col = TIMESTAMP_COLUMN_MAP.get(entity_type, "created_at")

                    try:
                        count = await db.execute(
                            text(f"SELECT COUNT(*) FROM {table} WHERE tenant_id = :tid AND {ts_col} < :cutoff"),  # nosec - table/column from whitelist, values parameterized
                            {"tid": tenant_id, "cutoff": cutoff},
                        )
                        total = count.scalar() or 0
                        if total == 0:
                            continue

                        if policy.action == "archive" and policy.cold_storage_path:
                            rows = await db.execute(
                                text(f"SELECT * FROM {table} WHERE tenant_id = :tid AND {ts_col} < :cutoff LIMIT 1000"),  # nosec - table/column from whitelist, values parameterized
                                {"tid": tenant_id, "cutoff": cutoff},
                            )
                            records = [dict(r._mapping) for r in rows.fetchall()]
                            archived = await cold_storage.store(entity_type, tenant_id, records)
                            stats["archived"] += archived

                        result = await db.execute(
                            text(f"DELETE FROM {table} WHERE tenant_id = :tid AND {ts_col} < :cutoff"),  # nosec - table/column from whitelist, values parameterized
                            {"tid": tenant_id, "cutoff": cutoff},
                        )
                        deleted = result.rowcount
                        stats["deleted"] += deleted
                        log.info("Retention: %s — deleted %d records older than %d days", entity_type, deleted, policy.retention_days)

                    except Exception as e:
                        log.warning("Retention error for %s: %s", entity_type, e)
                        stats["errors"] += 1

                await db.commit()
        except Exception as e:
            log.error("Retention run error: %s", e)
            stats["errors"] += 1

        self._stats["total_archived"] += stats["archived"]
        self._stats["total_deleted"] += stats["deleted"]
        self._stats["last_run"] = datetime.now(timezone.utc).isoformat()
        self._stats["errors"] += stats["errors"]
        return stats

    async def start(self, interval: int = 86400) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run_loop(interval))
        log.info("Retention manager started (interval: %ds)", interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Retention manager stopped")

    async def _run_loop(self, interval: int) -> None:
        while self._running:
            try:
                stats = await self.run_once()
                log.info("Retention cycle complete: %s", stats)
            except Exception as e:
                log.error("Retention cycle error: %s", e)
            await asyncio.sleep(interval)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "policies": {k: v.to_dict() for k, v in self._policies.items()},
            "cold_storage": cold_storage.get_stats(),
        }


retention_manager = RetentionManager()
