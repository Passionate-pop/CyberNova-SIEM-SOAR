from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import NormalizedEvent, Alert, TrainingRecord
from cybernova.ml.features import (
    extract_system_features,
    extract_process_features,
    extract_network_features,
    extract_file_features,
    combine_features,
)

log = logging.getLogger("cybernova.ml.training_pipeline")


class TrainingPipeline:
    """Periodically extracts features from normalized events and stores training records.

    Runs as a background task. Queries events from a sliding time window,
    aggregates per device/tenant, extracts feature vectors, and optionally
    labels records by cross-referencing with alerts.
    """

    def __init__(
        self,
        window_minutes: int = 5,
        overlap_minutes: int = 1,
        min_events_per_window: int = 10,
    ):
        self.window_minutes = window_minutes
        self.overlap_minutes = overlap_minutes
        self.min_events_per_window = min_events_per_window
        self._last_run: Optional[datetime] = None
        self._total_records: int = 0
        self._run_count: int = 0

    async def run_once(self, db: AsyncSession) -> int:
        """Execute one training data extraction cycle. Returns records created."""
        now = datetime.now(timezone.utc)
        window_end = now - timedelta(seconds=30)
        window_start = (self._last_run or (now - timedelta(minutes=self.window_minutes + self.overlap_minutes)))

        if self._last_run:
            window_start = self._last_run - timedelta(minutes=self.overlap_minutes)

        records = await self._extract_records(db, window_start, window_end)
        if records:
            db.add_all(records)
            await db.commit()
            self._total_records += len(records)

        self._last_run = window_end
        self._run_count += 1

        if records:
            log.info(
                "training cycle #%d: window=[%s, %s] records=%d total=%d",
                self._run_count,
                window_start.isoformat(),
                window_end.isoformat(),
                len(records),
                self._total_records,
            )

        return len(records)

    async def _extract_records(
        self,
        db: AsyncSession,
        window_start: datetime,
        window_end: datetime,
    ) -> List[TrainingRecord]:
        stmt = (
            select(NormalizedEvent)
            .where(
                NormalizedEvent.timestamp >= window_start,
                NormalizedEvent.timestamp < window_end,
            )
            .order_by(NormalizedEvent.tenant_id, NormalizedEvent.device_id)
        )
        result = await db.execute(stmt)
        events = result.scalars().all()

        if not events:
            return []

        grouped: Dict[str, List[NormalizedEvent]] = {}
        for ev in events:
            group_key = f"{ev.tenant_id}:{ev.device_id or 'unknown'}"
            grouped.setdefault(group_key, []).append(ev)

        records: List[TrainingRecord] = []
        for group_key, group_events in grouped.items():
            if len(group_events) < self.min_events_per_window:
                continue

            tenant_id, device_id = group_key.split(":", 1)
            features = self._extract_features(group_events)
            label, label_source = await self._label_window(db, tenant_id, window_start, window_end, device_id)

            record = TrainingRecord(
                tenant_id=tenant_id,
                window_start=window_start,
                window_end=window_end,
                entity_type="device",
                entity_id=device_id,
                feature_vector=features,
                label=label,
                label_source=label_source,
                event_count=len(group_events),
                source="pipeline",
            )
            records.append(record)

        return records

    def _extract_features(self, events: List[NormalizedEvent]) -> Dict[str, float]:
        system_data = self._aggregate_system(events)
        process_data = self._collect_processes(events)
        network_data = self._collect_connections(events)
        file_data = self._collect_file_events(events)

        system_feat = extract_system_features(system_data)
        process_feat = extract_process_features(process_data)
        network_feat = extract_network_features(network_data)
        file_feat = extract_file_features(file_data)

        return combine_features(system_feat, process_feat, network_feat, file_feat)

    def _aggregate_system(self, events: List[NormalizedEvent]) -> Dict[str, Any]:
        cpu_vals = []
        mem_vals = []
        for ev in events:
            extra = ev.extra_data or {}
            cpu = extra.get("cpu_usage")
            mem = extra.get("memory_usage")
            if cpu is not None:
                cpu_vals.append(float(cpu))
            if mem is not None:
                mem_vals.append(float(mem))

        return {
            "cpu_usage": sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0,
            "memory_usage": sum(mem_vals) / len(mem_vals) if mem_vals else 0,
            "disk_usage": 0,
            "process_count": float(len([e for e in events if e.event_type == "process_create"])),
            "network_connections": float(len([e for e in events if e.event_type.startswith("network_")])),
        }

    def _collect_processes(self, events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
        procs = []
        for ev in events:
            if ev.event_type == "process_create":
                extra = ev.extra_data or {}
                procs.append({
                    "name": extra.get("process_name", ""),
                    "pid": extra.get("process_pid"),
                })
        return procs

    def _collect_connections(self, events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
        conns = []
        for ev in events:
            if ev.event_type in ("network_connection", "network_disconnect"):
                extra = ev.extra_data or {}
                conns.append({
                    "remote_ip": extra.get("dest_ip", ""),
                    "local_ip": extra.get("source_ip", ""),
                    "state": extra.get("connection_state"),
                })
        return conns

    def _collect_file_events(self, events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
        files = []
        for ev in events:
            if ev.event_type == "file_change":
                extra = ev.extra_data or {}
                files.append({
                    "path": extra.get("file_path", ""),
                    "action": extra.get("file_action", "modify"),
                    "file_size": extra.get("file_size"),
                })
        return files

    async def _label_window(
        self,
        db: AsyncSession,
        tenant_id: str,
        window_start: datetime,
        window_end: datetime,
        device_id: str,
    ) -> tuple[Optional[str], Optional[str]]:
        stmt = (
            select(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.device_id == device_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.severity.in_(["high", "critical"]),
            )
            .limit(1)
        )
        result = await db.execute(stmt)
        alert = result.scalar_one_or_none()
        if alert:
            return ("attack", "alert")
        return (None, None)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "run_count": self._run_count,
            "total_records": self._total_records,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "window_minutes": self.window_minutes,
        }


training_pipeline = TrainingPipeline()


async def run_training_cycle(db: AsyncSession) -> int:
    """Convenience wrapper called by the scheduler."""
    return await training_pipeline.run_once(db)
