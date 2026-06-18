"""
CyberNova — Dashboard / Analytics Service + Storage & Retention
Aggregates metrics, manages data retention, provides dashboard API.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    RawEvent, NormalizedEvent, EnrichedEvent, Alert,
    Incident, Device, ResponseAction, AuditLog,
)
from cybernova.core.utils.helpers import utcnow
from cybernova.config.constants import RETENTION_POLICY

log = logging.getLogger("cybernova.datalake")


class DatalakeService:

    async def get_metrics(self, db: AsyncSession, tenant_id: str) -> Dict[str, Any]:
        now = utcnow()
        day_ago = now - timedelta(hours=24)

        total_events = (await db.execute(
            select(func.count(NormalizedEvent.id)).where(NormalizedEvent.tenant_id == tenant_id)
        )).scalar() or 0

        events_24h = (await db.execute(
            select(func.count(NormalizedEvent.id))
            .where(NormalizedEvent.tenant_id == tenant_id, NormalizedEvent.timestamp >= day_ago)
        )).scalar() or 0

        active_alerts = (await db.execute(
            select(func.count(Alert.id))
            .where(Alert.tenant_id == tenant_id, Alert.status.in_(["new", "correlated"]))
        )).scalar() or 0

        open_incidents = (await db.execute(
            select(func.count(Incident.id))
            .where(Incident.tenant_id == tenant_id, Incident.status.in_(["new", "in_progress", "escalated"]))
        )).scalar() or 0

        active_devices = (await db.execute(
            select(func.count(Device.id)).where(Device.tenant_id == tenant_id)
        )).scalar() or 0

        sev_rows = (await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.tenant_id == tenant_id, Alert.status.in_(["new", "correlated"]))
            .group_by(Alert.severity)
        )).all()

        type_rows = (await db.execute(
            select(NormalizedEvent.event_type, func.count(NormalizedEvent.id))
            .where(NormalizedEvent.tenant_id == tenant_id, NormalizedEvent.timestamp >= day_ago)
            .group_by(NormalizedEvent.event_type)
            .order_by(func.count(NormalizedEvent.id).desc()).limit(10)
        )).all()

        pending_actions = (await db.execute(
            select(func.count(ResponseAction.id))
            .where(ResponseAction.tenant_id == tenant_id, ResponseAction.status == "pending")
        )).scalar() or 0

        return {
            "total_events": total_events, "events_last_24h": events_24h,
            "active_alerts": active_alerts, "open_incidents": open_incidents,
            "active_devices": active_devices, "pending_actions": pending_actions,
            "top_severities": {row[0]: row[1] for row in sev_rows},
            "top_event_types": {row[0]: row[1] for row in type_rows},
            "timestamp": now.isoformat(),
        }

    async def get_pipeline_status(self, db: AsyncSession, tenant_id: str) -> Dict[str, Any]:
        raw = (await db.execute(
            select(func.count(RawEvent.id)).where(RawEvent.tenant_id == tenant_id)
        )).scalar() or 0
        norm = (await db.execute(
            select(func.count(NormalizedEvent.id)).where(NormalizedEvent.tenant_id == tenant_id)
        )).scalar() or 0
        alerts = (await db.execute(
            select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)
        )).scalar() or 0
        incidents = (await db.execute(
            select(func.count(Incident.id)).where(Incident.tenant_id == tenant_id)
        )).scalar() or 0

        return {
            "ingestion": {"status": "active", "total": raw},
            "normalization": {"status": "active", "total": norm},
            "detection": {"status": "active", "alerts": alerts},
            "correlation": {"status": "active", "incidents": incidents},
        }

    async def apply_retention(self, db: AsyncSession, tenant_id: str) -> Dict[str, int]:
        now = utcnow()
        deleted = {}
        for model, name, date_col in [
            (RawEvent, "raw_events", RawEvent.received_at),
            (NormalizedEvent, "normalized_events", NormalizedEvent.normalized_at),
            (EnrichedEvent, "enriched_events", EnrichedEvent.enriched_at),
        ]:
            cutoff = now - timedelta(days=RETENTION_POLICY.get(name, 90))
            result = await db.execute(
                delete(model).where(date_col < cutoff, model.tenant_id == tenant_id)
            )
            deleted[name] = result.rowcount
            if result.rowcount:
                log.info("Retention: deleted %d from %s (tenant=%s)", result.rowcount, name, tenant_id)
        return deleted

    async def get_storage_stats(self, db: AsyncSession, tenant_id: str) -> Dict[str, int]:
        stats = {}
        for model, name in [
            (RawEvent, "raw_events"), (NormalizedEvent, "normalized_events"),
            (EnrichedEvent, "enriched_events"), (Alert, "alerts"), (AuditLog, "audit_logs"),
        ]:
            count = (await db.execute(
                select(func.count(model.id)).where(model.tenant_id == tenant_id)
            )).scalar() or 0
            stats[name] = count
        return stats


datalake_service = DatalakeService()
