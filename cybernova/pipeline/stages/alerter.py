"""
CyberNova — Alert Stage
Persists alerts and incidents to the database and publishes notifications.
"""
from __future__ import annotations

import logging
from typing import Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.database.repository.repositories import AlertRepository
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics
from cybernova.core.utils.helpers import new_id
from sqlalchemy import text

log = logging.getLogger("cybernova.pipeline.stage.alerter")


class AlertStage(PipelineStage):
    """Persists alerts and incidents, publishes to event bus."""

    def __init__(self):
        super().__init__("alert")

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        from cybernova.database.postgres.session import get_db_session

        tenant_id = envelope.tenant_id
        alerts_data = envelope.payload.get("alerts", [])
        incidents_data = envelope.payload.get("incidents", [])

        if not alerts_data and not incidents_data:
            envelope.stage = "complete"
            return envelope

        async for db in get_db_session():
            try:
                repo = AlertRepository(db, tenant_id)

                alert_mappings = []
                for alert_dict in alerts_data:
                    alert_mappings.append({
                        "id": alert_dict["id"],
                        "tenant_id": tenant_id,
                        "event_id": alert_dict.get("event_id"),
                        "rule_name": alert_dict.get("rule_name", ""),
                        "severity": alert_dict.get("severity", "medium"),
                        "risk_score": alert_dict.get("risk_score", 0.0),
                        "description": alert_dict.get("description", ""),
                        "status": "new",
                        "source_ip": alert_dict.get("source_ip", ""),
                        "dest_ip": alert_dict.get("dest_ip", ""),
                        "user": alert_dict.get("user", ""),
                        "event_type": alert_dict.get("event_type", ""),
                        "device_id": alert_dict.get("device_id", ""),
                        "extra_data": alert_dict.get("extra_data", {}),
                        "mitre_tactic": alert_dict.get("mitre_tactic"),
                        "mitre_technique": alert_dict.get("mitre_technique"),
                    })

                if alert_mappings:
                    await repo.bulk_insert(alert_mappings)

                for alert_dict in alerts_data:
                    await event_producer.publish(
                        Topics.ALERT_CREATED,
                        {"alert_id": alert_dict["id"], "rule_name": alert_dict.get("rule_name", ""),
                         "severity": alert_dict.get("severity", "medium"),
                         "event_id": alert_dict.get("event_id")},
                        tenant_id=tenant_id,
                    )

                for inc_dict in incidents_data:
                    inc_id = inc_dict.get("incident_id") or next(
                        (a.get("id") for a in alerts_data if a.get("id")), new_id()
                    )
                    # Use the descriptive title from correlation stage, not a generic one
                    inc_title = inc_dict.get("title") or f"Investigation: {inc_dict.get('description', 'Alerts correlated')}"
                    inc_detail = {
                        "id": inc_id,
                        "tenant_id": tenant_id,
                        "title": inc_title,
                        "severity": inc_dict.get("severity", "medium"),
                        "status": "new",
                        "risk_score": inc_dict.get("risk_score", 0),
                    }
                    await db.execute(
                        text("""
                            INSERT INTO incidents (id, tenant_id, title, severity, status, risk_score, created_at, updated_at)
                            VALUES (:id, :tenant_id, :title, :severity, :status, :risk_score, NOW(), NOW())
                            ON CONFLICT (id) DO UPDATE SET
                                title = EXCLUDED.title,
                                updated_at = NOW()
                        """),
                        inc_detail,
                    )

                await db.commit()
                # Note: WebSocket broadcasts happen in notification_stage to avoid duplicates

            except Exception as e:
                log.error("Alert stage DB error: %s", e)
                await db.rollback()
                raise

        envelope.stage = "soar"
        return envelope


alert_stage = AlertStage()
