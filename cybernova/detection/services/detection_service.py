"""
CyberNova — Detection Service
Evaluates events against rules, creates alerts, emits to event bus.
Consumes EVENT_ENRICHED or EVENT_NORMALIZED.
"""
from __future__ import annotations

import logging
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import NormalizedEvent, EnrichedEvent, Alert
from cybernova.database.repository.repositories import AlertRepository
from cybernova.detection.rules_engine.rules import rule_engine
from cybernova.detection.services.noise_control import should_suppress_alert
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics

log = logging.getLogger("cybernova.detection.service")

_EXTRA_RULES_REGISTERED = False


def _ensure_extra_rules() -> None:
    global _EXTRA_RULES_REGISTERED
    if _EXTRA_RULES_REGISTERED:
        return
    try:
        from cybernova.detection.sigma.sigma_loader import sigma_loader
        count_sigma = sigma_loader.register_all()
        log.info("Registered %d Sigma rules", count_sigma)
    except Exception as e:
        log.warning("Sigma rule registration skipped: %s", e)
    try:
        from cybernova.detection.cloud.cloud_detections import register_cloud_rules
        count_cloud = register_cloud_rules()
        log.info("Registered %d cloud detection rules", count_cloud)
    except Exception as e:
        log.warning("Cloud rule registration skipped: %s", e)
    try:
        from cybernova.detection.kubernetes.k8s_detections import register_k8s_rules
        count_k8s = register_k8s_rules()
        log.info("Registered %d Kubernetes detection rules", count_k8s)
    except Exception as e:
        log.warning("K8s rule registration skipped: %s", e)
    _EXTRA_RULES_REGISTERED = True


def _get_mitre_for_rule(rule) -> tuple:
    mitre_tactic = getattr(rule, "mitre_tactic", None) or None
    mitre_technique = getattr(rule, "mitre_technique", None) or None
    return mitre_tactic, mitre_technique


class DetectionService:

    async def scan_event(
        self, event_id: str, db: AsyncSession, tenant_id: str,
    ) -> List[Alert]:
        _ensure_extra_rules()

        result = await db.execute(
            select(EnrichedEvent).where(
                EnrichedEvent.normalized_event_id == event_id,
                EnrichedEvent.tenant_id == tenant_id,
            )
        )
        # Use scalars().first() instead of scalar_one_or_none() to handle
        # rare duplicate EnrichedEvent rows from race conditions between
        # the async pipeline and manual pipeline runs.
        enriched = result.scalars().first()

        result2 = await db.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.id == event_id,
                NormalizedEvent.tenant_id == tenant_id,
            )
        )
        normalized = result2.scalar_one_or_none()
        if not normalized:
            return []

        event_data: Dict = {
            "event_type": normalized.event_type or "",
            "severity": normalized.severity or "info",
            "source_ip": normalized.source_ip or "",
            "dest_ip": normalized.dest_ip or "",
            "protocol": normalized.protocol or "",
            "user": normalized.user or "",
            "message": normalized.message or "",
        }
        if enriched:
            event_data["risk_score"] = enriched.risk_score or 0.0

        triggered = rule_engine.evaluate(event_data)
        stateful_results = rule_engine.evaluate_stateful(event_data)

        all_results: List = []
        all_results.extend(triggered)
        for sr in stateful_results:
            if sr and sr.get("detected"):
                all_results.append(sr)

        if not all_results:
            return []

        repo = AlertRepository(db, tenant_id)
        alerts: List[Alert] = []

        for rule in all_results:
            if isinstance(rule, dict):
                rule_name = rule.get("threat_type", "stateful_detection")
                severity = rule.get("severity", "medium")
                risk_score = rule.get("risk_score", 50.0)
                description = rule.get("message", "Stateful detection triggered")
                mitre_tactic = rule.get("mitre_tactic")
                mitre_technique = rule.get("mitre_technique")
            else:
                rule_name = rule.name
                severity = rule.severity
                risk_score = rule.risk_score
                description = f"{rule.description}: {normalized.message[:200]}"
                mitre_tactic, mitre_technique = _get_mitre_for_rule(rule)

            alert = Alert(
                id=new_id(), tenant_id=tenant_id,
                event_id=enriched.id if enriched else event_id,
                device_id=normalized.device_id,
                rule_name=rule_name, severity=severity,
                risk_score=risk_score,
                description=description,
                status="new", created_at=utcnow(),
                source_ip=normalized.source_ip or "",
                dest_ip=normalized.dest_ip or "",
                user=normalized.user or "",
                event_type=normalized.event_type or "",
                raw_event=normalized.extra_data or {},
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
            )

            if await should_suppress_alert(db, tenant_id, alert):
                continue

            await repo.create(alert)
            alerts.append(alert)

            await event_producer.publish(
                Topics.ALERT_CREATED,
                {"alert_id": alert.id, "rule_name": rule_name,
                 "severity": severity, "event_id": event_id},
                tenant_id=tenant_id,
            )

            # Persist notification to DB for UI display
            try:
                from cybernova.response.notifications.notification_service import notification_service
                alert_dict = {
                    "id": alert.id,
                    "tenant_id": tenant_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "risk_score": risk_score,
                    "description": description,
                    "source_ip": normalized.source_ip or "",
                    "dest_ip": normalized.dest_ip or "",
                    "user": normalized.user or "",
                }
                await notification_service.send_notification(alert_dict)
            except Exception as notify_err:
                log.debug("Notification creation skipped for alert %s: %s", alert.id, notify_err)

        log.info("Detection: %d alerts for event %s tenant=%s", len(alerts), event_id, tenant_id)
        return alerts

    async def scan_pending(
        self, db: AsyncSession, tenant_id: str, limit: int = 100,
    ) -> List[Alert]:
        already_scanned = select(Alert.event_id).where(Alert.tenant_id == tenant_id)
        result = await db.execute(
            select(NormalizedEvent)
            .where(~NormalizedEvent.id.in_(already_scanned),
                   NormalizedEvent.tenant_id == tenant_id)
            .order_by(NormalizedEvent.timestamp.asc()).limit(limit)
        )
        events = result.scalars().all()
        all_alerts: List[Alert] = []
        for event in events:
            alerts = await self.scan_event(event.id, db, tenant_id)
            all_alerts.extend(alerts)
        log.info("Scanned %d pending events → %d alerts for tenant=%s",
                 len(events), len(all_alerts), tenant_id)
        return all_alerts


detection_service = DetectionService()
