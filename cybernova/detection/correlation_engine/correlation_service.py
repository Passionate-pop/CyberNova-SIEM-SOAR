"""
CyberNova — Correlation Engine
Rule-based attack chain detection + time-window grouping.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from cybernova.database.postgres.models import Alert, Incident
from cybernova.database.repository.repositories import AlertRepository
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.core.event_bus.producer import event_producer
from cybernova.config.constants import Topics
from cybernova.correlation.rules_engine import rules_engine
from cybernova.correlation.incident_builder import incident_builder

log = logging.getLogger("cybernova.detection.correlation")


class CorrelationService:

    async def correlate_alerts(
        self,
        db_or_alerts: Any,
        tenant_id: str = "default",
        window_minutes: int = 15,
    ) -> List[Incident]:
        """Correlate alerts using rule-based sequence matching + time grouping."""
        if isinstance(db_or_alerts, list):
            if not db_or_alerts:
                return []
            if len(db_or_alerts) == 1 and isinstance(db_or_alerts[0], dict):
                current_alert = db_or_alerts[0]
                alerts = await self._fetch_recent_alerts(current_alert, tenant_id, window_minutes)
            else:
                alerts = db_or_alerts
        else:
            db: AsyncSession = db_or_alerts
            repo = AlertRepository(db, tenant_id)
            alerts_raw = await repo.get_uncorrelated()
            alerts = [self._alert_to_dict(a) for a in alerts_raw]
            if not alerts:
                return []

        incidents = []

        await rules_engine.load_rules(tenant_id)
        rules = rules_engine._rules.get(tenant_id, [])
        
        log.debug("Processing %d alerts for tenant=%s", len(alerts), tenant_id)
        for a in alerts[:5]:
            log.debug("Alert id=%s rule=%s event_type=%s source_ip=%s user=%s created_at=%s", 
                a.get("id"), a.get("rule_name"), a.get("event_type"), a.get("source_ip"), a.get("user"), a.get("created_at"))

        grouped = self._group_alerts_by_entity(alerts)

        # Track which alerts were matched by sequence rules so unmatched
        # high/critical alerts can trigger a fallback incident.
        matched_alert_ids: set = set()

        for entity_value, entity_alerts in grouped.items():
            for rule in rules:
                if not rule.enabled:
                    continue
                matched, confidence = await rules_engine.match_sequence(entity_alerts, rule)
                if matched:
                    incident_dict = incident_builder.build_incident(
                        rule.name, rule.description, entity_alerts, tenant_id
                    )
                    matched_local_ids = [a.get("id", "") for a in entity_alerts if a.get("id")]
                    incident = await self._create_incident(
                        incident_dict, tenant_id,
                        db=db_or_alerts if isinstance(db_or_alerts, AsyncSession) else None,
                        alert_ids=matched_local_ids,
                    )
                    if incident:
                        incidents.append(incident)
                        for a_id in matched_local_ids:
                            matched_alert_ids.add(a_id)
                    log.info(
                        "Correlation rule '%s' matched for %s (confidence=%.2f)",
                        rule.name, entity_value, confidence,
                    )

        # ── Fallback: create single-alert incidents for high/critical alerts
        #    that were NOT matched by any sequence rule.  This ensures every
        #    significant alert moves into an incident, even when the sequence
        #    pattern doesn't match.
        for a in alerts:
            alert_id = a.get("id", "")
            if alert_id in matched_alert_ids:
                continue
            severity = a.get("severity", "low").lower()
            if severity not in ("high", "critical", "crit"):
                continue
            incident_dict = incident_builder.build_incident(
                rule_name=a.get("rule_name", "Security Alert"),
                rule_description=a.get("description", ""),
                matched_alerts=[a],
                tenant_id=tenant_id,
            )
            alert_ids_list = [alert_id] if alert_id else None
            incident = await self._create_incident(
                incident_dict, tenant_id,
                db=db_or_alerts if isinstance(db_or_alerts, AsyncSession) else None,
                alert_ids=alert_ids_list,
            )
            if incident:
                incidents.append(incident)
                matched_alert_ids.add(alert_id)
                log.info(
                    "Fallback incident created for unmatched %s alert: %s (id=%s)",
                    severity, a.get("rule_name", "?"), alert_id,
                )

        if isinstance(db_or_alerts, AsyncSession):
            try:
                await db_or_alerts.commit()
            except SQLAlchemyError as e:
                log.warning("Correlation commit failed: %s", e)

        log.info("Correlation: %d incidents for tenant=%s", len(incidents), tenant_id)
        return incidents

    def _group_alerts_by_entity(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for alert in alerts:
            raw_event = alert.get("raw_event") or {}
            source_ip = alert.get("source_ip") or raw_event.get("source_ip", "")
            user = alert.get("user") or raw_event.get("user", "")
            if source_ip:
                groups[source_ip].append(alert)
            if user:
                groups[f"user:{user}"].append(alert)
        return groups

    async def _fetch_recent_alerts(
        self, current_alert: Dict[str, Any], tenant_id: str, window_minutes: int = 15
    ) -> List[Dict[str, Any]]:
        try:
            from cybernova.database.redis import get_redis
            r = await get_redis()
            if not r:
                return [current_alert]
            msgs = await r.xrevrange(
                "cybernova:alerts", "+", "-",
                count=100
            )
            alerts = []
            for msg_id, data in msgs:
                try:
                    event = json.loads(data.get("data", "{}"))
                    event["_msg_id"] = msg_id
                    alerts.append(event)
                except (json.JSONDecodeError, TypeError, ValueError) as e:
                    log.warning("Failed to decode alert JSON from Redis: %s", e)

            entity_keys = set()
            if current_alert.get("source_ip"):
                entity_keys.add(current_alert["source_ip"])
            if current_alert.get("user"):
                entity_keys.add(f"user:{current_alert['user']}")
            recent = [current_alert]
            for alert in alerts:
                if alert.get("id") == current_alert.get("id"):
                    continue
                alert_ip = alert.get("source_ip", "")
                alert_user = alert.get("user", "")
                for key in entity_keys:
                    if (key == alert_ip or key == f"user:{alert_user}") and len(recent) < 20:
                        recent.append(alert)
                        break
            return recent
        except (ConnectionError, TimeoutError, OSError, json.JSONDecodeError, TypeError, ValueError) as e:
            log.warning("Could not fetch recent alerts from Redis: %s", e)
            return [current_alert]

    def _alert_to_dict(self, alert: Alert) -> Dict[str, Any]:
        raw_event = getattr(alert, "raw_event", None) or {}
        return {
            "id": alert.id,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "user": getattr(alert, "user", ""),
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "event_type": getattr(alert, "event_type", ""),
            "description": alert.description,
            "created_at": alert.created_at.isoformat() if alert.created_at else "",
            "status": alert.status,
            "raw_event": raw_event,
        }

    async def _create_incident(
        self,
        incident_dict: Dict[str, Any],
        tenant_id: str,
        db: Optional[AsyncSession] = None,
        alert_ids: Optional[List[str]] = None,
    ) -> Optional[Incident]:
        """
        Create an incident record and mark the associated alerts as correlated.
        
        When `db` is provided (the normal path from correlate_alerts/correlate_pending),
        the incident and alert updates share the same session so a single commit
        persists everything atomically.
        """
        try:
            if db is not None:
                # Use the caller's session
                incident = Incident(
                    id=incident_dict.get("id", new_id()),
                    tenant_id=tenant_id,
                    title=incident_dict["title"],
                    severity=incident_dict["severity"],
                    risk_score=incident_dict.get("risk_score", 50.0),
                    status="new",
                    description=incident_dict.get("description", ""),
                    created_at=utcnow(),
                )
                db.add(incident)
                await db.flush()

                # Mark linked alerts as correlated so they aren't re-processed
                if alert_ids:
                    from sqlalchemy import update as sa_update
                    await db.execute(
                        sa_update(Alert)
                        .where(Alert.id.in_(alert_ids), Alert.tenant_id == tenant_id)
                        .values(incident_id=incident.id, status="correlated")
                    )
            else:
                from cybernova.database.postgres.session import get_db_session
                async for session in get_db_session():
                    incident = Incident(
                        id=incident_dict.get("id", new_id()),
                        tenant_id=tenant_id,
                        title=incident_dict["title"],
                        severity=incident_dict["severity"],
                        risk_score=incident_dict.get("risk_score", 50.0),
                        status="new",
                        description=incident_dict.get("description", ""),
                        created_at=utcnow(),
                    )
                    session.add(incident)
                    await session.commit()
                    await session.refresh(incident)

            await event_producer.publish(
                Topics.INCIDENT_CREATED,
                {
                    "incident_id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "affected_entities": incident_dict.get("affected_entities", {}),
                },
                tenant_id=tenant_id,
            )
            return incident
        except (OSError, SQLAlchemyError, KeyError, AttributeError, TypeError, ValueError) as exc:
            log.error("Failed to create incident: %s", exc)
            return None

    async def correlate_pending(
        self, db: AsyncSession, tenant_id: str,
        window_minutes: int = 15,
    ) -> List[Incident]:
        """Public entry point to correlate all uncorrelated alerts for a tenant."""
        return await self.correlate_alerts(db, tenant_id, window_minutes)


correlation_service = CorrelationService()
