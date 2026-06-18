"""
CyberNova — Correlation Stage
Correlates alerts into incidents based on shared attributes and time windows.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from datetime import datetime, timezone

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.core.utils.helpers import new_id, utcnow

log = logging.getLogger("cybernova.pipeline.stage.correlator")


class CorrelationStage(PipelineStage):
    """Correlates triggered alerts into incidents by common source IP, user, or rule."""

    def __init__(self):
        super().__init__("correlation")
        self._active_incidents: Dict[str, Dict[str, Any]] = {}

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        alerts = envelope.payload.get("alerts", [])
        if not alerts:
            envelope.stage = "alert"
            return envelope

        incidents: list = []
        grouped = self._group_alerts(alerts)

        for group_key, group_alerts in grouped.items():
            if group_key in self._active_incidents:
                inc = self._active_incidents[group_key]
                existing_ids = {a.get("id") for a in inc.get("alerts", [])}
                new_ids = [a["id"] for a in group_alerts if a["id"] not in existing_ids]
                inc["alerts"].extend(a for a in group_alerts if a["id"] not in existing_ids)
                inc["alert_count"] = len(inc["alerts"])
                inc["max_severity"] = self._max_severity(inc["alerts"])
                inc["updated_at"] = utcnow().isoformat()
                incidents.append({"incident_id": inc["id"], "title": inc.get("title", ""), "severity": inc.get("max_severity", inc.get("severity", "medium")), "risk_score": inc.get("risk_score", 0), "new_alerts": len(new_ids), "updated": True})
            else:
                max_sev = self._max_severity(group_alerts)
                inc_id = new_id()
                # Build a descriptive title from the alert descriptions
                unique_descriptions = list(dict.fromkeys(
                    a.get("description", "") for a in group_alerts if a.get("description")
                ))
                if unique_descriptions:
                    title = f"Correlated: {unique_descriptions[0][:120]}"
                    if len(unique_descriptions) > 1:
                        title += f" (+{len(unique_descriptions) - 1} related alerts)"
                else:
                    title = f"Correlated: {group_key[:100]}"
                incident = {
                    "id": inc_id,
                    "tenant_id": envelope.tenant_id,
                    "title": title,
                    "severity": max_sev,
                    "status": "new",
                    "alerts": group_alerts,
                    "alert_count": len(group_alerts),
                    "risk_score": max(a.get("risk_score", 0) for a in group_alerts),
                    "created_at": utcnow().isoformat(),
                    "updated_at": utcnow().isoformat(),
                }
                self._active_incidents[group_key] = incident
                incidents.append({"incident_id": inc_id, "title": title, "severity": max_sev, "risk_score": incident["risk_score"], "new_alerts": len(group_alerts), "updated": False})

        self._prune_old_incidents()

        envelope.payload["incidents"] = incidents
        envelope.payload["alerts"] = alerts
        envelope.stage = "alert"
        return envelope

    def _group_alerts(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = {}
        for alert in alerts:
            source_ip = alert.get("source_ip", "")
            user = alert.get("user", "")
            rule_name = alert.get("rule_name", "")

            if source_ip:
                key = f"ip:{source_ip}"
            elif user:
                key = f"user:{user}"
            else:
                key = f"rule:{rule_name}"

            if key not in groups:
                groups[key] = []
            groups[key].append(alert)
        return groups

    def _max_severity(self, alerts: List[Dict]) -> str:
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_rank = max(rank.get(a.get("severity", "info"), 0) for a in alerts)
        rev = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        return rev.get(max_rank, "info")

    def _prune_old_incidents(self) -> None:
        now = utcnow()
        stale = []
        for key, inc in self._active_incidents.items():
            created = inc.get("created_at", "")
            if created:
                try:
                    dt = datetime.fromisoformat(created)
                    # Ensure timezone-aware comparison
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if (now - dt).total_seconds() > 3600:
                        stale.append(key)
                except (ValueError, TypeError) as e:
                    log.warning("Failed to parse createdAt %s: %s", created, e)
                    stale.append(key)
        for key in stale:
            del self._active_incidents[key]


correlation_stage = CorrelationStage()
