"""
CyberNova — Notification Service
Handles severity-based notifications:
- Low/Med: UI only (no push)
- High: App notification
- Critical: Automated action + notification
"""
from __future__ import annotations

import logging
from typing import Any, Dict
from datetime import datetime, timezone
from enum import Enum

from cybernova.config.settings import get_settings
from cybernova.soar.engine import BlockIPAction
from cybernova.integrations.registry import integration_registry

log = logging.getLogger("cybernova.notifications")


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationService:

    def __init__(self):
        self.settings = get_settings()
        self._notification_history: list = []

    def get_severity_level(self, severity: str) -> SeverityLevel:
        sev = severity.lower() if severity else "low"
        if sev in ("critical", "crit"):
            return SeverityLevel.CRITICAL
        elif sev in ("high", "hi"):
            return SeverityLevel.HIGH
        elif sev in ("medium", "med", "warn", "warning"):
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def should_notify(self, severity: str) -> bool:
        level = self.get_severity_level(severity)
        return level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)

    def should_auto_act(self, severity: str) -> bool:
        level = self.get_severity_level(severity)
        return level == SeverityLevel.CRITICAL

    async def send_notification(self, alert: Dict[str, Any]) -> bool:
        severity = alert.get("severity", "low")
        level = self.get_severity_level(severity)

        # Build notification record for ALL severity levels — low/medium get
        # persisted to the DB for UI display, while high/critical also trigger
        # push notifications.
        notification = {
            "id": alert.get("id", ""),
            "type": "alert",
            "severity": severity,
            "title": f"[{severity.upper()}] {alert.get('rule_name', 'Security Alert')}",
            "message": alert.get("description", "")[:200],
            "source_ip": alert.get("source_ip", ""),
            "dest_ip": alert.get("dest_ip", ""),
            "user": alert.get("user", ""),
            "risk_score": alert.get("risk_score", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_intel": alert.get("threat_intel", {}),
            "geo": alert.get("geo", {}),
        }

        # Persist to the notifications DB table so the UI can display them
        await self._persist_notification(alert, notification)

        # In-memory history for /api/v1/notifications/fallback and service use
        self._notification_history.append(notification)
        """
        Trim in-memory history to prevent unbounded growth.
        """
        if len(self._notification_history) > 1000:
            self._notification_history = self._notification_history[-500:]

        # Only push / auto-act for high+ severity
        if level not in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            log.debug("Low/Med severity — persisted to DB, not pushed")
            return False

        log.info("Sending push notification for %s alert: %s", severity.upper(), alert.get("rule_name", "unknown"))

        # Push to external integrations if configured
        try:
            results = await integration_registry.send_to_all("alert", notification)
            for name, success in results.items():
                log.info("Integration %s: %s", name, "sent" if success else "failed (not configured)")
        except Exception as e:
            log.warning("Failed to push notifications to integrations: %s", e)

        log.info("Notification recorded: %s", notification["title"])
        return True

    async def _persist_notification(self, alert: Dict[str, Any], notification: Dict[str, Any]) -> None:
        """Write a notification record to the database so the API can serve it."""
        try:
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import Notification as NotificationModel
            from datetime import datetime, timezone

            async for db in get_db_session():
                record = NotificationModel(
                    id=notification.get("id") or alert.get("id", ""),
                    tenant_id=alert.get("tenant_id", "default"),
                    user_id=alert.get("user_id", None),
                    type="alert",
                    title=notification["title"],
                    message=notification["message"],
                    read=False,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(record)
                # No explicit commit needed — get_db_session() auto-commits
                log.debug("Notification persisted to DB: %s", notification["title"])
        except Exception as exc:
            log.warning("Failed to persist notification to DB: %s", exc)

    def get_action_text(self, severity: str) -> str:
        level = self.get_severity_level(severity)
        if level == SeverityLevel.CRITICAL:
            return "AUTOMATED_ACTION_REQUIRED"
        elif level == SeverityLevel.HIGH:
            return "INVESTIGATE_NOW"
        return "MONITOR"

    async def execute_auto_action(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        level = self.get_severity_level(alert.get("severity", "low"))
        if level != SeverityLevel.CRITICAL:
            return {"action": "none", "status": "skipped"}

        log.warning("EXECUTING AUTOMATED ACTION for CRITICAL alert: %s", alert.get("rule_name"))

        actions_taken = []

        if alert.get("source_ip"):
            action = self._block_ip(alert["source_ip"], alert)
            actions_taken.append(action)

        return {
            "action": "automated_response",
            "status": "executed",
            "actions": actions_taken,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _block_ip(self, ip: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        log.warning("BLOCKING IP: %s - Reason: %s", ip, alert.get("rule_name"))
        action = BlockIPAction()
        incident = {
            "id": alert.get("id", ""),
            "title": alert.get("rule_name", ""),
            "severity": alert.get("severity", ""),
            "source_ip": ip,
            "dest_ip": alert.get("dest_ip", ""),
        }
        success = action.execute(incident)
        return {
            "type": "block_ip",
            "ip": ip,
            "status": "blocked" if success else "failed",
            "reason": alert.get("rule_name", "critical_threat"),
        }

    def get_recent_notifications(self, limit: int = 50) -> list:
        return self._notification_history[-limit:]

    def get_circuit_breaker_status(self) -> Dict[str, Any]:
        return {
            "push_notification": "ok",
        }


notification_service = NotificationService()
