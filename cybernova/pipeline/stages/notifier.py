"""
CyberNova — Notification Stage
Sends notifications for triggered alerts via configured channels (email, Slack, webhook, PagerDuty).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage

log = logging.getLogger("cybernova.pipeline.stage.notifier")


class NotificationStage(PipelineStage):
    """Dispatches alert notifications through configured channels."""

    def __init__(self):
        super().__init__("notification")

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        alerts = envelope.payload.get("alerts", [])
        if not alerts:
            envelope.stage = "complete"
            return envelope

        for alert in alerts:
            try:
                await self._dispatch(alert, envelope.tenant_id)
            except Exception as e:
                log.warning("Notification dispatch failed for alert %s: %s",
                            alert.get("id", "unknown"), e)

        envelope.stage = "complete"
        return envelope

    async def _dispatch(self, alert: Dict[str, Any], tenant_id: str) -> None:
        severity = alert.get("severity", "info")
        risk_score = alert.get("risk_score", 0)
        rule_name = alert.get("rule_name", "unknown")
        description = alert.get("description", "")

        # Always log the notification
        log.info(
            "NOTIFICATION: [%s/%d] %s — %s (tenant=%s)",
            severity.upper(), risk_score, rule_name,
            description[:120], tenant_id,
        )

        # Create in-app Notification DB record for ALL alerts (medium+)
        # Users need to see every alert in the notifications panel
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_level = severity_rank.get(severity, 0)

        if sev_level >= 2:
            try:
                await self._create_db_notification(
                    tenant_id=tenant_id,
                    severity=severity,
                    rule_name=rule_name,
                    description=description,
                    risk_score=risk_score,
                    alert_id=alert.get("id", ""),
                    source_ip=alert.get("source_ip", ""),
                )
            except Exception as e:
                log.warning("Failed to create in-app notification: %s", e)

        # Broadcast real-time WebSocket notification for ALL alerts
        try:
            await self._broadcast_ws_notification(alert, tenant_id)
        except Exception as e:
            log.debug("WebSocket broadcast failed (non-critical): %s", e)

        # Only dispatch external notifications for medium+ severity
        if sev_level < 2:
            return

        # Check if notification integrations are configured
        from cybernova.config.settings import get_settings
        settings = get_settings()

        tasks = []

        # Slack webhook
        if settings.integrations_slack_webhook:
            tasks.append(self._send_slack(alert, settings))

        # Email (SMTP) — send if host is configured (password optional for local SMTP)
        if settings.smtp_host:
            tasks.append(self._send_email(alert, settings))

        # PagerDuty
        if settings.integrations_pagerduty_key:
            tasks.append(self._send_pagerduty(alert, settings))

        if tasks:
            import asyncio
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _create_db_notification(
        self,
        tenant_id: str,
        severity: str,
        rule_name: str,
        description: str,
        risk_score: float,
        alert_id: str,
        source_ip: str,
    ) -> None:
        """Create an in-app Notification record in the database.
        
        This ensures the frontend notifications panel shows real alerts,
        not just external channel dispatches.
        """
        from cybernova.database.postgres.session import get_db_session
        from cybernova.database.postgres.models import Notification
        from cybernova.core.utils.helpers import new_id
        from datetime import datetime, timezone

        type_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }

        notification = Notification(
            id=new_id(),
            tenant_id=tenant_id,
            user_id=None,  # broadcast to all users in tenant
            type=type_map.get(severity, "info"),
            title=f"[{severity.upper()}] {rule_name}",
            message=(description or "")[:2000],
            read=False,
            created_at=datetime.now(timezone.utc),
        )

        async for db in get_db_session():
            db.add(notification)
            await db.commit()
            log.debug("In-app notification created: %s for tenant=%s", rule_name, tenant_id)
            break

        # Broadcast SYSTEM_NOTIFICATION over WebSocket for real-time bell icon update
        try:
            from cybernova.api.websocket import ws_handler, WebSocketMessage, EventType
            ws_notif = WebSocketMessage(
                event_type=EventType.SYSTEM_NOTIFICATION,
                data={
                    "id": notification.id,
                    "type": type_map.get(severity, "info"),
                    "title": notification.title,
                    "message": notification.message or "",
                    "timestamp": notification.created_at.isoformat() if notification.created_at else "",
                },
                tenant_id=tenant_id,
            )
            await ws_handler._manager.send_to_tenant(
                tenant_id, ws_notif, {EventType.SYSTEM_NOTIFICATION},
            )
            log.debug("SYSTEM_NOTIFICATION broadcast for %s", rule_name)
        except Exception as e:
            log.warning("SYSTEM_NOTIFICATION broadcast failed: %s", e)

    async def _send_slack(self, alert: Dict[str, Any], settings) -> None:
        """Send alert notification to Slack webhook."""
        try:
            import httpx
            payload = {
                "text": (
                    f"*[CyberNova] {alert.get('severity', 'INFO').upper()} Alert*\n"
                    f"*Rule:* {alert.get('rule_name', 'unknown')}\n"
                    f"*Score:* {alert.get('risk_score', 0)}\n"
                    f"*Description:* {alert.get('description', '')[:500]}"
                ),
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(settings.integrations_slack_webhook, json=payload)
                resp.raise_for_status()
                log.debug("Slack notification sent for alert %s", alert.get("id"))
        except Exception as e:
            log.warning("Slack notification failed: %s", e)

    async def _send_email(self, alert: Dict[str, Any], settings) -> None:
        """Send alert notification via SMTP email."""
        try:
            import smtplib
            from email.message import EmailMessage
            import asyncio

            def _send_sync():
                msg = EmailMessage()
                msg.set_content(
                    f"Alert: {alert.get('rule_name', 'unknown')}\n\n"
                    f"Severity: {alert.get('severity', 'info')}\n"
                    f"Risk Score: {alert.get('risk_score', 0)}\n"
                    f"Description: {alert.get('description', '')}\n\n"
                    f"Source IP: {alert.get('source_ip', 'N/A')}\n"
                    f"Event ID: {alert.get('event_id', 'N/A')}\n"
                )
                msg["Subject"] = f"[CyberNova] {alert.get('severity', 'INFO').upper()} - {alert.get('rule_name', 'Alert')}"
                msg["From"] = settings.from_email or "noreply@cybernova.io"
                msg["To"] = settings.oncall_email or settings.from_email or "admin@cybernova.io"

                smtp_host = settings.smtp_host
                smtp_port = settings.smtp_port or 587
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                    # STARTTLS only if not already on a secure port or local SMTP
                    if smtp_port not in (25, 1025):
                        try:
                            server.starttls()
                        except smtplib.SMTPNotSupportedError:
                            pass
                    # Only authenticate if credentials are provided
                    if settings.smtp_user or settings.smtp_password:
                        server.login(settings.smtp_user or "", settings.smtp_password or "")
                    server.send_message(msg)

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _send_sync)
            log.debug("Email notification sent for alert %s", alert.get("id"))
        except Exception as e:
            log.warning("Email notification failed: %s", e)

    async def _send_pagerduty(self, alert: Dict[str, Any], settings) -> None:
        """Send alert to PagerDuty via Events API v2."""
        try:
            import httpx
            payload = {
                "routing_key": settings.integrations_pagerduty_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"[CyberNova] {alert.get('rule_name', 'Alert')} — {alert.get('description', '')[:120]}",
                    "severity": alert.get("severity", "info"),
                    "source": "cybernova",
                    "custom_details": {
                        "alert_id": alert.get("id"),
                        "risk_score": alert.get("risk_score", 0),
                        "event_id": alert.get("event_id"),
                        "tenant_id": alert.get("tenant_id", "default"),
                    },
                },
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                )
                resp.raise_for_status()
                log.debug("PagerDuty notification sent for alert %s", alert.get("id"))
        except Exception as e:
            log.warning("PagerDuty notification failed: %s", e)

    async def _broadcast_ws_notification(self, alert: Dict[str, Any], tenant_id: str) -> None:
        """Broadcast alert to all connected WebSocket clients for real-time UI updates."""
        from datetime import datetime, timezone
        try:
            from cybernova.api.websocket import ws_handler
            await ws_handler.broadcast_alert(
                {
                    "id": alert.get("id", ""),
                    "rule_name": alert.get("rule_name", "unknown"),
                    "severity": alert.get("severity", "medium"),
                    "risk_score": alert.get("risk_score", 0),
                    "description": alert.get("description", ""),
                    "source_ip": alert.get("source_ip", ""),
                    "dest_ip": alert.get("dest_ip", ""),
                    "event_type": alert.get("event_type", ""),
                    "alert_id": alert.get("id", ""),
                    "created_at": alert.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                },
                tenant_id,
            )
            log.debug("WebSocket broadcast sent for alert %s", alert.get("id"))
        except Exception as e:
            log.warning("WebSocket broadcast failed: %s", e)


notification_stage = NotificationStage()
