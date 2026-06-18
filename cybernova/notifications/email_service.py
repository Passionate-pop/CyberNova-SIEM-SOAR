"""
CyberNova — Email Notification Service
Sends alerts and incident notifications via SMTP (free).
"""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
from dataclasses import dataclass

from cybernova.config.settings import get_settings
from cybernova.database.postgres.models import User

log = logging.getLogger("cybernova.notifications")
settings = get_settings()


@dataclass
class EmailNotification:
    to: str
    subject: str
    body: str
    html: Optional[str] = None
    priority: str = "normal"


class EmailService:
    def __init__(self):
        self.smtp_host = getattr(settings, 'smtp_host', '')
        self.smtp_port = getattr(settings, 'smtp_port', 587)
        self.smtp_user = getattr(settings, 'smtp_user', '')
        self.smtp_password = getattr(settings, 'smtp_password', '')
        self.from_email = getattr(settings, 'from_email', 'noreply@cybernova.io')
        self.from_name = getattr(settings, 'from_name', 'CyberNova')
        self.enabled = bool(self.smtp_host)

    async def send(self, notification: EmailNotification) -> bool:
        """Send email notification."""
        if not self.enabled:
            log.debug(f"Email disabled - would send to {notification.to}: {notification.subject}")
            return True

        if self.smtp_host:
            return await self._send_via_smtp(notification)
        else:
            log.warning("No email transport configured")
            return False

    async def _send_via_smtp(self, notification: EmailNotification) -> bool:
        """Send via SMTP without blocking the event loop."""
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_sync, notification)
            return True
        except Exception as e:
            log.error("SMTP send failed: %s", e)
            return False

    def _send_sync(self, notification: EmailNotification) -> None:
        """Synchronous SMTP send — runs in thread pool executor."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = notification.subject
        msg["From"] = f"{self.from_name} <{self.from_email}>"
        msg["To"] = notification.to

        msg.attach(MIMEText(notification.body, "plain"))
        if notification.html:
            msg.attach(MIMEText(notification.html, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
        except smtplib.SMTPException as e:
            log.error("SMTP protocol error: %s", e)
            raise

    async def send_alert(
        self,
        to: str,
        alert: Dict[str, Any],
        tenant_name: str,
    ) -> bool:
        """Send alert notification."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }
        emoji = severity_emoji.get(alert.get("severity", "low"), "⚪")

        subject = f"{emoji} [CyberNova] {alert.get('severity', 'alert').upper()}: {alert.get('rule_name', 'Alert')}"
        body = f"""
New Security Alert - CyberNova

Tenant: {tenant_name}
Severity: {alert.get('severity', 'unknown').upper()}
Rule: {alert.get('rule_name', 'Unknown')}
Description: {alert.get('description', 'No description')}

Source IP: {alert.get('source_ip', 'N/A')}
Dest IP: {alert.get('dest_ip', 'N/A')}
User: {alert.get('user', 'N/A')}

Time: {alert.get('created_at', 'N/A')}

View in CyberNova: https://cybernova.io/alerts/{alert.get('id')}
"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #16213e; padding: 20px; color: #e0e0e0; }}
        .severity-critical {{ color: #ef4444; }}
        .severity-high {{ color: #f97316; }}
        .severity-medium {{ color: #eab308; }}
        .severity-low {{ color: #22c55e; }}
        .footer {{ background: #0f0f23; padding: 15px; color: #6b7280; font-size: 12px; border-radius: 0 0 8px 8px; }}
        .button {{ display: inline-block; background: #06b6d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🛡️ CyberNova Alert</h2>
        </div>
        <div class="content">
            <p class="severity-{alert.get('severity', 'low')}">
                <strong>{emoji} {alert.get('severity', 'alert').upper()}</strong>
            </p>
            <h3>{alert.get('rule_name', 'Alert')}</h3>
            <p>{alert.get('description', 'No description')}</p>
            <table>
                <tr><td><strong>Source IP:</strong></td><td>{alert.get('source_ip', 'N/A')}</td></tr>
                <tr><td><strong>Dest IP:</strong></td><td>{alert.get('dest_ip', 'N/A')}</td></tr>
                <tr><td><strong>User:</strong></td><td>{alert.get('user', 'N/A')}</td></tr>
                <tr><td><strong>Time:</strong></td><td>{alert.get('created_at', 'N/A')}</td></tr>
            </table>
            <p><a href="https://cybernova.io/alerts/{alert.get('id')}" class="button">View Alert</a></p>
        </div>
        <div class="footer">
            <p>CyberNova SIEM - Real-time threat detection</p>
        </div>
    </div>
</body>
</html>
"""
        return await self.send(EmailNotification(
            to=to,
            subject=subject,
            body=body,
            html=html,
        ))

    async def send_incident(
        self,
        to: str,
        incident: Dict[str, Any],
        tenant_name: str,
    ) -> bool:
        """Send incident notification."""
        subject = f"🚨 [CyberNova] INCIDENT: {incident.get('title', 'Incident')}"
        body = f"""
New Incident Created - CyberNova

Tenant: {tenant_name}
Title: {incident.get('title', 'N/A')}
Severity: {incident.get('severity', 'unknown').upper()}
Status: {incident.get('status', 'new').upper()}
Description: {incident.get('description', 'No description')}

Created: {incident.get('created_at', 'N/A')}

View in CyberNova: https://cybernova.io/incidents/{incident.get('id')}
"""
        return await self.send(EmailNotification(
            to=to,
            subject=subject,
            body=body,
        ))

    async def send_welcome(
        self,
        to: str,
        tenant_name: str,
    ) -> bool:
        """Send welcome email."""
        subject = "Welcome to CyberNova!"
        body = f"""
Welcome to CyberNova, {tenant_name}!

Get started:
1. Configure your data sources (syslog, agents, API)
2. Set up threat intelligence (VirusTotal, AbuseIPDB)
3. Connect built-in SOAR for SOAR automation
4. Invite your team

Docs: https://docs.cybernova.io
Support: support@cybernova.io

- The CyberNova Team
"""
        return await self.send(EmailNotification(
            to=to,
            subject=subject,
            body=body,
        ))


email_service = EmailService()


async def notify_alert_subscribers(
    tenant_id: str,
    alert: Dict[str, Any],
    tenant_name: str,
) -> int:
    """Notify all subscribed users of new alert."""
    from sqlalchemy import select
    from cybernova.database.postgres.session import get_db_session

    sent = 0
    async for db in get_db_session():
        result = await db.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.is_active,
            )
        )
        users = result.scalars().all()

        for user in users:
            if user.email:
                await email_service.send_alert(user.email, alert, tenant_name)
                sent += 1
        break

    return sent
