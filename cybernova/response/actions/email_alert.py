from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict

log = logging.getLogger("cybernova.response.actions.email_alert")

SMTP_HOST = os.environ.get("CYBERNOVA_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("CYBERNOVA_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("CYBERNOVA_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("CYBERNOVA_SMTP_PASSWORD", "")
FROM_EMAIL = os.environ.get("CYBERNOVA_FROM_EMAIL", "noreply@cybernova.io")
FROM_NAME = os.environ.get("CYBERNOVA_FROM_NAME", "CyberNova")


def _build_email(incident: Dict[str, Any]) -> Dict[str, Any]:
    severity = incident.get("severity", "low").upper()
    subject = f"[CyberNova] [{severity}] {incident.get('title', 'Security Alert')}"
    body = (
        f"New Security Alert - CyberNova\n\n"
        f"Severity: {severity}\n"
        f"Rule: {incident.get('title', 'N/A')}\n"
        f"Risk Score: {incident.get('risk_score', 0)}\n"
        f"Source IP: {incident.get('source_ip', 'N/A')}\n"
        f"Destination IP: {incident.get('dest_ip', 'N/A')}\n"
        f"User: {incident.get('user', 'N/A')}\n\n"
        f"Description:\n{incident.get('description', 'No description')}\n\n"
        f"Alert ID: {incident.get('id', '')}"
    )
    return {"subject": subject, "body": body}


def execute_email_alert(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Send an email alert via SMTP for a security incident.

    Expected incident keys:
        id, title, severity, source_ip, dest_ip, user, risk_score, description
    Recipient is read from incident['to'] or action parameters.
    """
    to_addr = incident.get("to", "")
    if not to_addr:
        log.warning("No recipient address for email alert")
        return {"success": False, "error": "No recipient address"}

    if not SMTP_HOST or not SMTP_USER:
        log.debug("SMTP not configured — would send email to %s", to_addr)
        return {"success": True, "simulated": True}

    try:
        email = _build_email(incident)
        msg = MIMEText(email["body"], "plain")
        msg["Subject"] = email["subject"]
        msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
        msg["To"] = to_addr

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        log.info("Email alert sent to %s: %s", to_addr, email["subject"])
        return {"success": True, "to": to_addr}
    except Exception as e:
        log.error("Email alert error: %s", e)
        return {"success": False, "error": str(e)}
