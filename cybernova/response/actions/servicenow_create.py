from __future__ import annotations

import logging
import os
from typing import Any, Dict

log = logging.getLogger("cybernova.response.actions.servicenow_create")

SNOW_URL = os.environ.get("CYBERNOVA_SERVICENOW_URL", "")
SNOW_USERNAME = os.environ.get("CYBERNOVA_SERVICENOW_USERNAME", "")
SNOW_PASSWORD = os.environ.get("CYBERNOVA_SERVICENOW_PASSWORD", "")

PRIORITY_MAP = {"critical": "1", "high": "2", "medium": "3", "low": "4"}


def _build_snow_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    severity = incident.get("severity", "low")
    priority = PRIORITY_MAP.get(severity, "3")
    short_description = f"[CyberNova] [{severity.upper()}] {incident.get('title', 'Security Alert')}"
    description = (
        f"CyberNova Security Alert\n\n"
        f"Severity: {severity}\n"
        f"Rule: {incident.get('title', 'N/A')}\n"
        f"Risk Score: {incident.get('risk_score', 0)}\n"
        f"Source IP: {incident.get('source_ip', 'N/A')}\n"
        f"Destination IP: {incident.get('dest_ip', 'N/A')}\n"
        f"User: {incident.get('user', 'N/A')}\n\n"
        f"Description:\n{incident.get('description', 'No description')}\n"
    )

    return {
        "short_description": short_description[:160],
        "description": description,
        "priority": priority,
        "category": "Security",
        "caller_id": incident.get("user", ""),
        "work_notes": f"Auto-created by CyberNova SOAR. Alert ID: {incident.get('id', '')}",
    }


def execute_servicenow_create(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Create a ServiceNow incident for a security alert.

    Expected incident keys:
        id, title, severity, source_ip, dest_ip, user, risk_score, description
    """
    if not SNOW_URL or not SNOW_USERNAME or not SNOW_PASSWORD:
        log.debug("ServiceNow not configured — would create incident for %s", incident.get("id", ""))
        return {"success": True, "simulated": True}

    try:
        import base64
        import httpx
        payload = _build_snow_incident(incident)
        auth = base64.b64encode(f"{SNOW_USERNAME}:{SNOW_PASSWORD}".encode()).decode()
        resp = httpx.post(
            f"{SNOW_URL.rstrip('/')}/api/now/table/incident",
            json=payload,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )
        success = resp.status_code < 400
        if success:
            result = resp.json().get("result", {})
            sys_id = result.get("sys_id", "")
            number = result.get("number", "")
            log.info("ServiceNow incident created: %s (%s)", number, sys_id)
            return {"success": True, "sys_id": sys_id, "number": number}

        log.warning("ServiceNow returned %d: %s", resp.status_code, resp.text[:200])
        return {"success": False, "status_code": resp.status_code}
    except Exception as e:
        log.error("ServiceNow create error: %s", e)
        return {"success": False, "error": str(e)}
