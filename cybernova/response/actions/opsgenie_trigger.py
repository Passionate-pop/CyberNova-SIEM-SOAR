from __future__ import annotations

import logging
import os
from typing import Any, Dict

log = logging.getLogger("cybernova.response.actions.opsgenie_trigger")

OPSGENIE_API_KEY = os.environ.get("CYBERNOVA_OPSGENIE_KEY", "")
OPSGENIE_API_URL = "https://api.opsgenie.com/v2/alerts"

PRIORITY_MAP = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


def _build_opsgenie_alert(incident: Dict[str, Any]) -> Dict[str, Any]:
    severity = incident.get("severity", "low")
    priority = PRIORITY_MAP.get(severity, "P4")
    alias = f"cybernova:alert:{incident.get('id', 'unknown')}"

    return {
        "message": f"[{severity.upper()}] {incident.get('title', 'Security Alert')}",
        "alias": alias,
        "description": incident.get("description", "")[:500],
        "priority": priority,
        "source": "cybernova",
        "details": {
            "alert_id": incident.get("id", ""),
            "risk_score": str(incident.get("risk_score", 0)),
            "source_ip": incident.get("source_ip", ""),
            "dest_ip": incident.get("dest_ip", ""),
            "user": incident.get("user", ""),
        },
        "tags": ["cybernova", f"severity:{severity}"],
    }


def execute_opsgenie_trigger(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Create an Opsgenie alert via the Opsgenie Alerts API v2.

    Expected incident keys:
        id, title, severity, source_ip, dest_ip, user, risk_score, description
    """
    if not OPSGENIE_API_KEY:
        log.debug("Opsgenie not configured — would trigger alert for %s", incident.get("id", ""))
        return {"success": True, "simulated": True}

    try:
        import httpx
        payload = _build_opsgenie_alert(incident)
        resp = httpx.post(
            OPSGENIE_API_URL,
            json=payload,
            headers={
                "Authorization": f"GenieKey {OPSGENIE_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )
        success = resp.status_code < 400
        if success:
            data = resp.json()
            log.info("Opsgenie alert created: request_id=%s", data.get("requestId", ""))
        else:
            log.warning("Opsgenie returned %d: %s", resp.status_code, resp.text[:200])

        return {
            "success": success,
            "status_code": resp.status_code,
            "alias": payload["alias"],
        }
    except Exception as e:
        log.error("Opsgenie trigger error: %s", e)
        return {"success": False, "error": str(e)}
