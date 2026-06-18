from __future__ import annotations

import logging
import os
from typing import Any, Dict

log = logging.getLogger("cybernova.response.actions.pagerduty_trigger")

PD_ROUTING_KEY = os.environ.get("CYBERNOVA_PAGERDUTY_KEY", "")
PD_EVENTS_API = "https://events.pagerduty.com/v2/enqueue"


def _build_pd_event(incident: Dict[str, Any]) -> Dict[str, Any]:
    severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
    sev = severity_map.get(incident.get("severity", "low"), "info")
    dedup_key = f"cybernova:trigger:{incident.get('id', 'unknown')}"

    return {
        "routing_key": PD_ROUTING_KEY,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"[{incident.get('severity', 'alert').upper()}] {incident.get('title', 'Security Alert')}",
            "severity": sev,
            "source": "cybernova",
            "component": "cybernova-siem",
            "class": incident.get("title", "security_alert"),
            "custom_details": {
                "alert_id": incident.get("id", ""),
                "risk_score": incident.get("risk_score", 0),
                "source_ip": incident.get("source_ip", ""),
                "dest_ip": incident.get("dest_ip", ""),
                "user": incident.get("user", ""),
                "description": incident.get("description", "")[:500],
            },
        },
    }


def execute_pagerduty_trigger(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Trigger a PagerDuty incident via the PD Events API v2.

    Expected incident keys:
        id, title, severity, source_ip, dest_ip, user, risk_score, description
    """
    if not PD_ROUTING_KEY:
        log.debug("PagerDuty not configured — would trigger incident for %s", incident.get("id", ""))
        return {"success": True, "simulated": True}

    try:
        import httpx
        pd_event = _build_pd_event(incident)
        resp = httpx.post(
            PD_EVENTS_API,
            json=pd_event,
            headers={"Content-Type": "application/json"},
            timeout=15.0,
        )
        success = resp.status_code < 400
        if success:
            data = resp.json()
            log.info("PagerDuty triggered: dedup_key=%s", data.get("dedup_key", ""))
        else:
            log.warning("PagerDuty returned %d: %s", resp.status_code, resp.text[:200])

        return {
            "success": success,
            "status_code": resp.status_code,
            "dedup_key": pd_event["dedup_key"],
        }
    except Exception as e:
        log.error("PagerDuty trigger error: %s", e)
        return {"success": False, "error": str(e)}
