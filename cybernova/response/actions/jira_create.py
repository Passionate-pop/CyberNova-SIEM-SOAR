from __future__ import annotations

import logging
import os
from typing import Any, Dict

log = logging.getLogger("cybernova.response.actions.jira_create")

JIRA_URL = os.environ.get("CYBERNOVA_JIRA_URL", "")
JIRA_EMAIL = os.environ.get("CYBERNOVA_JIRA_EMAIL", "")
JIRA_TOKEN = os.environ.get("CYBERNOVA_JIRA_TOKEN", "")
JIRA_PROJECT = os.environ.get("CYBERNOVA_JIRA_PROJECT", "SEC")

PRIORITY_MAP = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}


def _build_jira_issue(incident: Dict[str, Any]) -> Dict[str, Any]:
    severity = incident.get("severity", "low").upper()
    priority = PRIORITY_MAP.get(incident.get("severity", "low"), "Medium")
    summary = f"[CyberNova] [{severity}] {incident.get('title', 'Security Alert')}"
    description = (
        f"h2. CyberNova Security Alert\n\n"
        f"|| Field || Value ||\n"
        f"| Severity | {severity} |\n"
        f"| Rule | {incident.get('title', 'N/A')} |\n"
        f"| Risk Score | {incident.get('risk_score', 0)} |\n"
        f"| Source IP | {incident.get('source_ip', 'N/A')} |\n"
        f"| Destination IP | {incident.get('dest_ip', 'N/A')} |\n"
        f"| User | {incident.get('user', 'N/A')} |\n\n"
        f"*Description:*\n{incident.get('description', 'No description')}\n"
    )

    return {
        "fields": {
            "project": {"key": JIRA_PROJECT},
            "summary": summary[:255],
            "description": description,
            "issuetype": {"name": "Task"},
            "priority": {"name": priority},
            "labels": ["cybernova", f"severity-{incident.get('severity', 'low')}"],
        }
    }


def execute_jira_create(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Create a Jira issue for a security alert.

    Expected incident keys:
        id, title, severity, source_ip, dest_ip, user, risk_score, description
    """
    if not JIRA_URL or not JIRA_EMAIL or not JIRA_TOKEN:
        log.debug("Jira not configured — would create issue for %s", incident.get("id", ""))
        return {"success": True, "simulated": True}

    try:
        import base64
        import httpx
        issue = _build_jira_issue(incident)
        auth = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_TOKEN}".encode()).decode()
        resp = httpx.post(
            f"{JIRA_URL.rstrip('/')}/rest/api/3/issue",
            json=issue,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )
        success = resp.status_code < 400
        if success:
            key = resp.json().get("key", "")
            log.info("Jira issue created: %s", key)
            return {"success": True, "issue_key": key, "url": f"{JIRA_URL}/browse/{key}"}

        log.warning("Jira returned %d: %s", resp.status_code, resp.text[:200])
        return {"success": False, "status_code": resp.status_code}
    except Exception as e:
        log.error("Jira create error: %s", e)
        return {"success": False, "error": str(e)}
