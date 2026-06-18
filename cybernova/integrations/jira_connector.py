"""Jira connector — creates issues/tickets for incidents and critical alerts."""
from __future__ import annotations
import base64
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.jira")


class JiraConnector(IntegrationPlugin):
    name = "jira"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._email: Optional[str] = None
        self._token: Optional[str] = None
        self._project: Optional[str] = None
        self._issue_type: str = "Task"
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'jira_url', None)
                     or getattr(self.settings, 'integrations_jira_url', None))
        self._email = (getattr(self.settings, 'jira_email', None)
                       or getattr(self.settings, 'integrations_jira_email', None))
        self._token = (getattr(self.settings, 'jira_token', None)
                       or getattr(self.settings, 'integrations_jira_token', None))
        self._project = (getattr(self.settings, 'jira_project', None)
                         or getattr(self.settings, 'integrations_jira_project', 'SEC'))
        if self._url and self._email and self._token:
            self._client = httpx.AsyncClient(timeout=15.0)
            log.info("Jira connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._email or not self._token:
            log.debug("Jira not configured — would create issue for %s", event)
            return {"success": True, "simulated": True}

        issue = self._build_issue(event, payload)
        return await self._create(issue)

    def _build_issue(self, event: str, payload: dict) -> dict:
        data = payload if event in ("alert", "new_alert") else payload.get("alert", payload)
        severity = data.get("severity", "low").upper()
        priority_map = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
        priority = priority_map.get(severity, "Medium")

        summary = f"[CyberNova] [{severity}] {data.get('rule_name', 'Security Alert')}"
        description = (
            f"h2. CyberNova Security {'Alert' if event in ('alert', 'new_alert') else 'Incident'}\n\n"
            f"|| Field || Value ||\n"
            f"| Severity | {severity} |\n"
            f"| Rule | {data.get('rule_name', 'N/A')} |\n"
            f"| Risk Score | {data.get('risk_score', 0)} |\n"
            f"| Source IP | {data.get('source_ip', 'N/A')} |\n"
            f"| Destination IP | {data.get('dest_ip', 'N/A')} |\n"
            f"| User | {data.get('user', 'N/A')} |\n"
            f"| Time | {data.get('created_at', 'N/A')} |\n\n"
            f"*Description:*\n{data.get('description', 'No description')}\n\n"
            f"[View in CyberNova|{getattr(self.settings, 'cybernova_base_url', 'https://cybernova.io')}/alerts/{data.get('id', '')}]"
        )

        return {
            "fields": {
                "project": {"key": self._project},
                "summary": summary[:255],
                "description": description,
                "issuetype": {"name": self._issue_type},
                "priority": {"name": priority},
                "labels": ["cybernova", f"severity-{data.get('severity', 'low')}", event],
            }
        }

    async def _create(self, issue: dict) -> Dict[str, Any]:
        try:
            auth = base64.b64encode(f"{self._email}:{self._token}".encode()).decode()
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/rest/api/3/issue",
                json=issue,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                },
            )
            success = resp.status_code < 400
            if success:
                key = resp.json().get("key", "")
                log.info("Jira issue created: %s", key)
                return {"success": True, "issue_key": key, "url": f"{self._url}/browse/{key}"}
            log.warning("Jira returned %d: %s", resp.status_code, resp.text[:200])
            return {"success": False, "status_code": resp.status_code}
        except Exception as e:
            log.error("Jira error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        if not self._url or not self._email or not self._token:
            return {"healthy": False, "error": "Jira not configured"}
        try:
            auth = base64.b64encode(f"{self._email}:{self._token}".encode()).decode()
            resp = await self._client.get(
                f"{self._url.rstrip('/')}/rest/api/3/project/{self._project}",
                headers={"Authorization": f"Basic {auth}"},
            )
            return {"healthy": resp.status_code < 400, "status_code": resp.status_code}
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
