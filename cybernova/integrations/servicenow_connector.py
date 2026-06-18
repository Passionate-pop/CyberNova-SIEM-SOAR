"""ServiceNow connector — creates incidents for critical alerts."""
from __future__ import annotations
import base64
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.servicenow")


class ServiceNowConnector(IntegrationPlugin):
    name = "servicenow"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'servicenow_url', None)
                     or getattr(self.settings, 'integrations_servicenow_url', None))
        self._username = (getattr(self.settings, 'servicenow_username', None)
                          or getattr(self.settings, 'integrations_servicenow_username', None))
        self._password = (getattr(self.settings, 'servicenow_password', None)
                          or getattr(self.settings, 'integrations_servicenow_password', None))
        if self._url and self._username and self._password:
            self._client = httpx.AsyncClient(timeout=15.0)
            log.info("ServiceNow connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._username or not self._password:
            log.debug("ServiceNow not configured — would create incident for %s", event)
            return {"success": True, "simulated": True}

        incident = self._build_incident(event, payload)
        return await self._create(incident)

    def _build_incident(self, event: str, payload: dict) -> dict:
        data = payload if event in ("alert", "new_alert") else payload.get("alert", payload)
        severity = data.get("severity", "low")
        priority_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
        priority = priority_map.get(severity, "3")

        short_description = f"[CyberNova] [{severity.upper()}] {data.get('rule_name', 'Security Alert')}"
        description = (
            f"CyberNova Security Alert\n\n"
            f"Severity: {severity}\n"
            f"Rule: {data.get('rule_name', 'N/A')}\n"
            f"Risk Score: {data.get('risk_score', 0)}\n"
            f"Source IP: {data.get('source_ip', 'N/A')}\n"
            f"Destination IP: {data.get('dest_ip', 'N/A')}\n"
            f"User: {data.get('user', 'N/A')}\n\n"
            f"Description:\n{data.get('description', 'No description')}\n\n"
            f"Alert ID: {data.get('id', '')}"
        )

        return {
            "short_description": short_description[:160],
            "description": description,
            "priority": priority,
            "category": "Security",
            "caller_id": data.get("user", ""),
            "work_notes": f"Auto-created by CyberNova SOAR. Alert ID: {data.get('id', '')}",
        }

    async def _create(self, incident: dict) -> Dict[str, Any]:
        try:
            auth = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/api/now/table/incident",
                json=incident,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                },
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
            log.error("ServiceNow error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        if not self._url or not self._username or not self._password:
            return {"healthy": False, "error": "ServiceNow not configured"}
        try:
            auth = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            resp = await self._client.get(
                f"{self._url.rstrip('/')}/api/now/table/incident?sysparm_limit=1",
                headers={"Authorization": f"Basic {auth}"},
            )
            return {"healthy": resp.status_code < 400, "status_code": resp.status_code}
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
