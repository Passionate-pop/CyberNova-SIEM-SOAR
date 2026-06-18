"""TheHive connector — creates alerts and cases in TheHive for incidents."""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.thehive")


class TheHiveConnector(IntegrationPlugin):
    name = "thehive"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._api_key: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'thehive_url', None)
                     or getattr(self.settings, 'integrations_thehive_url', None))
        self._api_key = (getattr(self.settings, 'thehive_api_key', None)
                         or getattr(self.settings, 'integrations_thehive_key', None))
        if self._url and self._api_key:
            self._client = httpx.AsyncClient(timeout=15.0)
            log.info("TheHive connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._api_key:
            log.debug("TheHive not configured — would create alert")
            return {"success": True, "simulated": True}

        if event in ("incident", "new_incident"):
            return await self._create_case(payload)
        elif event in ("alert", "new_alert"):
            return await self._create_alert(payload)
        return {"success": True, "skipped": True}

    async def _create_alert(self, alert: dict) -> Dict[str, Any]:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        try:
            body = {
                "title": f"[CyberNova] {alert.get('rule_name', 'Security Alert')}",
                "description": alert.get("description", "")[:1000],
                "severity": severity_map.get(alert.get("severity", "low"), 1),
                "date": int(alert.get("timestamp", 0)),
                "tags": ["cybernova", f"severity-{alert.get('severity', 'low')}"],
                "type": "cybernova_alert",
                "source": "cybernova",
                "sourceRef": f"cybernova-{alert.get('id', 'unknown')}",
                "artifacts": [
                    {"dataType": "ip", "data": alert.get("source_ip", "")} if alert.get("source_ip") else None,
                    {"dataType": "ip", "data": alert.get("dest_ip", "")} if alert.get("dest_ip") else None,
                    {"dataType": "user", "data": alert.get("user", "")} if alert.get("user") else None,
                    {"dataType": "other", "data": f"risk_score:{alert.get('risk_score', 0)}"},
                ],
            }
            body["artifacts"] = [a for a in body["artifacts"] if a]
            headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
            resp = await self._client.post(f"{self._url.rstrip('/')}/api/v1/alert", json=body, headers=headers)
            success = resp.status_code < 400
            if success:
                log.info("TheHive alert created: %s", resp.json().get("_id", ""))
            return {"success": success}
        except Exception as e:
            log.error("TheHive alert error: %s", e)
            return {"success": False, "error": str(e)}

    async def _create_case(self, incident: dict) -> Dict[str, Any]:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        try:
            body = {
                "title": f"[CyberNova] {incident.get('title', 'Security Incident')}",
                "description": incident.get("description", "")[:2000],
                "severity": severity_map.get(incident.get("severity", "low"), 1),
                "tags": ["cybernova", "incident", f"severity-{incident.get('severity', 'low')}"],
                "customFields": {
                    "riskScore": {"string": str(incident.get("risk_score", 0))},
                },
            }
            headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
            resp = await self._client.post(f"{self._url.rstrip('/')}/api/v1/case", json=body, headers=headers)
            success = resp.status_code < 400
            if success:
                log.info("TheHive case created: %s", resp.json().get("_id", ""))
            return {"success": success}
        except Exception as e:
            log.error("TheHive case error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        if not self._url or not self._api_key:
            return {"healthy": False, "error": "TheHive not configured"}
        import time
        start = time.monotonic()
        try:
            headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
            resp = await self._client.get(f"{self._url.rstrip('/')}/api/v1/alert", headers=headers)
            latency = (time.monotonic() - start) * 1000
            return {"healthy": resp.status_code < 400, "latency_ms": round(latency, 1)}
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {"healthy": False, "error": str(e), "latency_ms": round(latency, 1)}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
