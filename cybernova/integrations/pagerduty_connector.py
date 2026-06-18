"""PagerDuty connector — triggers incidents and alerts on critical events."""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.pagerduty")


class PagerDutyConnector(IntegrationPlugin):
    name = "pagerduty"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._routing_key: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._routing_key = (getattr(self.settings, 'pagerduty_routing_key', None)
                             or getattr(self.settings, 'integrations_pagerduty_key', None))
        if self._routing_key:
            self._client = httpx.AsyncClient(timeout=15.0)
            log.info("PagerDuty connector initialized")

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._routing_key:
            log.debug("PagerDuty not configured — would trigger for %s", event)
            return {"success": True, "simulated": True}

        pd_event = self._build_event(event, payload)
        return await self._trigger(pd_event)

    def _build_event(self, event: str, payload: dict) -> dict:
        alert = payload if event in ("alert", "new_alert") else payload.get("alert", payload)
        severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
        sev = severity_map.get(alert.get("severity", "low"), "info")

        return {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": f"cybernova:{event}:{alert.get('id', 'unknown')}",
            "payload": {
                "summary": f"[{alert.get('severity', 'alert').upper()}] {alert.get('rule_name', 'Security Alert')}",
                "severity": sev,
                "source": "cybernova",
                "component": "cybernova-siem",
                "group": event,
                "class": alert.get("rule_name", "security_alert"),
                "custom_details": {
                    "alert_id": alert.get("id", ""),
                    "risk_score": alert.get("risk_score", 0),
                    "source_ip": alert.get("source_ip", ""),
                    "dest_ip": alert.get("dest_ip", ""),
                    "user": alert.get("user", ""),
                    "description": alert.get("description", "")[:500],
                },
            },
            "links": [{
                "href": f"{getattr(self.settings, 'cybernova_base_url', 'https://cybernova.io')}/alerts/{alert.get('id', '')}",
                "text": "View in CyberNova",
            }],
        }

    async def _trigger(self, pd_event: dict) -> Dict[str, Any]:
        try:
            resp = await self._client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=pd_event,
                headers={"Content-Type": "application/json"},
            )
            success = resp.status_code < 400
            if success:
                data = resp.json()
                log.info("PagerDuty triggered: dedup_key=%s", data.get("dedup_key", ""))
            else:
                log.warning("PagerDuty returned %d: %s", resp.status_code, resp.text[:200])
            return {"success": success, "status_code": resp.status_code, "dedup_key": pd_event["dedup_key"]}
        except Exception as e:
            log.error("PagerDuty error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: dict) -> dict:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> dict:
        if not self._routing_key:
            return {"healthy": False, "error": "not configured"}
        return {"healthy": True, "latency_ms": 0}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
