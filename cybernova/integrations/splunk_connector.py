"""Splunk connector — forwards alerts and events to Splunk HEC."""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.splunk")


class SplunkConnector(IntegrationPlugin):
    name = "splunk"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._token: Optional[str] = None
        self._source: str = "cybernova"
        self._sourcetype: str = "_json"
        self._index: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'splunk_hec_url', None)
                     or getattr(self.settings, 'integrations_splunk_url', None))
        self._token = (getattr(self.settings, 'splunk_hec_token', None)
                       or getattr(self.settings, 'integrations_splunk_token', None))
        self._index = (getattr(self.settings, 'splunk_index', None)
                       or getattr(self.settings, 'integrations_splunk_index', 'security'))
        if self._url and self._token:
            self._client = httpx.AsyncClient(timeout=15.0, verify=True)
            log.info("Splunk connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._token:
            log.debug("Splunk not configured — would forward event")
            return {"success": True, "simulated": True}

        hec_event = self._build_event(event, payload)
        return await self._send(hec_event)

    def _build_event(self, event: str, payload: dict) -> dict:
        return {
            "time": payload.get("timestamp", payload.get("created_at", "")),
            "source": self._source,
            "sourcetype": self._sourcetype,
            "index": self._index,
            "event": {
                "event_type": event,
                "cybernova": payload,
                "severity": payload.get("severity", "info"),
                "rule_name": payload.get("rule_name", ""),
                "risk_score": payload.get("risk_score", 0),
                "source_ip": payload.get("source_ip", ""),
                "dest_ip": payload.get("dest_ip", ""),
                "user": payload.get("user", ""),
            },
        }

    async def _send(self, hec_event: dict) -> Dict[str, Any]:
        try:
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/services/collector",
                json=hec_event,
                headers={"Authorization": f"Splunk {self._token}"},
            )
            success = resp.status_code < 400
            if not success:
                log.warning("Splunk HEC returned %d: %s", resp.status_code, resp.text[:200])
            return {"success": success}
        except Exception as e:
            log.error("Splunk HEC error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_batch(self, events: list) -> Dict[str, Any]:
        if not self._client:
            return {"success": False, "error": "not configured"}
        hec_events = [self._build_event(e.get("event", "unknown"), e.get("payload", {})) for e in events]
        try:
            data = "\n".join(json.dumps(e) for e in hec_events)
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/services/collector/raw",
                content=data,
                headers={"Authorization": f"Splunk {self._token}"},
            )
            return {"success": resp.status_code < 400}
        except Exception as e:
            log.error("Splunk batch error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        if not self._url or not self._token:
            return {"healthy": False, "error": "Splunk not configured"}
        import time
        start = time.monotonic()
        try:
            resp = await self._client.get(
                f"{self._url.rstrip('/')}/services/collector/health",
                headers={"Authorization": f"Splunk {self._token}"},
            )
            latency = (time.monotonic() - start) * 1000
            return {"healthy": resp.status_code < 400, "latency_ms": round(latency, 1)}
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {"healthy": False, "error": str(e), "latency_ms": round(latency, 1)}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
