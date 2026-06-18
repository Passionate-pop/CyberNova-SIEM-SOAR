"""MISP connector — pushes IoCs and threat indicators to MISP."""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional
import time
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.misp")


class MISPConnector(IntegrationPlugin):
    name = "misp"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._api_key: Optional[str] = None
        self._default_event_id: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'misp_url', None)
                     or getattr(self.settings, 'integrations_misp_url', None))
        self._api_key = (getattr(self.settings, 'misp_api_key', None)
                         or getattr(self.settings, 'integrations_misp_key', None))
        self._default_event_id = getattr(self.settings, 'misp_event_id', None)
        if self._url and self._api_key:
            self._client = httpx.AsyncClient(timeout=30.0, verify=True)
            log.info("MISP connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._api_key:
            log.debug("MISP not configured — would push IoCs")
            return {"success": True, "simulated": True}

        attributes = self._extract_iocs(event, payload)
        if not attributes:
            return {"success": True, "count": 0}

        return await self._push_attributes(attributes)

    def _extract_iocs(self, event: str, payload: dict) -> list:
        attributes = []
        data = payload if event in ("alert", "new_alert") else payload.get("alert", payload)

        if data.get("source_ip"):
            attributes.append(self._make_attribute("ip-src", data["source_ip"], data))
        if data.get("dest_ip"):
            attributes.append(self._make_attribute("ip-dst", data["dest_ip"], data))
        if data.get("user"):
            attributes.append(self._make_attribute("text", f"User: {data['user']}", data))
        hash_val = data.get("file_hash", data.get("hash", ""))
        if hash_val:
            attr_type = self._detect_hash_type(hash_val)
            attributes.append(self._make_attribute(attr_type, hash_val, data))
        domain = data.get("domain", "")
        if domain:
            attributes.append(self._make_attribute("domain", domain, data))
        url_val = data.get("url", "")
        if url_val:
            attributes.append(self._make_attribute("url", url_val, data))
        return attributes

    def _make_attribute(self, attr_type: str, value: str, data: dict) -> dict:
        return {
            "type": attr_type, "value": value,
            "category": "Network activity",
            "to_ids": True,
            "comment": f"CyberNova: {data.get('rule_name', 'alert')} | risk:{data.get('risk_score', 0)}",
        }

    def _detect_hash_type(self, h: str) -> str:
        length = len(h)
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        return "text"

    async def _push_attributes(self, attributes: list) -> Dict[str, Any]:
        try:
            event_id = self._default_event_id or self._find_or_create_event()
            if not event_id:
                return {"success": False, "error": "No MISP event ID configured"}
            headers = {"Authorization": self._api_key, "Content-Type": "application/json", "Accept": "application/json"}
            added = 0
            for attr in attributes:
                resp = await self._client.post(
                    f"{self._url.rstrip('/')}/attributes/add/{event_id}",
                    json=attr, headers=headers,
                )
                if resp.status_code < 400:
                    added += 1
            return {"success": True, "added": added, "total": len(attributes)}
        except Exception as e:
            log.error("MISP push error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send an event to MISP."""
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        """Check connectivity to MISP."""
        if not self._url:
            return {"healthy": False, "latency_ms": 0, "details": "MISP not configured"}
        try:
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._url.rstrip('/')}/servers/getVersion.json",
                                       headers={"Authorization": self._api_key, "Accept": "application/json"})
                latency = (time.monotonic() - start) * 1000
                return {
                    "healthy": resp.status_code < 400,
                    "latency_ms": round(latency, 2),
                    "details": f"MISP {self._url} — HTTP {resp.status_code}",
                }
        except Exception as e:
            return {"healthy": False, "latency_ms": 0, "details": str(e)}

    async def _find_or_create_event(self) -> Optional[str]:
        return self._default_event_id

    async def teardown(self):
        if self._client:
            await self._client.aclose()
