"""OpenCTI connector — pushes observables and indicators to OpenCTI."""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional
import httpx
from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.opencti")


class OpenCTIConnector(IntegrationPlugin):
    name = "opencti"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()
        self._url: Optional[str] = None
        self._token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._url = (getattr(self.settings, 'opencti_url', None)
                     or getattr(self.settings, 'integrations_opencti_url', None))
        self._token = (getattr(self.settings, 'opencti_token', None)
                       or getattr(self.settings, 'integrations_opencti_token', None))
        if self._url and self._token:
            self._client = httpx.AsyncClient(timeout=30.0)
            log.info("OpenCTI connector initialized for %s", self._url)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._url or not self._token:
            log.debug("OpenCTI not configured — would push observables")
            return {"success": True, "simulated": True}

        observables = self._extract_observables(event, payload)
        results = []
        for obs in observables:
            result = await self._push_observable(obs)
            results.append(result)
        return {"success": all(r.get("success") for r in results), "results": results}

    def _extract_observables(self, event: str, payload: dict) -> list:
        observables = []
        data = payload if event in ("alert", "new_alert") else payload.get("alert", payload)

        if data.get("source_ip"):
            observables.append(self._make_observable("IPv4-Addr", data["source_ip"], data))
        if data.get("dest_ip"):
            observables.append(self._make_observable("IPv4-Addr", data["dest_ip"], data))
        if data.get("domain"):
            observables.append(self._make_observable("Domain-Name", data["domain"], data))
        if data.get("url"):
            observables.append(self._make_observable("Url", data["url"], data))
        if data.get("file_hash"):
            hash_type = self._detect_hash_type(data["file_hash"])
            observables.append(self._make_observable(hash_type, data["file_hash"], data))
        if data.get("user"):
            observables.append(self._make_observable("User-Account", data["user"], data))

        return observables

    def _make_observable(self, entity_type: str, value: str, data: dict) -> dict:
        return {
            "query": """
                mutation CreateIndicator($input: IndicatorAddInput!) {
                    indicatorAdd(input: $input) { id name }
                }
            """,
            "variables": {
                "input": {
                    "name": f"CyberNova: {data.get('rule_name', 'indicator')} - {value[:50]}",
                    "pattern": f"[{entity_type}: '{value}']",
                    "pattern_type": "stix",
                    "x_opencti_score": min(int(data.get("risk_score", 50)), 100),
                    "description": data.get("description", "")[:500],
                    "labels": ["cybernova", data.get("severity", "low")],
                }
            },
        }

    def _detect_hash_type(self, h: str) -> str:
        length = len(h)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA-1"
        elif length == 64:
            return "SHA-256"
        return "Artifact"

    async def _push_observable(self, observable: dict) -> Dict[str, Any]:
        try:
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/graphql",
                json=observable,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
            success = resp.status_code < 400
            if success:
                data = resp.json()
                log.info("OpenCTI indicator created: %s", data.get("data", {}).get("indicatorAdd", {}).get("name", ""))
            return {"success": success}
        except Exception as e:
            log.error("OpenCTI error: %s", e)
            return {"success": False, "error": str(e)}

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def health_check(self) -> Dict[str, Any]:
        if not self._url or not self._token:
            return {"healthy": False, "error": "OpenCTI not configured"}
        import time
        start = time.monotonic()
        try:
            query = {"query": "{ about { name version } }"}
            resp = await self._client.post(
                f"{self._url.rstrip('/')}/graphql",
                json=query,
                headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
            )
            latency = (time.monotonic() - start) * 1000
            data = resp.json()
            healthy = resp.status_code < 400 and data.get("data", {}).get("about") is not None
            return {"healthy": healthy, "latency_ms": round(latency, 1)}
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {"healthy": False, "error": str(e), "latency_ms": round(latency, 1)}

    async def teardown(self):
        if self._client:
            await self._client.aclose()
