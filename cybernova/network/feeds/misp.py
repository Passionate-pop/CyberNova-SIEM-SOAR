from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from cybernova.config.settings import get_settings
from cybernova.network.threat_intel import threat_intel_service

log = logging.getLogger("cybernova.network.feeds.misp")

MISP_DEFAULT_TIMEOUT = 30


class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True, **kwargs):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                verify=self.verify_ssl,
                timeout=MISP_DEFAULT_TIMEOUT,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            )
        return self._client

    async def list_events(self, limit: int = 100, page: int = 1) -> List[Dict[str, Any]]:
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.url}/events/index", params={"limit": limit, "page": page})
            resp.raise_for_status()
            return resp.json() if isinstance(resp.json(), list) else resp.json().get("response", [])
        except Exception as e:
            log.warning("MISP list events failed: %s", e)
            return []

    async def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.url}/events/{event_id}")
            resp.raise_for_status()
            data = resp.json()
            return data.get("Event", data)
        except Exception as e:
            log.warning("MISP get event %s failed: %s", event_id, e)
            return None

    async def get_attributes(self, event_id: str) -> List[Dict[str, Any]]:
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.url}/attributes/event/{event_id}")
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs and isinstance(data, dict):
                attrs = data.get("Attribute", [])
            return attrs if isinstance(attrs, list) else []
        except Exception as e:
            log.warning("MISP get attributes for %s failed: %s", event_id, e)
            return []

    async def poll_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        events = await self.list_events(limit=limit)
        iocs = []
        for event in events:
            event_id = event.get("id") or event.get("Event", {}).get("id", "")
            if not event_id:
                continue
            attrs = await self.get_attributes(event_id)
            for attr in attrs:
                ioc = self._parse_attribute(attr, event)
                if ioc:
                    iocs.append(ioc)
        log.info("MISP poll: %d IOCs from %d events", len(iocs), len(events))
        return iocs

    def _parse_attribute(self, attr: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        if not value:
            return None

        if attr_type in ("ip-src", "ip-dst", "ip-dst|port"):
            ioc_type = "ip"
        elif attr_type in ("domain", "domain|ip", "hostname"):
            ioc_type = "domain"
        elif attr_type in ("url", "uri"):
            ioc_type = "url"
        elif attr_type in ("md5", "filename|md5"):
            ioc_type = "md5"
        elif attr_type in ("sha1", "filename|sha1"):
            ioc_type = "sha1"
        elif attr_type in ("sha256", "filename|sha256"):
            ioc_type = "sha256"
        elif attr_type in ("mutex", "named pipe"):
            ioc_type = attr_type
        elif attr_type in ("email", "email-src", "email-dst"):
            ioc_type = "email"
        elif attr_type in ("regkey", "regkey|value"):
            ioc_type = "registry"
        else:
            return None

        if "|" in value:
            value = value.split("|")[0].strip()

        event_info = event.get("info", event.get("Event", {}).get("info", ""))
        event_threat_level = event.get("threat_level_id", event.get("Event", {}).get("threat_level_id", ""))

        return {
            "type": ioc_type,
            "value": value,
            "attr_type": attr_type,
            "category": attr.get("category", ""),
            "comment": attr.get("comment", ""),
            "event_info": event_info,
            "threat_level": event_threat_level,
            "source": "misp",
            "feed_url": self.url,
        }

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


async def poll_misp_feed(url: str, api_key: str, verify_ssl: bool = True) -> int:
    client = MISPClient(url, api_key, verify_ssl)
    try:
        iocs = await client.poll_recent_events(limit=50)
        total = 0
        for ioc in iocs:
            await threat_intel_service.add_ioc(
                indicator=ioc["value"],
                ioc_type=ioc["type"],
                metadata={
                    "source": "misp",
                    "feed_url": url,
                    "attr_type": ioc.get("attr_type"),
                    "category": ioc.get("category"),
                    "comment": ioc.get("comment"),
                    "event_info": ioc.get("event_info"),
                },
            )
            total += 1
        return total
    finally:
        await client.close()


async def poll_all_misp() -> int:
    settings = get_settings()
    total = 0
    misp_url = getattr(settings, "integrations_misp_url", "")
    misp_key = getattr(settings, "integrations_misp_key", "")
    if misp_url and misp_key:
        total += await poll_misp_feed(misp_url, misp_key)
    return total
