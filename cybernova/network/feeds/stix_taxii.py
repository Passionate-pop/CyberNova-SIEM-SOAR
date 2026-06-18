from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

# Safe XML parsing via defusedxml (with fallback if not installed)
try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring  # nosec
except ImportError:
    import xml.etree.ElementTree as _ET  # nosec - fallback only, defusedxml is in requirements

    def _safe_fromstring(xml_str: str) -> Any:
        return _ET.fromstring(xml_str)  # nosec - fallback only

from cybernova.config.settings import get_settings
from cybernova.network.threat_intel import threat_intel_service

log = logging.getLogger("cybernova.network.feeds.stix_taxii")

TAXII_DEFAULT_POLL_TIMEOUT = 30


class TAXIICollection:
    def __init__(self, name: str, url: str, collection_id: str):
        self.name = name
        self.url = url
        self.collection_id = collection_id


class TAXIIClient:
    def __init__(self, discovery_url: str, username: str = "", password: str = "", **kwargs):  # nosec
        self.discovery_url = discovery_url.rstrip("/")
        self.username = username
        self.password = password
        self._auth = (username, password) if username and password else None
        self._collections: List[TAXIICollection] = []
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                auth=self._auth,
                timeout=TAXII_DEFAULT_POLL_TIMEOUT,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            )
        return self._client

    async def discover_collections(self) -> List[TAXIICollection]:
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.discovery_url}/taxii2/")
            resp.raise_for_status()
            api_root = resp.json().get("api_roots", [self.discovery_url])[0]

            api_resp = await client.get(f"{api_root}/collections/")
            api_resp.raise_for_status()
            collections = []
            for coll in api_resp.json().get("collections", []):
                collections.append(TAXIICollection(
                    name=coll.get("title", coll["id"]),
                    url=f"{api_root}/collections/{coll['id']}/",
                    collection_id=coll["id"],
                ))
            self._collections = collections
            log.info("TAXII discovery: %d collections from %s", len(collections), self.discovery_url)
            return collections
        except Exception as e:
            log.warning("TAXII discovery failed for %s: %s", self.discovery_url, e)
            return []

    async def poll_collection(self, collection: TAXIICollection, added_after: str = "") -> List[Dict[str, Any]]:
        client = await self._get_client()
        iocs = []
        try:
            params = {"match[spec_version]": "2.1"}
            if added_after:
                params["added_after"] = added_after
            resp = await client.get(f"{collection.url}objects/", params=params)
            resp.raise_for_status()
            data = resp.json()
            objects = data.get("objects", [])
            for obj in objects:
                if obj.get("type") in ("indicator", "malware", "attack-pattern", "threat-actor"):
                    ioc = self._parse_stix_object(obj)
                    if ioc:
                        iocs.append(ioc)
            log.info("TAXII poll %s: %d IOCs", collection.name, len(iocs))
        except Exception as e:
            log.warning("TAXII poll failed for %s: %s", collection.name, e)
        return iocs

    def _parse_stix_object(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        obj_type = obj.get("type", "")
        stix_id = obj.get("id", "")
        name = obj.get("name", "")
        description = obj.get("description", "")
        pattern = obj.get("pattern", "")
        labels = obj.get("labels", [])
        created = obj.get("created", "")

        indicators = []
        if pattern:
            import re
            matches = re.findall(r"\[(.+?)\]", pattern)
            for match in matches:
                parts = match.split("=")
                if len(parts) == 2:
                    key = parts[0].strip().strip("'")
                    value = parts[1].strip().strip("'")
                    if "ip" in key.lower():
                        indicators.append({"type": "ip", "value": value})
                    elif "domain" in key.lower():
                        indicators.append({"type": "domain", "value": value.lower()})
                    elif "url" in key.lower() or "uri" in key.lower():
                        indicators.append({"type": "url", "value": value})
                    elif "hash" in key.lower():
                        indicators.append({"type": "hash", "value": value.lower()})
                    elif "md5" in key.lower():
                        indicators.append({"type": "md5", "value": value.lower()})
                    elif "sha1" in key.lower():
                        indicators.append({"type": "sha1", "value": value.lower()})
                    elif "sha256" in key.lower():
                        indicators.append({"type": "sha256", "value": value.lower()})
                    elif "email" in key.lower() or "addr" in key.lower():
                        indicators.append({"type": "email", "value": value.lower()})

        if not indicators:
            return None

        return {
            "stix_id": stix_id,
            "name": name,
            "type": obj_type,
            "description": description,
            "indicators": indicators,
            "labels": labels,
            "created": created,
            "source": "taxii",
            "feed_url": self.discovery_url,
        }

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


async def poll_taxii_feed(
    discovery_url: str,
    username: str = "",
    password: str = "",
    collection_names: Optional[List[str]] = None,
    added_after: str = "",
) -> int:
    client = TAXIIClient(discovery_url, username, password)
    try:
        collections = await client.discover_collections()
        if collection_names:
            collections = [c for c in collections if c.name in collection_names]
        total = 0
        for coll in collections:
            iocs = await client.poll_collection(coll, added_after)
            for ioc in iocs:
                for ind in ioc.get("indicators", []):
                    await threat_intel_service.add_ioc(
                        indicator=ind["value"],
                        ioc_type=ind["type"],
                        metadata={
                            "source": "taxii",
                            "feed_url": discovery_url,
                            "stix_id": ioc.get("stix_id"),
                            "description": ioc.get("description", ""),
                            "labels": ioc.get("labels", []),
                            "created": ioc.get("created", ""),
                        },
                    )
            total += len(iocs)
        return total
    finally:
        await client.close()


async def poll_stix_feeds() -> int:
    settings = get_settings()
    total = 0

    taxii_url = getattr(settings, "integrations_taxii_url", "")
    if taxii_url:
        total += await poll_taxii_feed(
            discovery_url=taxii_url,
            username=getattr(settings, "integrations_taxii_username", ""),
            password=getattr(settings, "integrations_taxii_password", ""),
        )

    taxii2_url = getattr(settings, "integrations_taxii2_url", "")
    if taxii2_url:
        total += await poll_taxii_feed(
            discovery_url=taxii2_url,
            username=getattr(settings, "integrations_taxii2_username", ""),
            password=getattr(settings, "integrations_taxii2_password", ""),
        )

    return total
