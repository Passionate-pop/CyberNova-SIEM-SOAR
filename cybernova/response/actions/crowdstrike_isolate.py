from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.response.actions.crowdstrike_isolate")

# ── Configuration ─────────────────────────────────────────────────────────────

CS_CLIENT_ID = os.environ.get("CYBERNOVA_CS_CLIENT_ID", "")
CS_CLIENT_SECRET = os.environ.get("CYBERNOVA_CS_CLIENT_SECRET", "")
CS_BASE_URL = os.environ.get("CYBERNOVA_CS_BASE_URL", "https://api.crowdstrike.com")


def _raise_if_not_configured():
    if not CS_CLIENT_ID or not CS_CLIENT_SECRET:
        raise ValueError(
            "CrowdStrike API not configured. Set CYBERNOVA_CS_CLIENT_ID "
            "and CYBERNOVA_CS_CLIENT_SECRET."
        )


# ── OAuth2 Token ──────────────────────────────────────────────────────────────

class TokenManager:
    """Manages OAuth2 access tokens for the CrowdStrike Falcon API."""

    def __init__(self, client_id: str, client_secret: str, base_url: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._expires_at: float = 0

    def get_token(self) -> str:
        if self._token and time.time() < self._expires_at - 60:
            return self._token

        import httpx
        url = f"{self._base_url}/oauth2/token"
        resp = httpx.post(
            url,
            data={"client_id": self._client_id, "client_secret": self._client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + data.get("expires_in", 1800)
        log.debug("Obtained CrowdStrike OAuth2 token (expires in %ds)", data.get("expires_in", 0))
        return self._token


# ── Falcon API Client ─────────────────────────────────────────────────────────

class FalconAPIClient:
    """Thin wrapper around the CrowdStrike Falcon API with OAuth2 auth."""

    def __init__(
        self,
        client_id: str = CS_CLIENT_ID,
        client_secret: str = CS_CLIENT_SECRET,
        base_url: str = CS_BASE_URL,
    ):
        _raise_if_not_configured()
        self._base_url = base_url.rstrip("/")
        self._token_mgr = TokenManager(client_id, client_secret, base_url)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token_mgr.get_token()}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        import httpx
        url = f"{self._base_url}{path}"
        headers = self._headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        resp = httpx.request(method, url, headers=headers, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def get_host_id_by_device_id(self, device_id: str) -> Optional[str]:
        """Resolve a device ID to the CrowdStrike agent ID (AID)."""
        results = self._request(
            "GET",
            f"/api/v1/hosts/entities/hosts/v1?ids={device_id}",
        )
        resources = results.get("resources", [])
        return resources[0] if resources else None

    def perform_action_v2(
        self,
        action_id: str = "network_isolation",
        device_ids: Optional[List[str]] = None,
        action_params: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Call PerformActionV2 on one or more hosts.

        Common actions: network_isolation, contain, lift_containment.
        """
        payload: Dict[str, Any] = {
            "action_parameters": action_params or [
                {"name": action_id, "value": "true"},
            ],
        }
        ids_param = "&".join(f"ids={did}" for did in (device_ids or []))
        result = self._request(
            "POST",
            f"/api/v1/entities/actions/host/v2?{ids_param}",
            json=payload,
        )
        return result

    def isolate_host(self, device_id: str) -> Dict[str, Any]:
        """Isolate a single host via network_isolation action."""
        result = self.perform_action_v2(
            action_id="network_isolation",
            device_ids=[device_id],
            action_params=[{"name": "network_isolation", "value": "true"}],
        )
        log.info("CrowdStrike isolate host %s: %s", device_id, result.get("status", "?"))
        return result

    def lift_isolation(self, device_id: str) -> Dict[str, Any]:
        """Remove isolation from a host."""
        result = self.perform_action_v2(
            action_id="network_isolation",
            device_ids=[device_id],
            action_params=[{"name": "network_isolation", "value": "false"}],
        )
        log.info("CrowdStrike lift isolation for host %s", device_id)
        return result

    def get_host_details(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed host information by device ID."""
        result = self._request(
            "GET",
            f"/api/v1/hosts/entities/hosts/v1?ids={device_id}",
        )
        resources = result.get("resources", [])
        if resources:
            return resources[0]
        return None

    def search_hosts(
        self,
        filter_str: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search for hosts using Falcon Query Language (FQL)."""
        params = f"?limit={limit}"
        if filter_str:
            params += f"&filter={filter_str}"
        result = self._request("GET", f"/api/v1/hosts/queries/devices/v1{params}")
        return result.get("resources", [])

    @staticmethod
    def is_available() -> bool:
        return bool(CS_CLIENT_ID and CS_CLIENT_SECRET)


# ── CrowdStrike Isolate Action ───────────────────────────────────────────────

class CrowdStrikeIsolateAction:
    """Isolate a host via CrowdStrike Falcon PerformActionV2 (network_isolation).

    Usage:
        action = CrowdStrikeIsolateAction()
        result = action.isolate_host("1234567890abcdef")
        # Returns: {"success": True, "device_id": "...", "action": "network_isolation"}
    """

    def __init__(
        self,
        client_id: str = CS_CLIENT_ID,
        client_secret: str = CS_CLIENT_SECRET,
        base_url: str = CS_BASE_URL,
    ):
        _raise_if_not_configured()
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url
        self._client: Optional[FalconAPIClient] = None

    @property
    def client(self) -> FalconAPIClient:
        if self._client is None:
            self._client = FalconAPIClient(
                client_id=self._client_id,
                client_secret=self._client_secret,
                base_url=self._base_url,
            )
        return self._client

    def isolate_host(self, device_id: str, reason: str = "") -> Dict[str, Any]:
        """Apply network isolation to a CrowdStrike-managed host."""
        if not device_id:
            return {"success": False, "error": "device_id is required"}

        try:
            result = self.client.isolate_host(device_id)
            errors = result.get("errors", [])
            if errors:
                return {"success": False, "error": str(errors), "device_id": device_id}

            resources = result.get("resources", [])
            log.warning(
                "CrowdStrike isolated host %s (%s)",
                device_id, reason or "SOAR automation",
            )
            return {
                "success": True,
                "device_id": device_id,
                "action": "network_isolation",
                "resources": resources,
                "status": result.get("status", "unknown"),
            }
        except Exception as e:
            log.exception("CrowdStrike isolate failed for %s", device_id)
            return {"success": False, "error": str(e), "device_id": device_id}

    def lift_isolation(self, device_id: str) -> Dict[str, Any]:
        """Remove network isolation from a host."""
        try:
            result = self.client.lift_isolation(device_id)
            errors = result.get("errors", [])
            if errors:
                return {"success": False, "error": str(errors), "device_id": device_id}

            log.info("CrowdStrike lifted isolation for host %s", device_id)
            return {
                "success": True,
                "device_id": device_id,
                "action": "lift_network_isolation",
            }
        except Exception as e:
            log.exception("CrowdStrike lift isolation failed for %s", device_id)
            return {"success": False, "error": str(e), "device_id": device_id}

    def get_host_info(self, device_id: str) -> Dict[str, Any]:
        """Get host details from CrowdStrike."""
        host = self.client.get_host_details(device_id)
        if not host:
            return {"success": False, "error": "Host not found", "device_id": device_id}
        return {
            "success": True,
            "device_id": device_id,
            "hostname": host.get("hostname"),
            "os": host.get("os_version"),
            "status": host.get("status"),
            "last_seen": host.get("last_seen"),
            "external_ip": host.get("external_ip"),
            "local_ip": host.get("local_ip"),
            "platform": host.get("platform_name"),
        }

    def find_host_by_hostname(self, hostname: str) -> Dict[str, Any]:
        """Search for a host by hostname in CrowdStrike."""
        results = self.client.search_hosts(filter_str=f"hostname:*'*{hostname}*'")
        if not results:
            return {"success": False, "error": f"No host found matching '{hostname}'"}
        host_id = results[0]
        return self.get_host_info(host_id)

    @staticmethod
    def is_available() -> bool:
        return FalconAPIClient.is_available()


# ── SOAR Integration ──────────────────────────────────────────────────────────

def execute_crowdstrike_isolate(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point for the SOAR engine to call CrowdStrike isolate.

    Expects incident dict with 'device_id' or 'hostname'.
    Configure CYBERNOVA_CS_CLIENT_ID and CYBERNOVA_CS_CLIENT_SECRET.
    """
    device_id = incident.get("device_id", "")
    hostname = incident.get("hostname", "")

    try:
        action = CrowdStrikeIsolateAction()

        if not device_id and hostname:
            lookup = action.find_host_by_hostname(hostname)
            if not lookup.get("success"):
                return lookup
            device_id = lookup.get("device_id", "")

        if not device_id:
            return {"success": False, "error": "No device_id or hostname in incident"}

        return action.isolate_host(device_id, reason=incident.get("title", ""))
    except ImportError:
        return {"success": False, "error": "httpx not installed"}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.exception("CrowdStrike isolate action failed")
        return {"success": False, "error": str(e)}
