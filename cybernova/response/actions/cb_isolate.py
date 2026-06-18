from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.response.actions.cb_isolate")

# ── Configuration ─────────────────────────────────────────────────────────────

CB_API_URL = os.environ.get("CYBERNOVA_CB_API_URL", "").rstrip("/")
CB_API_KEY = os.environ.get("CYBERNOVA_CB_API_KEY", "")
CB_API_SECRET = os.environ.get("CYBERNOVA_CB_API_SECRET", "")
CB_ORG_KEY = os.environ.get("CYBERNOVA_CB_ORG_KEY", "")


def _raise_if_not_configured():
    if not CB_API_URL or not CB_API_KEY or not CB_API_SECRET:
        raise ValueError(
            "Carbon Black API not configured. Set CYBERNOVA_CB_API_URL, "
            "CYBERNOVA_CB_API_KEY, and CYBERNOVA_CB_API_SECRET."
        )


def _basic_auth_header() -> Dict[str, str]:
    import base64
    raw = f"{CB_API_KEY}/{CB_API_SECRET}"
    encoded = base64.b64encode(raw.encode()).decode()
    return {"Authorization": f"Basic {encoded}", "Content-Type": "application/json"}


# ── API Client ────────────────────────────────────────────────────────────────

class CarbonBlackAPIClient:
    """Thin wrapper around the Carbon Black Defense / Response API.

    Supports:
      - Sensor isolation (CB Response / Enterprise EDR)
      - Hash banning (CB Defense cloud)
      - Sensor search and details
    """

    def __init__(
        self,
        api_url: str = CB_API_URL,
        api_key: str = CB_API_KEY,
        api_secret: str = CB_API_SECRET,
        org_key: str = CB_ORG_KEY,
    ):
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._api_secret = api_secret
        self._org_key = org_key

    @property
    def _headers(self) -> Dict[str, str]:
        return _basic_auth_header()

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        import httpx
        url = f"{self._api_url}{path}"
        headers = dict(self._headers)
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        resp = httpx.request(method, url, headers=headers, timeout=30, **kwargs)
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {"success": True}
        return resp.json()

    # ── Sensor Isolation (CB Response / Enterprise EDR) ───────────────────

    def isolate_sensor(self, sensor_id: int) -> Dict[str, Any]:
        """Isolate a sensor by ID.

        POST /api/v1/sensor/{sensor_id}/isolate
        """
        result = self._request("POST", f"/api/v1/sensor/{sensor_id}/isolate")
        log.info("Carbon Black isolated sensor %d", sensor_id)
        return result

    def unisolate_sensor(self, sensor_id: int) -> Dict[str, Any]:
        """Remove isolation from a sensor.

        POST /api/v1/sensor/{sensor_id}/unisolate
        """
        result = self._request("POST", f"/api/v1/sensor/{sensor_id}/unisolate")
        log.info("Carbon Black unisolated sensor %d", sensor_id)
        return result

    def get_sensor(self, sensor_id: int) -> Optional[Dict[str, Any]]:
        """Get sensor details by ID."""
        try:
            result = self._request("GET", f"/api/v1/sensor/{sensor_id}")
            return result
        except Exception as e:
            log.warning("Failed to get sensor %d: %s", sensor_id, e)
            return None

    def search_sensors(self, query: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search sensors using CB Response API."""
        params = f"?limit={limit}"
        if query:
            params += f"&q={query}"
        result = self._request("GET", f"/api/v1/sensor{params}")
        return result if isinstance(result, list) else result.get("results", [])

    def find_sensor_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        sensors = self.search_sensors(query=hostname)
        for s in sensors:
            if s.get("hostname", "").lower() == hostname.lower():
                return s
            if hostname.lower() in s.get("hostname", "").lower():
                return s
        return None

    # ── Hash Banning (CB Defense Cloud) ───────────────────────────────────

    def ban_hash(self, md5_hash: str, description: str = "") -> Dict[str, Any]:
        """Ban a file hash via CB Defense cloud API.

        POST /banning/v1/ban
        """
        payload: Dict[str, Any] = {
            "md5_hash": md5_hash,
            "description": description or "Banned by CyberNova SOAR",
            "enabled": True,
        }
        result = self._request("POST", "/banning/v1/ban", json=payload)
        log.info("Carbon Black banned hash %s", md5_hash)
        return result

    def unban_hash(self, md5_hash: str) -> Dict[str, Any]:
        """Remove a hash ban."""
        result = self._request("DELETE", f"/banning/v1/ban/{md5_hash}")
        log.info("Carbon Black unbanned hash %s", md5_hash)
        return result

    def get_ban(self, md5_hash: str) -> Optional[Dict[str, Any]]:
        """Check if a hash is banned."""
        try:
            result = self._request("GET", f"/banning/v1/ban/{md5_hash}")
            return result
        except Exception:
            return None

    def list_bans(self, limit: int = 100) -> List[Dict[str, Any]]:
        result = self._request("GET", f"/banning/v1/ban?limit={limit}")
        return result if isinstance(result, list) else result.get("results", [])

    # ── Live Response Session Isolation (CB Defense) ──────────────────────

    def create_live_response_session(self, sensor_id: int) -> Optional[str]:
        """Create a live response session for a sensor.

        POST /api/v1/cblr/session
        """
        result = self._request(
            "POST", "/api/v1/cblr/session",
            json={"sensor_id": sensor_id},
        )
        session_id = result.get("id")
        if session_id:
            log.info("Created Live Response session %s for sensor %d", session_id, sensor_id)
            return str(session_id)
        return None

    def isolate_via_live_response(self, sensor_id: int) -> Dict[str, Any]:
        """Isolate a sensor via Live Response session.

        POST /api/v1/cblr/session/{session_id}/isolate
        """
        session_id = self.create_live_response_session(sensor_id)
        if not session_id:
            return {"success": False, "error": "Failed to create Live Response session"}

        self._request("POST", f"/api/v1/cblr/session/{session_id}/isolate")
        log.info("Carbon Black isolated sensor %d via Live Response", sensor_id)
        return {"success": True, "sensor_id": sensor_id, "session_id": session_id}

    @staticmethod
    def is_available() -> bool:
        return bool(CB_API_URL and CB_API_KEY and CB_API_SECRET)


# ── CB Isolate Action ────────────────────────────────────────────────────────

class CarbonBlackIsolateAction:
    """Isolate a host and/or ban a hash via Carbon Black API.

    Supports two modes:
      - Sensor isolation (CB Response / Enterprise EDR)
      - Hash banning (CB Defense cloud)

    Usage:
        action = CarbonBlackIsolateAction()
        result = action.isolate_host("12345")
        result = action.ban_hash("d41d8cd98f00b204e9800998ecf8427e")
    """

    def __init__(
        self,
        api_url: str = CB_API_URL,
        api_key: str = CB_API_KEY,
        api_secret: str = CB_API_SECRET,
        org_key: str = CB_ORG_KEY,
    ):
        _raise_if_not_configured()
        self._api_url = api_url
        self._api_key = api_key
        self._api_secret = api_secret
        self._org_key = org_key
        self._client: Optional[CarbonBlackAPIClient] = None

    @property
    def client(self) -> CarbonBlackAPIClient:
        if self._client is None:
            self._client = CarbonBlackAPIClient(
                api_url=self._api_url,
                api_key=self._api_key,
                api_secret=self._api_secret,
                org_key=self._org_key,
            )
        return self._client

    def isolate_host(self, sensor_id: str, reason: str = "",
                     use_live_response: bool = False) -> Dict[str, Any]:
        """Isolate a sensor by ID.

        Args:
            sensor_id: Numeric sensor ID (string or int).
            reason: Description for the action.
            use_live_response: If True, isolate via Live Response session.
        """
        try:
            sid = int(sensor_id)
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid sensor_id: {sensor_id}"}

        check = self.client.get_sensor(sid)
        if check is None:
            return {"success": False, "error": f"Sensor {sensor_id} not found"}

        if check.get("status") == "ACTIVE" and check.get("is_isolating", False):
            log.info("Sensor %d already isolating", sid)
            return {"success": True, "sensor_id": sensor_id, "already_isolated": True}

        try:
            if use_live_response:
                result = self.client.isolate_via_live_response(sid)
            else:
                self.client.isolate_sensor(sid)
                result = {"success": True, "sensor_id": sensor_id}

            if result.get("success"):
                log.warning("Carbon Black isolated sensor %s (%s)", sensor_id, reason or "SOAR automation")
            return result
        except Exception as e:
            log.exception("Carbon Black isolate failed for sensor %s", sensor_id)
            return {"success": False, "error": str(e), "sensor_id": sensor_id}

    def unisolate_host(self, sensor_id: str) -> Dict[str, Any]:
        """Remove isolation from a sensor."""
        try:
            sid = int(sensor_id)
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid sensor_id: {sensor_id}"}

        try:
            self.client.unisolate_sensor(sid)
            log.info("Carbon Black unisolated sensor %s", sensor_id)
            return {"success": True, "sensor_id": sensor_id}
        except Exception as e:
            log.exception("Carbon Black unisolate failed for sensor %s", sensor_id)
            return {"success": False, "error": str(e), "sensor_id": sensor_id}

    def ban_hash(self, md5_hash: str, description: str = "") -> Dict[str, Any]:
        """Ban a file hash via CB Defense."""
        if not md5_hash or len(md5_hash) != 32:
            return {"success": False, "error": "Invalid MD5 hash"}

        existing = self.client.get_ban(md5_hash)
        if existing:
            log.info("Hash %s already banned", md5_hash)
            return {"success": True, "hash": md5_hash, "already_banned": True}

        try:
            self.client.ban_hash(md5_hash, description=description)
            log.warning("Carbon Black banned hash %s (%s)", md5_hash, description or "SOAR automation")
            return {"success": True, "hash": md5_hash}
        except Exception as e:
            log.exception("Carbon Black ban hash failed for %s", md5_hash)
            return {"success": False, "error": str(e), "hash": md5_hash}

    def unban_hash(self, md5_hash: str) -> Dict[str, Any]:
        """Remove a hash ban."""
        try:
            self.client.unban_hash(md5_hash)
            return {"success": True, "hash": md5_hash}
        except Exception as e:
            return {"success": False, "error": str(e), "hash": md5_hash}

    def find_sensor(self, hostname: str) -> Dict[str, Any]:
        """Find a sensor by hostname."""
        sensor = self.client.find_sensor_by_hostname(hostname)
        if not sensor:
            return {"success": False, "error": f"Sensor not found: {hostname}"}
        return {
            "success": True,
            "sensor_id": str(sensor.get("id")),
            "hostname": sensor.get("hostname"),
            "status": sensor.get("status"),
            "os": sensor.get("os_environment"),
            "version": sensor.get("sensor_version"),
            "is_isolating": sensor.get("is_isolating", False),
            "last_seen": sensor.get("last_checkin_time"),
        }

    @staticmethod
    def is_available() -> bool:
        return CarbonBlackAPIClient.is_available()


# ── SOAR Integration ──────────────────────────────────────────────────────────

def execute_cb_isolate(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point for the SOAR engine to call Carbon Black isolate.

    Supports both sensor isolation and hash banning.
    For isolation: provide 'sensor_id' or 'hostname'.
    For hash ban: provide 'md5_hash'.

    Configure CYBERNOVA_CB_API_URL, CYBERNOVA_CB_API_KEY, CYBERNOVA_CB_API_SECRET.
    """
    sensor_id = incident.get("sensor_id") or incident.get("device_id", "")
    hostname = incident.get("hostname", "")
    md5_hash = incident.get("md5_hash", "")

    try:
        action = CarbonBlackIsolateAction()

        if md5_hash:
            return action.ban_hash(md5_hash, description=incident.get("title", ""))

        if not sensor_id and hostname:
            lookup = action.find_sensor(hostname)
            if not lookup.get("success"):
                return lookup
            sensor_id = lookup.get("sensor_id", "")

        if not sensor_id:
            return {"success": False, "error": "No sensor_id, hostname, or md5_hash in incident"}

        return action.isolate_host(sensor_id, reason=incident.get("title", ""))
    except ImportError:
        return {"success": False, "error": "httpx not installed"}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.exception("Carbon Black isolate action failed")
        return {"success": False, "error": str(e)}
