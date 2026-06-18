from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.response.actions.sentinelone_isolate")

# ── Configuration ─────────────────────────────────────────────────────────────

S1_API_URL = os.environ.get("CYBERNOVA_S1_API_URL", "").rstrip("/")
S1_API_TOKEN = os.environ.get("CYBERNOVA_S1_API_TOKEN", "")
S1_ACCOUNT_ID = os.environ.get("CYBERNOVA_S1_ACCOUNT_ID", "")


def _raise_if_not_configured():
    if not S1_API_URL or not S1_API_TOKEN:
        raise ValueError(
            "SentinelOne API not configured. Set CYBERNOVA_S1_API_URL "
            "and CYBERNOVA_S1_API_TOKEN."
        )


# ── API Client ────────────────────────────────────────────────────────────────

class SentinelOneAPIClient:
    """Thin wrapper around the SentinelOne Management REST API."""

    def __init__(
        self,
        api_url: str = S1_API_URL,
        api_token: str = S1_API_TOKEN,
        account_id: str = S1_ACCOUNT_ID,
    ):
        self._api_url = api_url.rstrip("/")
        self._api_token = api_token
        self._account_id = account_id

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"ApiToken {self._api_token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        import httpx
        url = f"{self._api_url}{path}"
        headers = self._headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        resp = httpx.request(method, url, headers=headers, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def disconnect_agent(self, agent_id: str) -> Dict[str, Any]:
        """Disconnect an agent from the network (isolate).

        POST /web/api/v2.1/agents/actions/disconnect-from-network
        """
        payload = {
            "filter": {"ids": [agent_id]},
        }
        result = self._request(
            "POST",
            "/web/api/v2.1/agents/actions/disconnect-from-network",
            json=payload,
        )
        affected = result.get("data", {}).get("affected", 0)
        log.info("SentinelOne disconnect agent %s (affected=%d)", agent_id, affected)
        return result

    def disconnect_by_hostname(self, hostname: str) -> Dict[str, Any]:
        """Disconnect agents matching a hostname pattern."""
        payload = {
            "filter": {"hostname__contains": hostname},
        }
        result = self._request(
            "POST",
            "/web/api/v2.1/agents/actions/disconnect-from-network",
            json=payload,
        )
        affected = result.get("data", {}).get("affected", 0)
        log.info("SentinelOne disconnect by hostname '%s' (affected=%d)", hostname, affected)
        return result

    def connect_agent(self, agent_id: str) -> Dict[str, Any]:
        """Reconnect an agent to the network (undo isolation).

        POST /web/api/v2.1/agents/actions/connect-to-network
        """
        payload = {
            "filter": {"ids": [agent_id]},
        }
        result = self._request(
            "POST", "/web/api/v2.1/agents/actions/connect-to-network",
            json=payload,
        )
        affected = result.get("data", {}).get("affected", 0)
        log.info("SentinelOne connect agent %s (affected=%d)", agent_id, affected)
        return result

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent details by ID."""
        result = self._request(
            "GET",
            f"/web/api/v2.1/agents?ids={agent_id}",
        )
        agents = result.get("data", [])
        return agents[0] if agents else None

    def search_agents(
        self,
        filter_str: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search agents using SentinelOne filter syntax."""
        params = f"?limit={limit}"
        if filter_str:
            params += f"&{filter_str}"
        result = self._request("GET", f"/web/api/v2.1/agents{params}")
        return result.get("data", [])

    def find_agent_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Find an agent by exact hostname match."""
        agents = self.search_agents(filter_str=f"hostname={hostname}")
        return agents[0] if agents else None

    def get_agent_network_status(self, agent_id: str) -> Optional[str]:
        """Get the current network connectivity status of an agent."""
        agent = self.get_agent(agent_id)
        if agent:
            return agent.get("networkStatus")
        return None

    @staticmethod
    def is_available() -> bool:
        return bool(S1_API_URL and S1_API_TOKEN)


# ── SentinelOne Isolate Action ───────────────────────────────────────────────

class SentinelOneIsolateAction:
    """Isolate a host via SentinelOne MGMT API (disconnect-from-network).

    Usage:
        action = SentinelOneIsolateAction()
        result = action.isolate_host("1234567890abcdef")
        # Returns: {"success": True, "agent_id": "...", "action": "disconnect-from-network"}
    """

    def __init__(
        self,
        api_url: str = S1_API_URL,
        api_token: str = S1_API_TOKEN,
        account_id: str = S1_ACCOUNT_ID,
    ):
        _raise_if_not_configured()
        self._api_url = api_url
        self._api_token = api_token
        self._account_id = account_id
        self._client: Optional[SentinelOneAPIClient] = None

    @property
    def client(self) -> SentinelOneAPIClient:
        if self._client is None:
            self._client = SentinelOneAPIClient(
                api_url=self._api_url,
                api_token=self._api_token,
                account_id=self._account_id,
            )
        return self._client

    def isolate_host(self, agent_id: str, reason: str = "") -> Dict[str, Any]:
        """Disconnect an agent from the network via SentinelOne API."""
        if not agent_id:
            return {"success": False, "error": "agent_id is required"}

        try:
            status_before = self.client.get_agent_network_status(agent_id)
            if status_before == "disconnected":
                log.info("Agent %s already disconnected (networkStatus=%s)", agent_id, status_before)
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "action": "disconnect-from-network",
                    "already_isolated": True,
                    "previous_status": status_before,
                }

            result = self.client.disconnect_agent(agent_id)
            affected = result.get("data", {}).get("affected", 0)

            if affected > 0:
                log.warning(
                    "SentinelOne isolated agent %s (%s)",
                    agent_id, reason or "SOAR automation",
                )
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "action": "disconnect-from-network",
                    "affected": affected,
                    "previous_status": status_before,
                }
            else:
                return {
                    "success": False,
                    "error": "No agents affected by disconnect action",
                    "agent_id": agent_id,
                }
        except Exception as e:
            log.exception("SentinelOne isolate failed for agent %s", agent_id)
            return {"success": False, "error": str(e), "agent_id": agent_id}

    def lift_isolation(self, agent_id: str) -> Dict[str, Any]:
        """Reconnect an agent to the network (undo isolation)."""
        try:
            result = self.client.connect_agent(agent_id)
            affected = result.get("data", {}).get("affected", 0)
            if affected > 0:
                log.info("SentinelOne reconnected agent %s to network", agent_id)
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "action": "connect-to-network",
                    "affected": affected,
                }
            return {
                "success": False,
                "error": "No agents affected by connect action",
                "agent_id": agent_id,
            }
        except Exception as e:
            log.exception("SentinelOne reconnect failed for agent %s", agent_id)
            return {"success": False, "error": str(e), "agent_id": agent_id}

    def find_agent(self, hostname: str) -> Dict[str, Any]:
        """Find an agent by hostname."""
        agent = self.client.find_agent_by_hostname(hostname)
        if not agent:
            return {"success": False, "error": f"Agent not found: {hostname}"}
        return {
            "success": True,
            "agent_id": agent.get("id"),
            "hostname": agent.get("hostname", hostname),
            "os": agent.get("osType"),
            "os_version": agent.get("osVersion"),
            "network_status": agent.get("networkStatus"),
            "ip": agent.get("externalIp") or agent.get("localIp"),
            "domain": agent.get("domain"),
            "is_active": agent.get("isActive"),
            "last_seen": agent.get("lastActiveDate"),
        }

    @staticmethod
    def is_available() -> bool:
        return SentinelOneAPIClient.is_available()


# ── SOAR Integration ──────────────────────────────────────────────────────────

def execute_sentinelone_isolate(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point for the SOAR engine to call SentinelOne isolate.

    Expects incident dict with 'agent_id' or 'hostname'.
    Configure CYBERNOVA_S1_API_URL and CYBERNOVA_S1_API_TOKEN.
    """
    agent_id = incident.get("agent_id") or incident.get("device_id", "")
    hostname = incident.get("hostname", "")

    try:
        action = SentinelOneIsolateAction()

        if not agent_id and hostname:
            lookup = action.find_agent(hostname)
            if not lookup.get("success"):
                return lookup
            agent_id = lookup.get("agent_id", "")

        if not agent_id:
            return {"success": False, "error": "No agent_id or hostname in incident"}

        return action.isolate_host(agent_id, reason=incident.get("title", ""))
    except ImportError:
        return {"success": False, "error": "httpx not installed"}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.exception("SentinelOne isolate action failed")
        return {"success": False, "error": str(e)}
