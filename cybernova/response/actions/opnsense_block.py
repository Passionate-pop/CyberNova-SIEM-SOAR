from __future__ import annotations

import httpx
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.response.actions.opnsense_block")

# ── Configuration ─────────────────────────────────────────────────────────────

OPN_API_URL = os.environ.get("CYBERNOVA_OPN_API_URL", "").rstrip("/")
OPN_API_KEY = os.environ.get("CYBERNOVA_OPN_API_KEY", "")
OPN_API_SECRET = os.environ.get("CYBERNOVA_OPN_API_SECRET", "")
OPN_ALIAS_NAME = os.environ.get("CYBERNOVA_OPN_ALIAS_NAME", "CyberNova_Blocked_IPs")
OPN_ALIAS_DESCRIPTION = os.environ.get(
    "CYBERNOVA_OPN_ALIAS_DESCRIPTION", "CyberNova SOAR blocked IPs",
)
OPN_RULE_SEQUENCE = int(os.environ.get("CYBERNOVA_OPN_RULE_SEQUENCE", "1"))
OPN_INTERFACE = os.environ.get("CYBERNOVA_OPN_INTERFACE", "wan")


def _raise_if_not_configured():
    if not OPN_API_URL or not OPN_API_KEY or not OPN_API_SECRET:
        raise ValueError(
            "OPNsense API not configured. Set CYBERNOVA_OPN_API_URL, "
            "CYBERNOVA_OPN_API_KEY, and CYBERNOVA_OPN_API_SECRET."
        )


# ── HTTP Client ───────────────────────────────────────────────────────────────

class OPNsenseAPIClient:
    """Thin wrapper around the OPNsense REST API using httpx digest auth."""

    def __init__(
        self,
        base_url: str = OPN_API_URL,
        api_key: str = OPN_API_KEY,
        api_secret: str = OPN_API_SECRET,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._api_secret = api_secret

    def _request(self, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        import httpx
        from httpx import DigestAuth
        url = f"{self._base_url}{path}"
        auth = DigestAuth(self._api_key, self._api_secret)
        resp = httpx.request(method, url, auth=auth, json=json, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ── Alias Management ──────────────────────────────────────────────────

    def get_alias(self, name: str = OPN_ALIAS_NAME) -> Optional[Dict[str, Any]]:
        try:
            result = self._request("GET", f"/api/firewall/alias/get/{name}")
            alias = result.get("alias", {})
            if alias.get("name") == name:
                return alias
            return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    def create_alias(
        self,
        name: str = OPN_ALIAS_NAME,
        description: str = OPN_ALIAS_DESCRIPTION,
        addresses: Optional[List[str]] = None,
    ) -> bool:
        payload = {
            "alias": {
                "enabled": "1",
                "name": name,
                "type": "network",
                "content": (addresses or []),
                "description": description,
                "proto": "",
                "updatefreq": "",
                "counters": "",
            }
        }
        self._request("POST", "/api/firewall/alias/set", json=payload)
        log.info("Created OPNsense alias '%s' with %d entries", name, len(addresses or []))
        return True

    def update_alias(
        self,
        name: str,
        addresses: List[str],
        description: str = OPN_ALIAS_DESCRIPTION,
    ) -> bool:
        payload = {
            "alias": {
                "enabled": "1",
                "name": name,
                "type": "network",
                "content": addresses,
                "description": description,
            }
        }
        self._request("POST", f"/api/firewall/alias/set/{name}", json=payload)
        log.info("Updated OPNsense alias '%s' (%d entries)", name, len(addresses))
        return True

    def add_to_alias(self, name: str, cidr: str) -> bool:
        payload = {"alias": {"address": cidr}}
        self._request("POST", f"/api/firewall/alias/addItem/{name}", json=payload)
        log.info("Added %s to OPNsense alias '%s'", cidr, name)
        return True

    def remove_from_alias(self, name: str, cidr: str) -> bool:
        payload = {"alias": {"address": cidr}}
        self._request("POST", f"/api/firewall/alias/delItem/{name}", json=payload)
        log.info("Removed %s from OPNsense alias '%s'", cidr, name)
        return True

    def list_alias_addresses(self, name: str) -> List[str]:
        alias = self.get_alias(name)
        if not alias:
            return []
        content = alias.get("content", "")
        if not content:
            return []
        return [c.strip() for c in content.split("\n") if c.strip()]

    # ── Rule Management ───────────────────────────────────────────────────

    def get_block_rule(self, alias_name: str) -> Optional[Dict[str, Any]]:
        result = self._request("GET", "/api/firewall/rule/searchRule")
        rows = result.get("rows", [])
        for row in rows:
            if alias_name in str(row):
                return row
        return None

    def create_block_rule(
        self,
        alias_name: str = OPN_ALIAS_NAME,
        interface: str = OPN_INTERFACE,
        sequence: int = OPN_RULE_SEQUENCE,
        description: str = "CyberNova SOAR block rule",
    ) -> bool:
        existing = self.get_block_rule(alias_name)
        if existing:
            log.info("Block rule for alias '%s' already exists (seq=%s)", alias_name, existing.get("sequence"))
            return True

        payload = {
            "rule": {
                "enabled": "1",
                "sequence": str(sequence),
                "interface": interface,
                "direction": "in",
                "protocol": "any",
                "source_net": alias_name,
                "source_not": "0",
                "destination_net": "any",
                "destination_not": "0",
                "target": "block",
                "log": "1",
                "description": description,
            }
        }
        self._request("POST", "/api/firewall/rule/addRule", json=payload)
        self._apply_changes()
        log.info("Created OPNsense block rule for alias '%s' on %s (seq=%s)", alias_name, interface, sequence)
        return True

    # ── Apply Changes ─────────────────────────────────────────────────────

    def _apply_changes(self) -> bool:
        try:
            self._request("POST", "/api/firewall/rule/apply")
            self._request("POST", "/api/firewall/alias/apply")
            log.info("Applied OPNsense firewall changes")
            return True
        except Exception as e:
            log.warning("OPNsense apply changes failed: %s", e)
            return False

    def reload_all(self) -> bool:
        return self._apply_changes()

    @staticmethod
    def is_available() -> bool:
        return bool(OPN_API_URL and OPN_API_KEY and OPN_API_SECRET)


# ── OPNsense Block Action ────────────────────────────────────────────────────

class OPNsenseBlockAction:
    """Block an IP address via OPNsense firewall alias + block rule.

    Creates or updates a network alias (list of blocked IPs) and ensures
    a block rule exists on the WAN interface referencing that alias.

    Usage:
        action = OPNsenseBlockAction()
        result = action.block_ip("203.0.113.5", reason="SSH brute force")
        # Returns: {"success": True, "cidr": "203.0.113.5/32", "alias": "CyberNova_Blocked_IPs"}
    """

    def __init__(
        self,
        base_url: str = OPN_API_URL,
        api_key: str = OPN_API_KEY,
        api_secret: str = OPN_API_SECRET,
        alias_name: str = OPN_ALIAS_NAME,
        interface: str = OPN_INTERFACE,
        sequence: int = OPN_RULE_SEQUENCE,
    ):
        _raise_if_not_configured()
        self.alias_name = alias_name
        self.interface = interface
        self.sequence = sequence
        self._client: Optional[OPNsenseAPIClient] = None

    @property
    def client(self) -> OPNsenseAPIClient:
        if self._client is None:
            self._client = OPNsenseAPIClient(
                base_url=OPN_API_URL,
                api_key=OPN_API_KEY,
                api_secret=OPN_API_SECRET,
            )
        return self._client

    def block_ip(self, ip_address: str, reason: str = "") -> Dict[str, Any]:
        """Block an IP by adding it to the alias and ensuring the block rule exists."""
        cidr = self._to_cidr(ip_address)
        alias = self.client.get_alias(self.alias_name)

        if alias:
            current = self.client.list_alias_addresses(self.alias_name)
            if cidr in current:
                log.info("IP %s (%s) already in alias '%s'", ip_address, cidr, self.alias_name)
            else:
                self.client.add_to_alias(self.alias_name, cidr)
            self.client.reload_all()
        else:
            self.client.create_alias(
                name=self.alias_name,
                description=reason or OPN_ALIAS_DESCRIPTION,
                addresses=[cidr],
            )
            self.client.create_block_rule(
                alias_name=self.alias_name,
                interface=self.interface,
                sequence=self.sequence,
                description=f"CyberNova SOAR: {reason or 'block IP'}",
            )
            self.client.reload_all()

        log.warning("OPNsense blocked IP %s (%s) in alias '%s'", ip_address, cidr, self.alias_name)
        return {
            "success": True,
            "ip": ip_address,
            "cidr": cidr,
            "alias": self.alias_name,
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove an IP from the alias."""
        cidr = self._to_cidr(ip_address)
        current = self.client.list_alias_addresses(self.alias_name)
        if cidr not in current:
            return {"success": True, "ip": ip_address, "already_absent": True}

        self.client.remove_from_alias(self.alias_name, cidr)
        self.client.reload_all()
        log.info("Unblocked IP %s from OPNsense alias '%s'", ip_address, self.alias_name)
        return {"success": True, "ip": ip_address}

    def list_blocked(self) -> Dict[str, Any]:
        """List all IPs in the block alias."""
        addresses = self.client.list_alias_addresses(self.alias_name)
        return {"success": True, "alias": self.alias_name, "blocked_ips": addresses, "count": len(addresses)}

    @staticmethod
    def _to_cidr(ip: str) -> str:
        ip = ip.strip()
        if "/" in ip:
            return ip
        return f"{ip}/32"

    @staticmethod
    def is_available() -> bool:
        return OPNsenseAPIClient.is_available()


# ── SOAR Integration ──────────────────────────────────────────────────────────

def execute_opnsense_block_ip(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point for the SOAR engine to call OPNsense block.

    Expects incident dict with 'source_ip' or 'dest_ip'.
    Requires CYBERNOVA_OPN_API_URL, CYBERNOVA_OPN_API_KEY, CYBERNOVA_OPN_API_SECRET.
    """
    ip = incident.get("dest_ip") or incident.get("source_ip")
    if not ip:
        return {"success": False, "error": "No IP address in incident"}

    try:
        action = OPNsenseBlockAction()
        return action.block_ip(ip, reason=incident.get("title", ""))
    except ImportError:
        return {"success": False, "error": "httpx not installed"}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.exception("OPNsense block action failed")
        return {"success": False, "error": str(e)}
