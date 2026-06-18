from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.response.actions.cloudflare_block")

# ── Configuration ─────────────────────────────────────────────────────────────

CF_API_TOKEN = os.environ.get("CYBERNOVA_CLOUDFLARE_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CYBERNOVA_CLOUDFLARE_ACCOUNT_ID", "")
CF_ZONE_ID = os.environ.get("CYBERNOVA_CLOUDFLARE_ZONE_ID", "")
CF_API_BASE = "https://api.cloudflare.com/client/v4"


# ── HTTP Client ───────────────────────────────────────────────────────────────

class CloudflareAPIClient:
    """Thin wrapper around Cloudflare v4 REST API with httpx."""

    def __init__(
        self,
        api_token: str = CF_API_TOKEN,
        account_id: str = CF_ACCOUNT_ID,
        zone_id: str = CF_ZONE_ID,
    ):
        self._api_token = api_token
        self._account_id = account_id
        self._zone_id = zone_id

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        import httpx
        url = f"{CF_API_BASE}{path}"
        resp = httpx.request(method, url, headers=self._headers, json=json, timeout=15)
        data = resp.json()
        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare API error: {errors}")
        return data

    def create_access_rule(self, ip: str, notes: str = "", mode: str = "block") -> Dict[str, Any]:
        """Create an IP Access Rule at the account level."""
        payload: Dict[str, Any] = {
            "mode": mode,
            "configuration": {
                "target": "ip",
                "value": ip,
            },
            "notes": notes or "Blocked by CyberNova SOAR",
        }
        path = f"/accounts/{self._account_id}/firewall/access_rules/rules"
        result = self._request("POST", path, json=payload)
        rule = result.get("result", {})
        log.info("Created Cloudflare access rule %s (mode=%s, ip=%s)", rule.get("id"), mode, ip)
        return rule

    def create_zone_access_rule(self, ip: str, notes: str = "", mode: str = "block") -> Dict[str, Any]:
        """Create an IP Access Rule at the zone level."""
        if not self._zone_id:
            raise ValueError("Zone ID required for zone-level access rule")
        payload: Dict[str, Any] = {
            "mode": mode,
            "configuration": {
                "target": "ip",
                "value": ip,
            },
            "notes": notes or "Blocked by CyberNova SOAR",
        }
        path = f"/zones/{self._zone_id}/firewall/access_rules/rules"
        result = self._request("POST", path, json=payload)
        rule = result.get("result", {})
        log.info("Created Cloudflare zone access rule %s (mode=%s, ip=%s)", rule.get("id"), mode, ip)
        return rule

    def list_access_rules(self, ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """List account-level IP access rules, optionally filtered by IP."""
        params = ""
        if ip:
            params = f"?configuration.value={ip}&configuration.target=ip"
        path = f"/accounts/{self._account_id}/firewall/access_rules/rules{params}"
        result = self._request("GET", path)
        return result.get("result", [])

    def delete_access_rule(self, rule_id: str) -> bool:
        """Delete an account-level IP access rule by ID."""
        path = f"/accounts/{self._account_id}/firewall/access_rules/rules/{rule_id}"
        self._request("DELETE", path)
        log.info("Deleted Cloudflare access rule %s", rule_id)
        return True

    def get_rule_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Find an existing access rule for a given IP."""
        rules = self.list_access_rules(ip=ip)
        if rules:
            return rules[0]
        return None

    @staticmethod
    def is_available() -> bool:
        return bool(CF_API_TOKEN and CF_ACCOUNT_ID)


# ── CF Block Action ───────────────────────────────────────────────────────────

class CloudflareBlockAction:
    """Block an IP address via Cloudflare IP Access Rule.

    Supports both account-level and zone-level access rules.
    Account-level rules apply across all zones in the account.

    Usage:
        action = CloudflareBlockAction()
        result = action.block_ip("203.0.113.5", reason="SSH brute force")
        # Returns: {"success": True, "rule_id": "...", "ip": "203.0.113.5"}
    """

    def __init__(
        self,
        api_token: str = CF_API_TOKEN,
        account_id: str = CF_ACCOUNT_ID,
        zone_id: str = CF_ZONE_ID,
        scope: str = "account",
    ):
        if not api_token or not account_id:
            raise ValueError(
                "Cloudflare API token and account ID are required. "
                "Set CYBERNOVA_CLOUDFLARE_API_TOKEN and CYBERNOVA_CLOUDFLARE_ACCOUNT_ID."
            )
        self._api_token = api_token
        self._account_id = account_id
        self._zone_id = zone_id
        self.scope = scope.lower()
        self._client: Optional[CloudflareAPIClient] = None

    @property
    def client(self) -> CloudflareAPIClient:
        if self._client is None:
            self._client = CloudflareAPIClient(
                api_token=self._api_token,
                account_id=self._account_id,
                zone_id=self._zone_id,
            )
        return self._client

    def block_ip(self, ip_address: str, reason: str = "", mode: str = "block") -> Dict[str, Any]:
        """Block an IP via Cloudflare IP Access Rule.

        Checks for an existing rule first to avoid duplicates.
        Supports 'block', 'challenge', 'js_challenge', 'managed_challenge' modes.
        """
        if mode not in ("block", "challenge", "js_challenge", "managed_challenge"):
            return {"success": False, "error": f"Invalid mode: {mode}", "ip": ip_address}

        existing = self.client.get_rule_by_ip(ip_address)
        if existing:
            log.info("IP %s already has access rule %s (mode=%s)", ip_address, existing.get("id"), existing.get("mode"))
            return {
                "success": True,
                "ip": ip_address,
                "rule_id": existing["id"],
                "already_exists": True,
                "mode": existing.get("mode"),
            }

        notes = reason or "Blocked by CyberNova SOAR"

        try:
            if self.scope == "zone" and self._zone_id:
                rule = self.client.create_zone_access_rule(ip_address, notes=notes, mode=mode)
            else:
                rule = self.client.create_access_rule(ip_address, notes=notes, mode=mode)
        except RuntimeError as e:
            log.error("Cloudflare block failed for %s: %s", ip_address, e)
            return {"success": False, "error": str(e), "ip": ip_address}

        log.warning("Cloudflare blocked IP %s (rule=%s, mode=%s, scope=%s)", ip_address, rule.get("id"), mode, self.scope)
        return {
            "success": True,
            "ip": ip_address,
            "rule_id": rule.get("id"),
            "mode": mode,
            "scope": self.scope,
            "already_exists": False,
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove the access rule for an IP."""
        existing = self.client.get_rule_by_ip(ip_address)
        if not existing:
            return {"success": True, "ip": ip_address, "already_absent": True}

        self.client.delete_access_rule(existing["id"])
        log.info("Cloudflare unblocked IP %s (removed rule %s)", ip_address, existing["id"])
        return {
            "success": True,
            "ip": ip_address,
            "rule_id": existing["id"],
        }

    def list_blocked(self, ip: Optional[str] = None) -> Dict[str, Any]:
        """List all Cloudflare access rules, optionally filtered by IP."""
        rules = self.client.list_access_rules(ip=ip)
        return {
            "success": True,
            "rules": [
                {
                    "id": r["id"],
                    "ip": r.get("configuration", {}).get("value"),
                    "mode": r.get("mode"),
                    "notes": r.get("notes"),
                    "created_at": r.get("created_on"),
                }
                for r in rules
            ],
            "count": len(rules),
        }


# ── SOAR Integration ──────────────────────────────────────────────────────────

def execute_cloudflare_block_ip(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point for the SOAR engine to call Cloudflare block.

    Expects incident dict with 'source_ip' or 'dest_ip'.
    Configure CYBERNOVA_CLOUDFLARE_API_TOKEN and CYBERNOVA_CLOUDFLARE_ACCOUNT_ID.
    """
    ip = incident.get("dest_ip") or incident.get("source_ip")
    if not ip:
        return {"success": False, "error": "No IP address in incident"}

    try:
        action = CloudflareBlockAction()
        return action.block_ip(ip, reason=incident.get("title", ""))
    except ImportError:
        return {"success": False, "error": "httpx not installed"}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        log.exception("Cloudflare block action failed")
        return {"success": False, "error": str(e)}
