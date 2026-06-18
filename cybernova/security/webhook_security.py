"""
CyberNova — SOAR Webhook Security
HMAC signature generation + validation for webhook security.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.security.soar")

SIGNATURE_HEADER = "X-CyberNova-Signature"
TIMESTAMP_HEADER = "X-CyberNova-Timestamp"
MAX_AGE_SECONDS = 300


class WebhookSigner:
    def __init__(self, secret: Optional[str] = None) -> None:
        settings = get_settings()
        self.secret = secret or settings.cybernova_webhook_token or settings.secret_key
        self.algorithm = "sha256"

    def sign(self, payload: Dict[str, Any], timestamp: Optional[str] = None) -> tuple[str, str]:
        """Generate HMAC signature for a payload. Returns (signature, timestamp)."""
        if timestamp is None:
            timestamp = str(int(datetime.now(timezone.utc).timestamp()))

        payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signed_data = f"{timestamp}.{payload_str}"
        signature = hmac.new(
            self.secret.encode("utf-8"),
            signed_data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return signature, timestamp

    def sign_and_attach_headers(
        self, payload: Dict[str, Any]
    ) -> tuple[Dict[str, Any], str, str]:
        """Sign payload and return (headers, signature, timestamp)."""
        signature, timestamp = self.sign(payload)
        headers = {
            SIGNATURE_HEADER: f"sha256={signature}",
            TIMESTAMP_HEADER: timestamp,
            "Content-Type": "application/json",
            "User-Agent": "CyberNova-SOAR/2.0",
        }
        return headers, signature, timestamp

    def verify(
        self,
        payload: Dict[str, Any],
        signature: str,
        timestamp: str,
    ) -> tuple[bool, str]:
        """Verify a webhook signature. Returns (valid, error_reason)."""
        try:
            ts = int(timestamp)
            age = datetime.now(timezone.utc).timestamp() - ts
            if age > MAX_AGE_SECONDS:
                return False, f"Timestamp too old: {age}s"
            if age < -60:
                return False, "Timestamp in the future"

            expected_sig, _ = self.sign(payload, timestamp)
            received_sig = signature.replace("sha256=", "")

            if not hmac.compare_digest(expected_sig, received_sig):
                return False, "Signature mismatch"

            return True, ""
        except Exception as exc:
            return False, f"Verification error: {exc}"

class TenantEnforcer:
    """Enforces tenant isolation at the stream and API level."""

    @staticmethod
    def get_stream_for_tenant(base_stream: str, tenant_id: str) -> str:
        """Get per-tenant stream name."""
        return f"{base_stream}:{tenant_id}"

    @staticmethod
    def validate_tenant_event(event: Dict[str, Any], expected_tenant: str) -> tuple[bool, str]:
        """Ensure an event belongs to the expected tenant."""
        event_tenant = event.get("tenant_id", "default")
        if event_tenant != expected_tenant:
            return False, f"Tenant mismatch: expected {expected_tenant}, got {event_tenant}"
        return True, ""

    @staticmethod
    def filter_streams_by_tenant(streams: list, tenant_id: str) -> list:
        """Filter stream list to only those belonging to a tenant."""
        filtered = []
        for stream in streams:
            parts = stream.split(":")
            if len(parts) >= 3 and parts[-1] == tenant_id:
                filtered.append(stream)
            elif tenant_id == "default" and ":default" not in stream:
                filtered.append(stream)
        return filtered


# Module-level singleton for unified API access
webhook_security = WebhookSigner()

