"""Slack connector — hardened: rate-limited, retry-capable, validated blocks."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import httpx

from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.slack")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_BLOCKS = 50
MAX_TEXT_LENGTH = 3000
MAX_DESCRIPTION_LENGTH = 2000
SLACK_API_BASE = "https://slack.com/api"
RATE_LIMIT_PER_SECOND = 1.0
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0


# ── Rate Limiter (token bucket per channel) ───────────────────────────────────

class TokenBucket:
    """Simple token bucket rate limiter — 1 send per second per channel."""

    def __init__(self, rate: float = RATE_LIMIT_PER_SECOND, burst: int = 2):
        self._rate = rate
        self._burst = burst
        self._tokens: Dict[str, float] = {}
        self._last_refill: Dict[str, float] = {}

    async def acquire(self, key: str = "default") -> None:
        now = time.monotonic()
        tokens = self._tokens.get(key, float(self._burst))
        last = self._last_refill.get(key, now)

        tokens = min(float(self._burst), tokens + (now - last) * self._rate)
        self._last_refill[key] = now

        if tokens < 1.0:
            wait = (1.0 - tokens) / self._rate
            await asyncio.sleep(wait)
            tokens = 0.0
        else:
            tokens -= 1.0

        self._tokens[key] = tokens

    def remaining(self, key: str = "default") -> float:
        return self._tokens.get(key, float(self._burst))


_rate_limiter = TokenBucket()


# ── Signature Verification (for incoming Slack Events API) ────────────────────

def verify_slack_signature(
    signing_secret: str,
    body: bytes,
    timestamp: str,
    signature: str,
    max_skew_seconds: int = 300,
) -> bool:
    """Verify Slack's HMAC-SHA256 request signature.

    Use for incoming webhooks / Events API to confirm the request
    genuinely came from Slack.
    """
    try:
        now = time.time()
        if abs(now - int(timestamp)) > max_skew_seconds:
            log.warning("Slack signature timestamp skew > %ds", max_skew_seconds)
            return False
    except (ValueError, TypeError):
        return False

    sig_basestring = f"v0:{timestamp}:".encode() + (body if isinstance(body, bytes) else body.encode())
    expected = "v0=" + hmac.new(
        signing_secret.encode(), sig_basestring, hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


# ── Block Validator ───────────────────────────────────────────────────────────

def validate_blocks(blocks: List[Dict[str, Any]]) -> List[str]:
    """Validate Slack Block Kit structure. Returns list of warnings (empty = valid)."""
    warnings: List[str] = []

    if not blocks:
        return ["empty blocks list"]

    if len(blocks) > MAX_BLOCKS:
        warnings.append(f"block count {len(blocks)} exceeds Slack limit of {MAX_BLOCKS}")

    for i, block in enumerate(blocks):
        block_type = block.get("type", "unknown")
        if block_type == "section":
            text = block.get("text", {}).get("text", "")
            if len(text) > MAX_TEXT_LENGTH:
                warnings.append(f"block[{i}] section text exceeds {MAX_TEXT_LENGTH} chars")
            for field in block.get("fields", []):
                ftext = field.get("text", "")
                if len(ftext) > MAX_TEXT_LENGTH:
                    warnings.append(f"block[{i}] field text exceeds {MAX_TEXT_LENGTH} chars")
        elif block_type == "actions":
            elements = block.get("elements", [])
            if len(elements) > 5:
                warnings.append(f"block[{i}] has {len(elements)} action elements (max 5)")

    return warnings


def truncate_text(text: str, max_len: int = MAX_DESCRIPTION_LENGTH) -> str:
    """Truncate text at a UTF-8 safe boundary."""
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "…"


# ── Slack Connector ───────────────────────────────────────────────────────────

@dataclass
class SendResult:
    success: bool
    status_code: int = 0
    error: Optional[str] = None
    retries: int = 0
    latency_ms: float = 0.0
    ts: Optional[str] = None
    channel: Optional[str] = None


class SlackConnector(IntegrationPlugin):
    name = "slack"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self.settings = get_settings()
        self._webhook_url: Optional[str] = None
        self._token: Optional[str] = None
        self._signing_secret: Optional[str] = None
        self._default_channel: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._bot_user_id: Optional[str] = None
        self._bot_name: Optional[str] = None

    async def initialize(self) -> None:
        self._webhook_url = (
            getattr(self.settings, "slack_webhook_url", None)
            or getattr(self.settings, "integrations_slack_webhook", None)
        )
        self._token = (
            getattr(self.settings, "slack_token", None)
            or getattr(self.settings, "integrations_slack_token", None)
        )
        self._signing_secret = getattr(self.settings, "slack_signing_secret", None)
        self._default_channel = getattr(self.settings, "slack_channel", "#security-alerts")

        if not self._webhook_url and not self._token:
            log.info("Slack connector: no credentials configured — running in simulation mode")
            return

        self._client = httpx.AsyncClient(timeout=15.0)

        if self._token:
            await self._validate_token()

        await super().initialize()
        log.info("Slack connector v%s initialized (webhook=%s, bot_token=%s)",
                 self.version, bool(self._webhook_url), bool(self._token))

    async def _validate_token(self) -> None:
        """Validate the bot token by calling auth.test on startup."""
        try:
            resp = await self._client.post(
                f"{SLACK_API_BASE}/auth.test",
                headers={"Authorization": f"Bearer {self._token}",
                         "Content-Type": "application/json"},
            )
            data = resp.json()
            if data.get("ok"):
                self._bot_user_id = data.get("user_id")
                self._bot_name = data.get("user")
                log.info("Slack bot authenticated as %s (%s)", self._bot_name, self._bot_user_id)
            else:
                log.warning("Slack token validation failed: %s", data.get("error", "unknown"))
        except Exception as e:
            log.warning("Slack token validation error (non-fatal): %s", e)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})
        channel = context.get("channel", self._default_channel)

        if not self._webhook_url and not self._token:
            log.debug("Slack not configured — would notify channel %s (%s)", channel, event)
            return {"success": True, "simulated": True}

        blocks = self._build_blocks(event, payload)
        warnings = validate_blocks(blocks)
        if warnings:
            log.warning("Slack block validation warnings: %s", "; ".join(warnings))

        if self._webhook_url:
            result = await self._send_via_webhook(blocks, channel)
        elif self._token:
            result = await self._send_via_api(blocks, channel)

        result["blocks_used"] = len(blocks)
        result["event"] = event

        self.metadata.record_use()
        if not result.get("success"):
            self.metadata.record_error(result.get("error", "send_failed"))

        return result

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    # ── Block Building ─────────────────────────────────────────────────────

    def _build_blocks(self, event: str, payload: dict) -> list:
        builder = self._get_builder(event)
        return builder(payload) if builder else self._default_blocks(event, payload)

    def _get_builder(self, event: str) -> Optional[Callable]:
        return {
            "alert": self._alert_blocks,
            "new_alert": self._alert_blocks,
            "incident": self._incident_blocks,
            "new_incident": self._incident_blocks,
            "soar_action": self._soar_blocks,
        }.get(event)

    def _alert_blocks(self, alert: dict) -> list:
        severity = alert.get("severity", "low").upper()
        color = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning",
                 "LOW": "good"}.get(severity, "good")
        description = truncate_text(alert.get("description", "No description"), MAX_DESCRIPTION_LENGTH)
        base_url = getattr(self.settings, "cybernova_base_url", "https://cybernova.io")
        alert_id = alert.get("id", "")
        created_at = alert.get("created_at", "N/A")

        blocks = [
            {"type": "header",
             "text": {"type": "plain_text", "text": f":rotating_light:  CyberNova Alert  [{severity}]",
                      "emoji": True}},
            {"type": "section",
             "fields": [
                 {"type": "mrkdwn", "text": f"*Rule:* {alert.get('rule_name', 'N/A')}"},
                 {"type": "mrkdwn", "text": f"*Risk Score:* {alert.get('risk_score', 0)}"},
                 {"type": "mrkdwn", "text": f"*Source IP:* {alert.get('source_ip', 'N/A')}"},
                 {"type": "mrkdwn", "text": f"*Dest IP:* {alert.get('dest_ip', 'N/A')}"},
             ]},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": f"```{description}```"}},
            {"type": "context",
             "elements": [
                 {"type": "mrkdwn",
                  "text": f":bust_in_silhouette: {alert.get('user', 'N/A')}  |  :clock1: {created_at}"},
             ]},
            {"type": "actions",
             "elements": [
                 {"type": "button", "text": {"type": "plain_text", "text": "View in CyberNova"},
                  "url": f"{base_url}/alerts/{alert_id}", "style": color},
             ]},
        ]
        return blocks

    def _incident_blocks(self, incident: dict) -> list:
        description = truncate_text(incident.get("description", ""), MAX_DESCRIPTION_LENGTH)
        return [
            {"type": "header",
             "text": {"type": "plain_text", "text": ":sos:  CyberNova Incident", "emoji": True}},
            {"type": "section",
             "fields": [
                 {"type": "mrkdwn", "text": f"*Title:* {incident.get('title', 'N/A')}"},
                 {"type": "mrkdwn", "text": f"*Severity:* {incident.get('severity', 'N/A').upper()}"},
                 {"type": "mrkdwn", "text": f"*Status:* {incident.get('status', 'new').upper()}"},
                 {"type": "mrkdwn", "text": f"*Risk Score:* {incident.get('risk_score', 0)}"},
             ]},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": description or "_No description_"}},
        ]

    def _soar_blocks(self, action: dict) -> list:
        return [
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f":zap: *SOAR Action Executed*\n"
                              f"*Type:* `{action.get('action_type', 'N/A')}`\n"
                              f"*Status:* `{action.get('status', 'N/A')}`\n"
                              f"*Target:* {action.get('target', 'N/A')}"}},
        ]

    def _default_blocks(self, event: str, payload: dict) -> list:
        payload_str = json.dumps(payload, indent=2, default=str)[:MAX_TEXT_LENGTH]
        return [
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f"*Event:* {event}\n```{payload_str}```"}},
        ]

    # ── Webhook Send (with retry) ──────────────────────────────────────────

    async def _send_via_webhook(self, blocks: list,
                                channel: Optional[str]) -> Dict[str, Any]:
        await _rate_limiter.acquire(channel or "webhook")

        body: Dict[str, Any] = {
            "text": f"CyberNova: {blocks[0].get('text', {}).get('text', 'Notification')}"
                    if blocks else "CyberNova Notification",
            "blocks": blocks,
            "mrkdwn": True,
        }
        if channel:
            body["channel"] = channel

        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            start = time.monotonic()
            try:
                resp = await self._client.post(self._webhook_url, json=body)
                elapsed = (time.monotonic() - start) * 1000

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", str(INITIAL_RETRY_DELAY * (2 ** attempt))))
                    log.warning("Slack rate limited (429), retrying in %ds (attempt %d/%d)",
                                retry_after, attempt + 1, MAX_RETRIES)
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code >= 500 and attempt < MAX_RETRIES - 1:
                    delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                    log.warning("Slack webhook %d, retrying in %.1fs (attempt %d/%d)",
                                resp.status_code, delay, attempt + 1, MAX_RETRIES)
                    await asyncio.sleep(delay)
                    continue

                success = resp.status_code < 400
                if not success:
                    log.warning("Slack webhook returned %d: %s", resp.status_code, resp.text[:300])
                else:
                    log.info("Slack webhook sent (status=%d, latency=%.0fms, blocks=%d)",
                             resp.status_code, elapsed, len(blocks))

                return {"success": success, "status_code": resp.status_code,
                        "latency_ms": round(elapsed, 1), "retries": attempt}

            except httpx.TimeoutException as e:
                last_exc = e
                log.warning("Slack webhook timeout (attempt %d/%d)", attempt + 1, MAX_RETRIES)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))
            except Exception as e:
                last_exc = e
                log.error("Slack webhook error (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, e)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))

        return {"success": False, "error": str(last_exc), "retries": MAX_RETRIES}

    # ── API Send (with retry) ──────────────────────────────────────────────

    async def _send_via_api(self, blocks: list, channel: str) -> Dict[str, Any]:
        await _rate_limiter.acquire(channel)

        text = f"CyberNova: {blocks[0].get('text', {}).get('text', 'Notification')}" if blocks else "CyberNova Notification"
        body = {"channel": channel, "blocks": blocks, "text": text,
                "link_names": False, "unfurl_links": False}

        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            start = time.monotonic()
            try:
                resp = await self._client.post(
                    f"{SLACK_API_BASE}/chat.postMessage",
                    headers={"Authorization": f"Bearer {self._token}",
                             "Content-Type": "application/json"},
                    json=body,
                )
                elapsed = (time.monotonic() - start) * 1000
                data = resp.json()

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After",
                                                       str(INITIAL_RETRY_DELAY * (2 ** attempt))))
                    log.warning("Slack API rate limited (429), retrying in %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                if not data.get("ok"):
                    error = data.get("error", "unknown_error")
                    if error in ("ratelimited", "service_unavailable") and attempt < MAX_RETRIES - 1:
                        delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                        await asyncio.sleep(delay)
                        continue
                    log.warning("Slack API error: %s (channel=%s)", error, channel)
                    return {"success": False, "error": error, "status_code": resp.status_code,
                            "latency_ms": round(elapsed, 1), "retries": attempt}

                ts = data.get("ts")
                log.info("Slack API message sent (channel=%s, ts=%s, latency=%.0fms, blocks=%d)",
                         channel, ts, elapsed, len(blocks))
                return {"success": True, "ts": ts, "channel": channel,
                        "status_code": resp.status_code, "latency_ms": round(elapsed, 1),
                        "retries": attempt}

            except httpx.TimeoutException as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))
            except Exception as e:
                last_exc = e
                log.error("Slack API error (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, e)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))

        return {"success": False, "error": str(last_exc), "retries": MAX_RETRIES}

    # ── Health Check ───────────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        if not self._webhook_url and not self._token:
            return {"healthy": False, "error": "not configured"}

        start = time.monotonic()
        try:
            if self._token:
                resp = await self._client.post(
                    f"{SLACK_API_BASE}/auth.test",
                    headers={"Authorization": f"Bearer {self._token}",
                             "Content-Type": "application/json"},
                )
                data = resp.json()
                healthy = data.get("ok", False)
                latency = (time.monotonic() - start) * 1000
                return {
                    "healthy": healthy,
                    "latency_ms": round(latency, 1),
                    "bot_name": data.get("user") if healthy else None,
                    "bot_id": data.get("user_id") if healthy else None,
                    "team": data.get("team") if healthy else None,
                    "error": data.get("error") if not healthy else None,
                }
            elif self._webhook_url:
                resp = await self._client.post(self._webhook_url, json={"text": "health check"})
                latency = (time.monotonic() - start) * 1000
                healthy = resp.status_code < 400
                return {"healthy": healthy, "latency_ms": round(latency, 1),
                        "status_code": resp.status_code}
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {"healthy": False, "latency_ms": round(latency, 1), "error": str(e)}

        return {"healthy": False, "error": "unknown"}

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        log.info("Slack connector shut down")

    def validate(self) -> List[str]:
        errors = super().validate()
        if not self._webhook_url and not self._token:
            errors.append("Neither webhook URL nor bot token configured "
                          "- set slack_webhook_url or slack_token in settings")
        return errors
