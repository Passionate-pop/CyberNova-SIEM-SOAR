"""Microsoft Teams connector — hardened: retry-capable, validated AdaptiveCards."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

import httpx

from cybernova.plugins.registry import IntegrationPlugin
from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.integrations.teams")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0
TEAMS_RATE_LIMIT = 0.5  # 2 seconds between messages (~30/min = Teams limit)
MAX_CARD_ACTIONS = 6
MAX_FACTS = 10


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class _TokenBucket:
    def __init__(self, rate: float = TEAMS_RATE_LIMIT, burst: int = 2):
        self._rate = rate
        self._burst = burst
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()

    async def acquire(self) -> None:
        now = time.monotonic()
        self._tokens = min(float(self._burst), self._tokens + (now - self._last_refill) * self._rate)
        self._last_refill = now
        if self._tokens < 1.0:
            await asyncio.sleep((1.0 - self._tokens) / self._rate)
            self._tokens = 0.0
        else:
            self._tokens -= 1.0


_rate_limiter = _TokenBucket()


# ── Helpers ───────────────────────────────────────────────────────────────────

def truncate_text(text: str, max_len: int = 2000) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "…"


def validate_card(card: Dict[str, Any]) -> List[str]:
    """Validate AdaptiveCard structure. Returns warnings list."""
    warnings: List[str] = []
    content = card.get("attachments", [{}])[0].get("content", {})
    body = content.get("body", [])
    actions = content.get("actions", [])

    if len(actions) > MAX_CARD_ACTIONS:
        warnings.append(f"actions count {len(actions)} exceeds Teams limit of {MAX_CARD_ACTIONS}")

    for i, block in enumerate(body):
        if block.get("type") == "FactSet":
            facts = block.get("facts", [])
            if len(facts) > MAX_FACTS:
                warnings.append(f"FactSet[{i}] has {len(facts)} facts (max {MAX_FACTS})")
            for fact in facts:
                val = fact.get("value", "")
                if len(val) > 500:
                    warnings.append(f"Fact[{fact.get('title', i)}] value exceeds 500 chars")

        text = block.get("text", "")
        if len(text) > 5000:
            warnings.append(f"block[{i}] text exceeds 5000 chars")

    return warnings


# ── Teams Connector ──────────────────────────────────────────────────────────

class TeamsConnector(IntegrationPlugin):
    name = "microsoft_teams"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self.settings = get_settings()
        self._webhook_url: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        self._webhook_url = (
            getattr(self.settings, "teams_webhook_url", None)
            or getattr(self.settings, "integrations_teams_webhook", None)
        )
        if self._webhook_url:
            self._client = httpx.AsyncClient(timeout=15.0)
        await super().initialize()
        log.info("Teams connector v%s initialized (webhook=%s)",
                 self.version, bool(self._webhook_url))

    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.execute({"event": event_type, "payload": payload})

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        event = context.get("event", "unknown")
        payload = context.get("payload", {})

        if not self._webhook_url:
            log.debug("Teams not configured — would notify for %s", event)
            return {"success": True, "simulated": True}

        card = self._build_card(event, payload)
        warnings = validate_card(card)
        if warnings:
            log.warning("Teams card validation warnings: %s", "; ".join(warnings))

        result = await self._send(card)
        result["event"] = event

        self.metadata.record_use()
        if not result.get("success"):
            self.metadata.record_error(result.get("error", "send_failed"))

        return result

    # ── Card Building ──────────────────────────────────────────────────────

    def _build_card(self, event: str, payload: dict) -> dict:
        builder = self._get_builder(event)
        return builder(payload) if builder else self._default_card(event, payload)

    def _get_builder(self, event: str) -> Optional[Callable]:
        return {
            "alert": self._alert_card,
            "new_alert": self._alert_card,
            "incident": self._incident_card,
            "new_incident": self._incident_card,
        }.get(event)

    def _alert_card(self, alert: dict) -> dict:
        severity = alert.get("severity", "low").upper()
        color_map = {"CRITICAL": "FF0000", "HIGH": "FF8C00",
                     "MEDIUM": "FFD700", "LOW": "00FF00"}
        color_map.get(severity, "00FF00")
        description = truncate_text(alert.get("description", "No description"), 2000)
        base_url = getattr(self.settings, "cybernova_base_url", "https://cybernova.io")
        alert_id = alert.get("id", "")

        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msTeams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": f":rotating_light: CyberNova Alert [{severity}]",
                            "color": "attention" if severity == "CRITICAL" else "warning",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Rule", "value": alert.get("rule_name", "N/A")},
                                {"title": "Risk Score", "value": str(alert.get("risk_score", 0))},
                                {"title": "Source IP", "value": alert.get("source_ip", "N/A")},
                                {"title": "Dest IP", "value": alert.get("dest_ip", "N/A")},
                                {"title": "User", "value": alert.get("user", "N/A")},
                                {"title": "Time", "value": alert.get("created_at", "N/A")},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": f"```{description}```",
                            "wrap": True,
                            "fontType": "Monospace",
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View in CyberNova",
                            "url": f"{base_url}/alerts/{alert_id}",
                        },
                    ],
                },
            }],
        }

    def _incident_card(self, incident: dict) -> dict:
        description = truncate_text(incident.get("description", ""), 2000)
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msTeams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": ":sos: CyberNova Incident",
                            "color": "attention",
                        },
                        {
                            "type": "TextBlock",
                            "text": incident.get("title", "N/A"),
                            "size": "Medium",
                            "weight": "Bolder",
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": incident.get("severity", "N/A").upper()},
                                {"title": "Status", "value": incident.get("status", "new").upper()},
                                {"title": "Risk Score", "value": str(incident.get("risk_score", 0))},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": description or "_No description_",
                            "wrap": True,
                        },
                    ],
                },
            }],
        }

    def _default_card(self, event: str, payload: dict) -> dict:
        payload_str = json.dumps(payload, indent=2, default=str)[:2000]
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": f"CyberNova Event: {event}", "size": "Medium"},
                        {"type": "TextBlock", "text": f"```{payload_str}```",
                         "fontType": "Monospace", "wrap": True},
                    ],
                },
            }],
        }

    # ── Send (with retry) ──────────────────────────────────────────────────

    async def _send(self, card: dict) -> Dict[str, Any]:
        await _rate_limiter.acquire()

        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            start = time.monotonic()
            try:
                resp = await self._client.post(self._webhook_url, json=card)
                elapsed = (time.monotonic() - start) * 1000

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After",
                                                       str(INITIAL_RETRY_DELAY * (2 ** attempt))))
                    log.warning("Teams rate limited (429), retrying in %ds (attempt %d/%d)",
                                retry_after, attempt + 1, MAX_RETRIES)
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code >= 500 and attempt < MAX_RETRIES - 1:
                    delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                    log.warning("Teams webhook %d, retrying in %.1fs (attempt %d/%d)",
                                resp.status_code, delay, attempt + 1, MAX_RETRIES)
                    await asyncio.sleep(delay)
                    continue

                success = resp.status_code < 400
                if not success:
                    log.warning("Teams webhook returned %d: %s",
                                resp.status_code, resp.text[:300])
                else:
                    log.info("Teams card sent (status=%d, latency=%.0fms)",
                             resp.status_code, elapsed)

                return {"success": success, "status_code": resp.status_code,
                        "latency_ms": round(elapsed, 1), "retries": attempt}

            except httpx.TimeoutException as e:
                last_exc = e
                log.warning("Teams webhook timeout (attempt %d/%d)", attempt + 1, MAX_RETRIES)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))
            except Exception as e:
                last_exc = e
                log.error("Teams webhook error (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, e)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))

        return {"success": False, "error": str(last_exc), "retries": MAX_RETRIES}

    # ── Health Check ───────────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        if not self._webhook_url:
            return {"healthy": False, "error": "not configured"}

        start = time.monotonic()
        try:
            test_card = {
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard", "version": "1.0",
                        "body": [{"type": "TextBlock", "text": "CyberNova health check"}],
                    },
                }],
            }
            resp = await self._client.post(self._webhook_url, json=test_card)
            latency = (time.monotonic() - start) * 1000
            healthy = resp.status_code < 400
            return {
                "healthy": healthy,
                "latency_ms": round(latency, 1),
                "status_code": resp.status_code,
                "error": None if healthy else f"HTTP {resp.status_code}",
            }
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {"healthy": False, "latency_ms": round(latency, 1), "error": str(e)}

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def teardown(self):
        if self._client:
            await self._client.aclose()
            self._client = None
        log.info("Teams connector shut down")

    def validate(self) -> List[str]:
        errors = super().validate()
        if not self._webhook_url:
            errors.append("Webhook URL not configured - set teams_webhook_url in settings")
        return errors
