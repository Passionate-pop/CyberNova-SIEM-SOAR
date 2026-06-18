"""
CyberNova — Rule Hot-Reload Engine
Rules loaded from DB, refreshed via Redis pub/sub or polling.
Workers automatically reload rules without restart.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis

from cybernova.streaming.streams import STREAM_PREFIX

log = logging.getLogger("cybernova.rules.hotreload")

RULES_CHANNEL = f"{STREAM_PREFIX}:rules:update"
RULES_RELOAD_INTERVAL = 30


class RulesHotReloader:
    def __init__(self, redis: Optional[aioredis.Redis] = None) -> None:
        self.redis = redis
        self._running = False
        self._tasks: set = set()
        self._detection_rules: Dict[str, List[Any]] = {}
        self._correlation_rules: Dict[str, List[Any]] = {}
        self._detection_listeners: List[callable] = []
        self._correlation_listeners: List[callable] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        self._running = True
        if self.redis:
            t = asyncio.create_task(self._pubsub_listener())
            self._tasks.add(t)
        t = asyncio.create_task(self._poll_reloader())
        self._tasks.add(t)
        log.info("Rules hot-reloader started (pubsub=%s, poll=%ds)", bool(self.redis), RULES_RELOAD_INTERVAL)

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _pubsub_listener(self) -> None:
        """Listen for rule update signals via Redis pub/sub."""
        if not self.redis:
            return
        try:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe(RULES_CHANNEL)
            log.info("Subscribed to rule update channel: %s", RULES_CHANNEL)

            async for message in pubsub.listen():
                if not self._running:
                    break
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        rule_type = data.get("type")
                        tenant_id = data.get("tenant_id", "default")
                        log.info("Rule update signal received: %s for tenant %s", rule_type, tenant_id)
                        await self._trigger_reload(rule_type, tenant_id)
                    except Exception as exc:
                        log.error("Failed to process rule update signal: %s", exc)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.error("Pub/sub listener error: %s", exc)

    async def _poll_reloader(self) -> None:
        """Poll DB for rule changes as fallback."""
        last_detection_hash = ""
        last_correlation_hash = ""

        while self._running:
            try:
                detection_rules = await self._load_detection_rules_from_db("default")
                detection_hash = self._rules_hash(detection_rules)
                if detection_hash != last_detection_hash and last_detection_hash:
                    log.info("Detection rules changed — triggering reload")
                    await self._trigger_reload("detection", "default")
                last_detection_hash = detection_hash

                correlation_rules = await self._load_correlation_rules_from_db("default")
                correlation_hash = self._rules_hash(correlation_rules)
                if correlation_hash != last_correlation_hash and last_correlation_hash:
                    log.info("Correlation rules changed — triggering reload")
                    await self._trigger_reload("correlation", "default")
                last_correlation_hash = correlation_hash

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Poll reloader error: %s", exc)

            await asyncio.sleep(RULES_RELOAD_INTERVAL)

    def _rules_hash(self, rules: List[Any]) -> str:
        import hashlib
        try:
            rules_data = [r.to_dict() if hasattr(r, "to_dict") else r for r in rules]
            return hashlib.sha256(json.dumps(rules_data, sort_keys=True).encode()).hexdigest()
        except (TypeError, ValueError):
            return ""

    async def _trigger_reload(self, rule_type: str, tenant_id: str) -> None:
        async with self._lock:
            if rule_type in ("detection", "all"):
                for listener in self._detection_listeners:
                    try:
                        await listener(tenant_id)
                    except Exception as exc:
                        log.error("Detection rule listener error: %s", exc)

            if rule_type in ("correlation", "all"):
                for listener in self._correlation_listeners:
                    try:
                        await listener(tenant_id)
                    except Exception as exc:
                        log.error("Correlation rule listener error: %s", exc)

    def on_detection_rules_update(self, listener: callable) -> None:
        self._detection_listeners.append(listener)

    def on_correlation_rules_update(self, listener: callable) -> None:
        self._correlation_listeners.append(listener)

    async def publish_update(self, rule_type: str, tenant_id: str = "default") -> None:
        """Publish a rule update signal so all workers reload."""
        if self.redis:
            await self.redis.publish(
                RULES_CHANNEL,
                json.dumps({"type": rule_type, "tenant_id": tenant_id}),
            )

    async def _load_detection_rules_from_db(self, tenant_id: str) -> List[Any]:
        try:
            from cybernova.detection.rules_engine.rules_dsl import detection_rules_engine
            rules = await detection_rules_engine.load_rules(tenant_id)
            return rules
        except Exception as e:
            log.warning("Failed to load detection rules from DB: %s", e)
            return []

    async def _load_correlation_rules_from_db(self, tenant_id: str) -> List[Any]:
        try:
            from cybernova.correlation.rules_engine import rules_engine
            rules = await rules_engine.load_rules(tenant_id)
            return rules
        except Exception as e:
            log.warning("Failed to load correlation rules from DB: %s", e)
            return []


rules_hotreloader = RulesHotReloader()
