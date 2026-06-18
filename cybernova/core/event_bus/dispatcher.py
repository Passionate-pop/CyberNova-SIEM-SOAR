"""
CyberNova — Event Bus: Dispatcher
Routes events to registered handlers. Decouples producers from consumers.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List

log = logging.getLogger("cybernova.event_bus.dispatcher")

HandlerType = Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]


class EventDispatcher:
    """In-process event dispatcher for synchronous event-driven flow."""

    def __init__(self) -> None:
        self._handlers: Dict[str, List[HandlerType]] = {}

    def subscribe(self, topic: str, handler: HandlerType) -> None:
        """Register a handler for a topic."""
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        log.info("Handler registered for topic: %s", topic)

    async def dispatch(self, topic: str, payload: Dict[str, Any]) -> int:
        """Dispatch an event to all registered handlers. Returns handler count."""
        handlers = self._handlers.get(topic, [])
        if not handlers:
            log.debug("No handlers for topic: %s", topic)
            return 0

        for handler in handlers:
            try:
                await handler(payload)
            except Exception as exc:
                log.error("Handler failed for %s: %s", topic, exc, exc_info=True)

        return len(handlers)

    async def dispatch_background(self, topic: str, payload: Dict[str, Any]) -> None:
        """Fire-and-forget dispatch (non-blocking)."""
        asyncio.create_task(self.dispatch(topic, payload))

    def list_topics(self) -> List[str]:
        return list(self._handlers.keys())


# Module-level singleton
event_dispatcher = EventDispatcher()
