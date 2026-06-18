"""
CyberNova — Async Background Workers
Runs heavy operations (enrichment, correlation, AI) as background tasks.
Uses asyncio.create_task for self-hosted zero-cost infra.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Coroutine, Optional

log = logging.getLogger("cybernova.workers")


class BackgroundWorker:
    """Lightweight async worker that processes tasks in the background."""

    def __init__(self, name: str, max_concurrent: int = 10) -> None:
        self.name = name
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._running = False
        self._tasks: set = set()

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self._semaphore

    async def submit(
        self,
        coro: Coroutine[Any, Any, Any],
        task_name: str = "unnamed",
    ) -> None:
        """Submit a coroutine for background execution."""
        async def _wrapper():
            async with self.semaphore:
                log.info("Worker %s: task '%s' started", self.name, task_name)
                try:
                    await coro
                    log.info("Worker %s: task '%s' completed", self.name, task_name)
                except Exception as exc:
                    log.error("Worker %s task '%s' failed: %s", self.name, task_name, exc, exc_info=True)
                finally:
                    self._tasks.discard(asyncio.current_task())

        task = asyncio.create_task(_wrapper())
        self._tasks.add(task)
        log.debug("Worker %s: submitted task '%s' (%d active)", self.name, task_name, len(self._tasks))

    async def shutdown(self, timeout: float = 30.0) -> None:
        """Wait for all pending tasks to complete."""
        if self._tasks:
            log.info("Worker %s: waiting for %d tasks to complete...", self.name, len(self._tasks))
            done, pending = await asyncio.wait(self._tasks, timeout=timeout)
            for t in pending:
                t.cancel()
            log.info("Worker %s: shutdown complete (%d done, %d cancelled)", self.name, len(done), len(pending))


# Pre-configured workers for different domains
enrichment_worker = BackgroundWorker("enrichment", max_concurrent=5)
correlation_worker = BackgroundWorker("correlation", max_concurrent=3)
ai_worker = BackgroundWorker("ai", max_concurrent=2)
webhook_worker = BackgroundWorker("webhook", max_concurrent=10)
