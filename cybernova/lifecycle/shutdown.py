"""Graceful shutdown manager — enforces a configurable time budget for draining in-flight work."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("cybernova.lifecycle.shutdown")


@dataclass
class GracefulShutdown:
    """Tracks time budget for a phased shutdown.

    Usage:
        gs = GracefulShutdown(timeout=30)
        async with gs:
            await phase1_stop_accepting()
            await phase2_drain_events(gs.remaining())
            await phase3_close_connections()
    """

    timeout: float = 30.0
    _start: float = field(default=0.0, init=False, repr=False)
    _triggered: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)

    def remaining(self) -> float:
        """Seconds left in the grace period (clamped to 0)."""
        if not self._start:
            return self.timeout
        elapsed = time.monotonic() - self._start
        return max(0.0, self.timeout - elapsed)

    @property
    def elapsed(self) -> float:
        """Seconds elapsed since shutdown was triggered."""
        return time.monotonic() - self._start if self._start else 0.0

    @property
    def expired(self) -> bool:
        """True when the grace period has elapsed."""
        return self.remaining() <= 0.0

    def trigger(self) -> None:
        """Mark shutdown start and notify waiters."""
        self._start = time.monotonic()
        self._triggered.set()
        log.info("Graceful shutdown triggered — %.1fs budget", self.timeout)

    async def wait_triggered(self) -> None:
        """Block until shutdown is triggered (for background tasks)."""
        await self._triggered.wait()

    async def drain_with_timeout(
        self,
        label: str,
        coro: Any,
        min_timeout: float = 1.0,
    ) -> None:
        """Run *coro* with the remaining time budget, clamped to *min_timeout*."""
        budget = max(min_timeout, self.remaining())
        try:
            await asyncio.wait_for(coro, timeout=budget)
            log.info("Drain phase '%s' completed (%.1fs remaining)", label, self.remaining())
        except asyncio.TimeoutError:
            log.warning("Drain phase '%s' timed out after %.1fs — forcing", label, budget)
        except Exception as e:
            log.error("Drain phase '%s' error: %s", label, e)

    async def __aenter__(self) -> "GracefulShutdown":
        self.trigger()
        return self

    async def __aexit__(self, *exc) -> None:
        total = time.monotonic() - self._start
        log.info("Shutdown completed in %.1fs (budget was %.1fs)", total, self.timeout)


# ---------------------------------------------------------------------------
# Shutdown helpers for main.py lifespan
# ---------------------------------------------------------------------------


async def safe_stop(label: str, coro: Any) -> None:
    """Safely stop a component, logging warnings on failure.

    Accepts either a coroutine or a callable that returns a coroutine
    (e.g. ``lambda: some_module.stop()``) and invokes it transparently.
    """
    try:
        if callable(coro):
            coro = coro()
        await coro
        log.debug("Shutdown %s: stopped", label)
    except Exception as e:
        log.warning("Shutdown %s: error: %s", label, e)
