from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.network.feeds.scheduler")


class FeedScheduler:
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._interval = 3600
        self._stats = {
            "total_polls": 0,
            "total_iocs": 0,
            "last_poll_time": None,
            "errors": 0,
        }

    async def start(self, interval: int = 3600) -> None:
        self._interval = interval
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        log.info("Feed scheduler started (interval: %ds)", interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Feed scheduler stopped")

    async def _poll_loop(self) -> None:
        import random  # nosec - used for scheduling jitter, not security
        consecutive_errors = 0
        while self._running:
            try:
                total = await self._poll_all()
                self._stats["total_polls"] += 1
                self._stats["total_iocs"] += total
                self._stats["last_poll_time"] = datetime.now(timezone.utc).isoformat()
                log.info("Feed poll cycle: %d IOCs ingested (total: %d)", total, self._stats["total_iocs"])
                consecutive_errors = 0
            except Exception as e:
                self._stats["errors"] += 1
                consecutive_errors += 1
                log.error("Feed poll cycle error (consecutive: %d): %s", consecutive_errors, e)
            # Add ±10% jitter to prevent thundering herd; backoff on consecutive errors
            jitter = random.uniform(-0.1, 0.1)  # nosec
            backoff = min(2 ** consecutive_errors, 16) if consecutive_errors > 0 else 1
            sleep_time = self._interval * (1 + jitter) * backoff
            await asyncio.sleep(sleep_time)

    async def poll_now(self) -> int:
        total = await self._poll_all()
        self._stats["total_polls"] += 1
        self._stats["total_iocs"] += total
        self._stats["last_poll_time"] = datetime.now(timezone.utc).isoformat()
        return total

    async def _poll_all(self) -> int:
        from cybernova.network.feeds.stix_taxii import poll_stix_feeds
        from cybernova.network.feeds.misp import poll_all_misp
        total = 0
        total += await poll_stix_feeds()
        total += await poll_all_misp()
        return total

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats}


feed_scheduler = FeedScheduler()
