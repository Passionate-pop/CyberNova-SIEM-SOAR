from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

from cybernova.multi_region.config import region_config

log = logging.getLogger("cybernova.multi_region.replication")


class CrossRegionReplicator:
    """
    Forwards events to peer regions for global threat detection.
    Each region runs its own pipeline and shares significant events.
    """

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._stats = {
            "forwarded": 0,
            "received": 0,
            "errors": 0,
            "last_forward": None,
            "last_receive": None,
        }

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._replication_loop())
        log.info("Cross-region replicator started in region: %s", region_config.current_region)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Cross-region replicator stopped")

    async def forward_event(self, event: Dict[str, Any]):
        """Queue an event for forwarding to peer regions."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("Replication queue full, dropping event")

    async def _replication_loop(self):
        while self._running:
            try:
                events: List[Dict[str, Any]] = []
                while len(events) < region_config.replication_batch_size:
                    try:
                        event = await asyncio.wait_for(
                            self._queue.get(), timeout=region_config.replication_interval
                        )
                        events.append(event)
                    except asyncio.TimeoutError:
                        break

                if events:
                    await self._forward_batch(events)
            except Exception as e:
                log.error("Replication loop error: %s", e)
                self._stats["errors"] += 1
            await asyncio.sleep(1)

    async def _forward_batch(self, events: List[Dict[str, Any]]):
        for peer in region_config.peer_regions:
            endpoint = region_config.api_endpoints.get(peer)
            if not endpoint:
                log.warning("No API endpoint configured for region: %s", peer)
                continue
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        f"{endpoint}/api/v1/multi-region/events",
                        json={
                            "source_region": region_config.current_region,
                            "events": events,
                            "forwarded_at": datetime.now(timezone.utc).isoformat(),
                        },
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        if resp.status == 200:
                            self._stats["forwarded"] += len(events)
                            log.debug("Forwarded %d events to %s", len(events), peer)
                        else:
                            log.warning("Forward to %s returned %d", peer, resp.status)
                            self._stats["errors"] += 1
            except Exception as e:
                log.error("Forward to %s failed: %s", peer, e)
                self._stats["errors"] += 1

        self._stats["last_forward"] = datetime.now(timezone.utc).isoformat()

    async def receive_events(self, events: List[Dict[str, Any]]) -> int:
        """Receive forwarded events from another region."""
        count = 0
        for event in events:
            try:
                from cybernova.pipeline.unified_pipeline import unified_pipeline
                event["_source_region"] = event.pop("source_region", "unknown")
                event["_replicated"] = True
                await unified_pipeline.ingest(
                    raw_data=event,
                    tenant_id=event.get("tenant_id", "default"),
                    source=f"replicated_{event.get('_source_region', 'unknown')}",
                    source_type="replicated_event",
                )
                count += 1
            except Exception as e:
                log.error("Failed to ingest replicated event: %s", e)
                self._stats["errors"] += 1

        self._stats["received"] += count
        self._stats["last_receive"] = datetime.now(timezone.utc).isoformat()
        return count

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "queue_size": self._queue.qsize(),
            "region": region_config.current_region,
            "peers": region_config.peer_regions,
            "enabled": region_config.enabled,
        }


cross_region_replicator = CrossRegionReplicator()
