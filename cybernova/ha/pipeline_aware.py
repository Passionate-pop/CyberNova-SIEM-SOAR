from __future__ import annotations

import asyncio
import logging

from cybernova.ha.leader import leader_election

log = logging.getLogger("cybernova.ha.pipeline_aware")


class LeaderAwarePipeline:
    """
    Wraps pipeline ingestion so only the leader replica processes events.
    Followers reject ingestion or queue events for the leader.
    On leadership change, gracefully drains in-flight work before handoff.
    """

    def __init__(self):
        self._draining = False
        self._in_flight = 0
        self._lock = asyncio.Lock()
        self._handoff_complete = asyncio.Event()
        self._handoff_complete.set()

    async def ingest(self, ingest_fn, *args, **kwargs):
        if self._draining:
            log.warning("Rejecting ingest — draining for leader handoff")
            raise LeaderHandoffError("Draining for leader handoff")
        if not leader_election.is_leader and not leader_election._local_mode:
            raise NotLeaderError("This replica is not the leader")

        async with self._lock:
            self._in_flight += 1
        try:
            return await ingest_fn(*args, **kwargs)
        finally:
            async with self._lock:
                self._in_flight -= 1
            if self._draining and self._in_flight == 0:
                self._handoff_complete.set()

    async def prepare_handoff(self):
        """Prepare to hand off leadership. Drains in-flight work."""
        log.info("Preparing leader handoff — draining %d in-flight events", self._in_flight)
        self._draining = True
        self._handoff_complete.clear()
        if self._in_flight > 0:
            try:
                await asyncio.wait_for(self._handoff_complete.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                log.warning("Handoff drain timeout with %d in-flight", self._in_flight)
        self._draining = False
        log.info("Leader handoff drain complete")

    @property
    def is_leader(self) -> bool:
        return leader_election.is_leader

    @property
    def in_flight_count(self) -> int:
        return self._in_flight


leader_aware_pipeline = LeaderAwarePipeline()


class NotLeaderError(Exception):
    def __init__(self, message="This replica is not the leader"):
        self.message = message
        super().__init__(message)


class LeaderHandoffError(Exception):
    def __init__(self, message="Draining for leader handoff"):
        self.message = message
        super().__init__(message)
