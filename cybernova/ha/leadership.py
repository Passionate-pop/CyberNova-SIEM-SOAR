"""
CyberNova — Leadership Controller
Wires leader election callbacks to start/stop pipeline and leader-only tasks.
Passive replicas serve cached dashboard data without running the pipeline.
"""
import logging
from typing import Callable, Coroutine, List, Tuple

from cybernova.ha.leader import leader_election
from cybernova.pipeline.unified_pipeline import unified_pipeline

log = logging.getLogger("cybernova.ha.leadership")

LeadershipTask = Tuple[str, Callable[[], Coroutine], Callable[[], Coroutine]]


class LeadershipController:
    """
    Manages lifecycle of pipeline and background tasks based on leader status.

    - On leadership gained: starts pipeline + registered leader-only tasks
    - On leadership lost: drains pipeline, stops leader-only tasks
    - Passive replica still serves API (dashboard from cache)
    """

    def __init__(self):
        self._pipeline_started = False
        self._leader_tasks: List[LeadershipTask] = []
        self._tasks_started = False

    def register_task(self, label: str, start_fn: Callable[[], Coroutine], stop_fn: Callable[[], Coroutine]) -> None:
        self._leader_tasks.append((label, start_fn, stop_fn))

    async def start(self) -> None:
        leader_election.on_leadership_gained(self._on_gained)
        leader_election.on_leadership_lost(self._on_lost)
        if leader_election.is_leader or leader_election._local_mode:
            await self._on_gained()
        log.info("LeadershipController registered callbacks (leader: %s)", leader_election.is_leader)

    async def _on_gained(self) -> None:
        log.info("Leadership gained — activating pipeline and leader tasks")
        await self._start_pipeline()
        await self._start_tasks()

    async def _on_lost(self) -> None:
        log.info("Leadership lost — deactivating pipeline and leader tasks")
        await self._stop_tasks()
        await self._stop_pipeline()

    async def _start_pipeline(self) -> None:
        if self._pipeline_started:
            return
        if unified_pipeline._running:
            self._pipeline_started = True
            log.info("Pipeline already running — tracking as leader-owned")
            return
        try:
            await unified_pipeline.initialize()
            await unified_pipeline.start()
            self._pipeline_started = True
            log.info("Pipeline started on leader")
        except Exception as e:
            log.error("Pipeline start error on leader promotion: %s", e)

    async def _stop_pipeline(self) -> None:
        if not self._pipeline_started:
            return
        try:
            from cybernova.ha.pipeline_aware import leader_aware_pipeline
            await leader_aware_pipeline.prepare_handoff()
            await unified_pipeline.drain(timeout=30)
            await unified_pipeline.close()
            self._pipeline_started = False
            log.info("Pipeline stopped on leader demotion")
        except Exception as e:
            log.warning("Pipeline stop error on leader demotion: %s", e)

    async def _start_tasks(self) -> None:
        if self._tasks_started:
            return
        for label, start_fn, _ in self._leader_tasks:
            try:
                await start_fn()
                log.debug("Leader task '%s' started", label)
            except Exception as e:
                log.warning("Leader task '%s' start error: %s", label, e)
        self._tasks_started = True

    async def _stop_tasks(self) -> None:
        if not self._tasks_started:
            return
        for label, _, stop_fn in reversed(self._leader_tasks):
            try:
                await stop_fn()
                log.debug("Leader task '%s' stopped", label)
            except Exception as e:
                log.warning("Leader task '%s' stop error: %s", label, e)
        self._tasks_started = False

    @property
    def is_active(self) -> bool:
        return leader_election.is_leader


leadership_controller = LeadershipController()
