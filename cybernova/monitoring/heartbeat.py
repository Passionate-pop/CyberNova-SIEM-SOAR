"""
CyberNova — Component Heartbeat Monitor
Tracks health of all background components/tasks.
Exposes status for /health and /ready endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

log = logging.getLogger("cybernova.monitoring.heartbeat")

HEARTBEAT_TIMEOUT = 600
CHECK_INTERVAL = 15


@dataclass
class ComponentStatus:
    name: str
    status: str = "starting"
    last_heartbeat: float = 0.0
    error_count: int = 0
    last_error: Optional[str] = None
    started_at: float = 0.0


class HeartbeatMonitor:
    def __init__(self, timeout: int = HEARTBEAT_TIMEOUT, check_interval: int = CHECK_INTERVAL):
        self._components: Dict[str, ComponentStatus] = {}
        self._timeout = timeout
        self._check_interval = check_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def register(self, name: str) -> None:
        if name not in self._components:
            self._components[name] = ComponentStatus(
                name=name,
                started_at=time.monotonic(),
            )
            log.debug("Component registered: %s", name)

    def mark_healthy(self, name: str) -> None:
        self.register(name)
        self._components[name].status = "healthy"
        self._components[name].last_heartbeat = time.monotonic()

    def mark_unhealthy(self, name: str, error: Optional[str] = None) -> None:
        self.register(name)
        self._components[name].status = "unhealthy"
        self._components[name].last_error = error
        self._components[name].error_count += 1

    def mark_stopped(self, name: str) -> None:
        if name in self._components:
            self._components[name].status = "stopped"

    def heartbeat(self, name: str) -> None:
        if name in self._components:
            self._components[name].last_heartbeat = time.monotonic()
            if self._components[name].status == "starting":
                self._components[name].status = "healthy"

    def get_status(self, name: str) -> Optional[ComponentStatus]:
        return self._components.get(name)

    def get_all(self) -> List[ComponentStatus]:
        return list(self._components.values())

    def is_healthy(self) -> bool:
        if not self._components:
            return True
        now = time.monotonic()
        for comp in self._components.values():
            if comp.status == "unhealthy":
                return False
            if comp.status == "healthy" and now - comp.last_heartbeat > self._timeout:
                return False
        return True

    def get_unhealthy(self) -> List[ComponentStatus]:
        now = time.monotonic()
        result = []
        for comp in self._components.values():
            if comp.status == "unhealthy":
                result.append(comp)
            elif comp.status == "healthy" and now - comp.last_heartbeat > self._timeout:
                result.append(comp)
        return result

    def summary(self) -> Dict[str, object]:
        all_comps = self.get_all()
        unhealthy = self.get_unhealthy()
        return {
            "healthy": self.is_healthy(),
            "total_components": len(all_comps),
            "unhealthy_count": len(unhealthy),
            "components": {
                c.name: {
                    "status": c.status,
                    "uptime_seconds": round(time.monotonic() - c.started_at) if c.started_at else 0,
                    "error_count": c.error_count,
                    "last_error": c.last_error,
                }
                for c in all_comps
            },
            "unhealthy_components": [c.name for c in unhealthy],
        }

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._check_loop())
        log.info("Heartbeat monitor started (timeout=%ds, interval=%ds)", self._timeout, self._check_interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Heartbeat monitor stopped")

    async def _check_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                now = time.monotonic()
                for comp in self._components.values():
                    if comp.status == "starting" and now - comp.started_at > 300:
                        comp.status = "unhealthy"
                        comp.last_error = "Never reported healthy after 300s"
                    elif comp.status == "healthy" and now - comp.last_heartbeat > self._timeout:
                        comp.status = "unhealthy"
                        comp.last_error = f"No heartbeat for {self._timeout}s"
                        log.warning("Component heartbeat timeout: %s", comp.name)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("Heartbeat check loop error: %s", e)


heartbeat_monitor = HeartbeatMonitor()
