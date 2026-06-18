"""
CyberNova — HA Health Monitor
Tracks health of pipeline components, database, Redis, and provides
a unified health status for load balancers and orchestration.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.ha.monitor")

CHECK_INTERVAL = 60  # seconds between health checks (was 15 — reduced polling to save CPU)


class HealthMonitor:
    """
    Monitors all critical component health.
    Used by load balancers / K8s readiness probes and internal failover decisions.
    """

    def __init__(self):
        self._running = False
        self._last_check: Optional[datetime] = None
        self._health_cache: Dict[str, Any] = {}
        self._check_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._running = True
        self._check_task = asyncio.create_task(self._health_loop())
        log.info("HealthMonitor started")

    async def stop(self) -> None:
        self._running = False
        if self._check_task and not self._check_task.done():
            self._check_task.cancel()
        log.info("HealthMonitor stopped")

    async def _health_loop(self) -> None:
        while self._running:
            self._health_cache = await self.check_all()
            self._last_check = datetime.now(timezone.utc)
            await asyncio.sleep(CHECK_INTERVAL)

    async def check_all(self) -> Dict[str, Any]:
        """Check health of all critical components."""
        checks = {
            "database": await self._check_database(),
            "database_replica": await self._check_replica_database(),
            "redis": await self._check_redis(),
            "pipeline": await self._check_pipeline(),
            "leader_election": await self._check_leader_election(),
            "event_bus": await self._check_event_bus(),
        }
        all_healthy = all(c.get("healthy", False) for c in checks.values())
        overall = "healthy" if all_healthy else "degraded"
        if not all_healthy:
            unhealthy = [name for name, c in checks.items() if not c.get("healthy")]
            log.warning("Health: %s — unhealthy components: %s", overall, unhealthy)
        return {
            "overall": overall,
            "healthy": all_healthy,
            "checks": checks,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _check_database(self) -> Dict[str, Any]:
        try:
            from cybernova.database.postgres.session import get_db_session
            from sqlalchemy import text
            async for db in get_db_session():
                await db.execute(text("SELECT 1"))
                return {"healthy": True, "status": "connected"}
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e)}

    async def _check_replica_database(self) -> Dict[str, Any]:
        try:
            from cybernova.database.postgres.session import get_replica_health
            return await get_replica_health()
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e), "configured": False}

    async def _check_redis(self) -> Dict[str, Any]:
        try:
            redis = await get_redis()
            if redis:
                await redis.ping()
                return {"healthy": True, "status": "connected"}
            return {"healthy": False, "status": "unavailable"}
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e)}

    async def _check_pipeline(self) -> Dict[str, Any]:
        try:
            from cybernova.pipeline.unified_pipeline import unified_pipeline
            from cybernova.ha.leader import leader_election
            is_leader = leader_election.is_leader or leader_election._local_mode
            if unified_pipeline._running:
                metrics = await unified_pipeline.get_metrics()
                return {"healthy": True, "status": "running", "metrics": metrics}
            if not is_leader:
                return {"healthy": True, "status": "not_leader"}
            return {"healthy": False, "status": "stopped"}
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e)}

    async def _check_leader_election(self) -> Dict[str, Any]:
        try:
            from cybernova.ha.leader import leader_election
            status = await leader_election.get_leader_status()
            return {"healthy": True, "status": "active", "is_leader": status["is_leader"]}
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e)}

    async def _check_event_bus(self) -> Dict[str, Any]:
        try:
            from cybernova.pipeline.unified_pipeline import unified_pipeline
            from cybernova.ha.leader import leader_election
            is_leader = leader_election.is_leader or leader_election._local_mode
            if unified_pipeline._bus:
                metrics = await unified_pipeline.get_metrics()
                pending = metrics.get("pending", {})
                total_pending = sum(v for v in pending.values() if isinstance(v, (int, float)))
                healthy = total_pending < 10000  # alert if >10k pending events
                return {
                    "healthy": healthy,
                    "status": "ok" if healthy else "backpressure",
                    "pending_events": total_pending,
                }
            if not is_leader:
                return {"healthy": True, "status": "not_leader"}
            return {"healthy": False, "status": "no_bus"}
        except Exception as e:
            return {"healthy": False, "status": "error", "detail": str(e)}

    def get_last_health(self) -> Dict[str, Any]:
        return self._health_cache if self._health_cache else {"overall": "unknown", "healthy": False, "checks": {}}

    def is_healthy(self) -> bool:
        return self._health_cache.get("healthy", False)


health_monitor = HealthMonitor()
