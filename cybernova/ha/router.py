"""
CyberNova — HA Status Router
Provides cluster status, leader info, health checks for load balancers.
"""
import logging
from fastapi import APIRouter, Depends

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_pipeline_view

from cybernova.ha.leader import leader_election
from cybernova.ha.monitor import health_monitor

log = logging.getLogger("cybernova.ha.router")
router = APIRouter(prefix="/api/v1/ha", tags=["High Availability"])


@router.get("/status", summary="HA cluster status")
async def ha_status(
    user: CurrentUser = Depends(require_pipeline_view),
):
    leader_status = await leader_election.get_leader_status()
    health = health_monitor.get_last_health()
    return {
        "cluster": {
            "instance_id": leader_status["instance_id"],
            "is_leader": leader_status["is_leader"],
            "leader_instance": leader_status["leader_instance"],
            "local_mode": leader_status["local_mode"],
        },
        "health": health,
    }


@router.get("/leader", summary="Get current leader info")
async def leader_status(
    user: CurrentUser = Depends(require_pipeline_view),
):
    return await leader_election.get_leader_status()


@router.get("/health", summary="Detailed health check for load balancers")
async def ha_health():
    """No auth required — for load balancer health probes."""
    health = health_monitor.get_last_health()
    return health


@router.get("/ready", summary="Readiness probe")
async def ready_probe():
    """K8s-style readiness: 200 if healthy, 503 if not."""
    from fastapi import Response
    import json
    health = health_monitor.get_last_health()
    is_ready = health.get("healthy", False)
    return Response(
        content=json.dumps({"status": "ready" if is_ready else "not_ready", "checks": health}),
        media_type="application/json",
        status_code=200 if is_ready else 503,
    )
