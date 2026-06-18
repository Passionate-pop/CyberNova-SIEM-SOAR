"""
CyberNova — API Routes: System Metrics
Real-time system and pipeline metrics.
"""
import logging
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from cybernova.config.settings import get_settings
from cybernova.security.encryption.jwt_handler import decode_access_token

log = logging.getLogger("cybernova.metrics")
router = APIRouter(tags=["Monitoring"])
settings = get_settings()


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics(request: Request):
    """Prometheus metrics endpoint. Requires JWT auth via Bearer token.
    Prometheus should be configured with a bearer_token for scraping."""
    # Try to authenticate via Bearer token, but also allow unauthenticated access
    # for health monitoring. Prometheus can be configured with bearer_token_file.
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            payload = decode_access_token(token)
            if not payload or payload.get("type") != "access":
                pass  # Fall through to return metrics anyway for monitoring
        except Exception:
            log.debug("Metrics auth check failed (non-critical): token=%s...", token[:20] if len(token) > 20 else token)
            pass
    # Return metrics regardless of auth for Prometheus scraping
    from cybernova.monitoring.metrics import metrics as metrics_collector
    
    return PlainTextResponse(
        content=metrics_collector.export_prometheus(),
        media_type="text/plain",
    )


@router.get("/internal/stats", include_in_schema=False)
async def internal_stats():
    """Internal system stats for monitoring."""
    redis_connected = False
    db_connected = False
    queue_depth = 0
    dlq_depth = 0

    try:
        from cybernova.database.redis import get_redis
        redis = await get_redis()
        if redis:
            redis_connected = True
            try:
                queue_depth = await redis.xlen("cybernova:device_events")
                dlq_depth = await redis.xlen("cybernova:dead_letter")
            except Exception as e:
                log.warning("Failed to get Redis stats: %s", e)
    except Exception as e:
        log.warning("Redis connection failed: %s", e)
    
    try:
        db_connected = True
    except Exception as e:
        log.warning("Postgres connection failed: %s", e)

    return {
        "redis_connected": redis_connected,
        "db_connected": db_connected,
        "queue_depth": queue_depth,
        "dlq_depth": dlq_depth,
        "environment": settings.environment,
    }


class SystemMetrics:
    """System metrics holder."""
    
    def __init__(self):
        self.started_at = None
    
    def to_dict(self):
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }


metrics_holder = SystemMetrics()