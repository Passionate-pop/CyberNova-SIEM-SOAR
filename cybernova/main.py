"""
CyberNova platform entry point. SIEM/SOAR with real-time pipeline.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import json

from fastapi import Depends, FastAPI, Response, WebSocket, Request
from sqlalchemy import text

from cybernova.config.settings import get_settings
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.database.postgres.session import close_db
from cybernova.database.redis import get_redis, close_redis
from cybernova.config.logging import setup_json_logging
from cybernova.core.workers.worker import (
    enrichment_worker, correlation_worker, ai_worker, webhook_worker,
)
from cybernova.api.middleware.stack import register_middleware

# ingestion
from cybernova.ingestion.syslog_receiver import syslog_receiver  # noqa: E402
from cybernova.ingestion.file_watcher import file_watcher  # noqa: E402

# pipeline
from cybernova.pipeline.unified_pipeline import unified_pipeline

# monitoring
from cybernova.monitoring.heartbeat import heartbeat_monitor
from cybernova.monitoring.health import health_registry

# websocket
from cybernova.api.websocket import ws_handler

# Logger for import guards (defined early so _safe_import can use it)
log = logging.getLogger("cybernova.main")

# Track which modules failed to import — exposes in /health for diagnostics
_FAILED_IMPORTS: list[str] = []

# Safe import helper — one broken module won't crash the entire app
def _safe_import(module_path: str, import_name: str, default=None):
    """Import a router/module safely — log warning on failure, never crash."""
    try:
        mod = __import__(module_path, fromlist=[import_name])
        return getattr(mod, import_name)
    except Exception as exc:
        label = f"{module_path}.{import_name}"
        _FAILED_IMPORTS.append(label)
        log.warning("[import-guard] FAILED to import %s: %s — skipping", label, exc)
        return default

# routers (safe imports — one broken module won't kill the whole app)
auth_router = _safe_import("cybernova.auth.routes.auth_router", "router")
device_router = _safe_import("cybernova.devices.router", "router")
command_router = _safe_import("cybernova.devices.commands", "router")
cmd_agent_router = _safe_import("cybernova.devices.commands", "agent_router")
blocklist_router = _safe_import("cybernova.devices.blocklist", "router")
bl_agent_router = _safe_import("cybernova.devices.blocklist", "agent_router")
device_event_processor = _safe_import("cybernova.pipeline.device_processor", "device_event_processor")
ingestion_router = _safe_import("cybernova.ingestion.routes.ingest_router", "router")
detection_router = _safe_import("cybernova.detection.routes.detection_router", "router")
response_router = _safe_import("cybernova.response.routes.response_router", "router")
datalake_router = _safe_import("cybernova.datalake.router", "router")
ai_network_router = _safe_import("cybernova.api.routes", "router")
dashboard_router = _safe_import("cybernova.api.routes.dashboard_router", "router")
pipeline_router = _safe_import("cybernova.pipeline.router", "router")
audit_router = _safe_import("cybernova.audit.routes", "router")
org_router = _safe_import("cybernova.api.organizations", "router")
admin_devices_router = _safe_import("cybernova.api.routes.admin_devices", "router")
policy_admin_router = _safe_import("cybernova.api.routes.policy_admin", "router")
dlq_router = _safe_import("cybernova.api.routes.dlq", "router")
metrics_router = _safe_import("cybernova.api.routes.metrics", "router")
analytics_router = _safe_import("cybernova.analytics.routes", "router")
setup_router = _safe_import("cybernova.api.routes.setup", "router")
soar_router = _safe_import("cybernova.response.routes.soar_actions", "router")
automation_router = _safe_import("cybernova.response.automation.router", "router")
playbook_routes_router = _safe_import("cybernova.api.routes.playbook_routes", "router")
agent_ingest_router = _safe_import("cybernova.ingestion.routes.agent_ingest", "router")
notifications_router = _safe_import("cybernova.api.routes.notifications_router", "router")
agent_download_router = _safe_import("cybernova.api.routes.agent_download", "router")
agent_auth_router = _safe_import("cybernova.api.routes.agent_auth", "router")
agent_heartbeat_router = _safe_import("cybernova.api.routes.agent_heartbeat", "router")
agent_telemetry_router = _safe_import("cybernova.api.routes.agent_telemetry", "router")
agent_commands_router = _safe_import("cybernova.api.routes.agent_commands", "router")
agent_update_router = _safe_import("cybernova.api.routes.agent_update", "router")
noise_router = _safe_import("cybernova.detection.routes.noise_routes", "router")
agent_receiver_router = _safe_import("cybernova.ingestion.agent_receiver", "router")
threat_intel_feeds_router = _safe_import("cybernova.network.feeds.router", "router")
anomaly_router = _safe_import("cybernova.detection.anomaly.router", "router")
isolation_router = _safe_import("cybernova.detection.isolation.router", "router")
retention_router = _safe_import("cybernova.storage.router", "router")
testing_router = _safe_import("cybernova.testing.router", "router")
user_admin_router = _safe_import("cybernova.auth.routes.user_admin_router", "router")
search_router = _safe_import("cybernova.search.router", "router")
compliance_router = _safe_import("cybernova.compliance.router", "router")
compliance_routes_router = _safe_import("cybernova.api.routes.compliance_routes", "router")
ha_router = _safe_import("cybernova.ha.router", "router")
performance_router = _safe_import("cybernova.performance.router", "router")
suppression_router = _safe_import("cybernova.suppression.router", "router")
backup_router = _safe_import("cybernova.backup.router", "router")
multi_region_router = _safe_import("cybernova.multi_region.router", "router")
marketplace_router = _safe_import("cybernova.marketplace.router", "router")
genai_router = _safe_import("cybernova.genai.router", "router")

worm_router = _safe_import("cybernova.worm.router", "router")
cloud_router = _safe_import("cybernova.cloud.router", "router")
cspm_router = _safe_import("cybernova.cspm.router", "router")
residency_router = _safe_import("cybernova.residency.router", "router")
abac_router = _safe_import("cybernova.abac.router", "router")
ml_router = _safe_import("cybernova.ml.router", "router")
ueba_router = _safe_import("cybernova.ueba.router", "router")
ransomware_router = _safe_import("cybernova.detection.ransomware.router", "router")
rag_router = _safe_import("cybernova.ai.rag.router", "router")
tenant_deletion_router = _safe_import("cybernova.api.routes.tenant_deletion", "router")
tenant_export_router = _safe_import("cybernova.api.routes.tenant_export", "router")
security_overview_router = _safe_import("cybernova.api.routes.security_overview", "router")
analysis_router = _safe_import("cybernova.api.routes.analysis", "router")
diagnostics_router = _safe_import("cybernova.api.routes.diagnostics", "router")

setup_json_logging()
from cybernova.monitoring.tracing import setup_tracing  # noqa: E402
from cybernova.lifecycle.shutdown import GracefulShutdown, safe_stop  # noqa: E402
from cybernova.lifecycle import startup as lifecycle_startup  # noqa: E402
settings = get_settings()
setup_tracing(
    service_name=settings.otel_service_name,
    service_version=settings.app_version,
    environment=settings.environment,
    otlp_endpoint=settings.otel_endpoint,
)


def safe_int(value, default=0):
    try:
        v = value() if callable(value) else value
        return int(v) if not hasattr(v, '__iter__') or isinstance(v, (str, bytes)) else len(v)
    except (TypeError, ValueError, AttributeError):
        return default


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — startup and shutdown."""
    log.info("=" * 60)
    log.info("CyberNova %s starting [%s]", settings.app_version, settings.environment)
    log.info("=" * 60)

    # --- Phase 1: Core Infrastructure ---
    await heartbeat_monitor.start()
    await lifecycle_startup.startup_database(settings, heartbeat_monitor)
    redis = await lifecycle_startup.startup_redis(settings, heartbeat_monitor)

    # --- Phase 2: High Availability ---
    leader_election = await lifecycle_startup.startup_ha(heartbeat_monitor)
    _is_leader = lifecycle_startup.resolve_is_leader(leader_election)

    # --- Phase 3: Pipeline ---
    await lifecycle_startup.startup_pipeline(settings, _is_leader, heartbeat_monitor)

    # --- Phase 4: Integrations ---
    await lifecycle_startup.startup_integrations(_is_leader, heartbeat_monitor)

    # --- Phase 5: Ingestion Sources ---
    await lifecycle_startup.startup_syslog(settings, _is_leader, unified_pipeline, heartbeat_monitor)
    await lifecycle_startup.startup_file_watcher(settings, _is_leader, unified_pipeline, heartbeat_monitor)

    # --- Phase 6: WebSocket & Dashboard ---
    await lifecycle_startup.startup_ws_dashboard(heartbeat_monitor)

    # --- Phase 7: Machine Learning ---
    await lifecycle_startup.startup_ml_training(_is_leader, heartbeat_monitor)
    await lifecycle_startup.startup_ml_model(_is_leader, redis, heartbeat_monitor)

    # --- Phase 8: Agent & Threat Intelligence ---
    await lifecycle_startup.startup_agent_manager(_is_leader, heartbeat_monitor)
    await lifecycle_startup.startup_threat_feeds(_is_leader, heartbeat_monitor)

    # --- Phase 9: Data Management ---
    await lifecycle_startup.startup_retention(_is_leader, heartbeat_monitor)
    await lifecycle_startup.startup_device_processor(_is_leader, heartbeat_monitor)
    await lifecycle_startup.startup_dlq_worker(_is_leader, heartbeat_monitor)

    # --- Phase 10: Background Services ---
    await lifecycle_startup.startup_ha_health_monitor(heartbeat_monitor)
    await lifecycle_startup.startup_backup(_is_leader, heartbeat_monitor)
    await lifecycle_startup.startup_marketplace()
    await lifecycle_startup.startup_genai()
    await lifecycle_startup.startup_cross_region(heartbeat_monitor)
    await lifecycle_startup.startup_key_rotation(_is_leader, heartbeat_monitor)

    # --- Phase 12: On-Call & Runbooks ---
    await lifecycle_startup.startup_oncall(settings)
    await lifecycle_startup.startup_runbooks()

    log.info("=" * 60)
    log.info("CyberNova READY -- listening on %s:%d", settings.host, settings.port)
    log.info("  -> API: http://localhost:%d/docs", settings.port)
    log.info("  -> Setup: POST /api/v1/setup/admin")
    log.info("  -> Agent: irm http://localhost:%d/agent.ps1 | iex", settings.port)
    log.info("=" * 60)

    yield  # app is live

    # --- phased graceful shutdown ---
    async with GracefulShutdown(timeout=settings.shutdown_grace_period) as gs:
        log.info("CyberNova shutting down (grace period: %.1fs)...", gs.timeout)

        # Phase 1: stop accepting new work
        log.info("Shutdown phase 1: stopping ingestion and pipeline...")

        await gs.drain_with_timeout("dashboard_push_worker", safe_stop(
            "dashboard_push_worker",
            lambda: __import__("cybernova.dashboard.websocket_worker",
                               fromlist=["dashboard_push_worker"]).dashboard_push_worker.stop(),
        ))
        await gs.drain_with_timeout("syslog_receiver", safe_stop("syslog_receiver", syslog_receiver.stop()))
        await gs.drain_with_timeout("file_watcher", safe_stop("file_watcher", file_watcher.stop()))

        await gs.drain_with_timeout("agent_manager", safe_stop(
            "agent_manager",
            lambda: __import__("cybernova.ingestion.agent.manager",
                               fromlist=["agent_manager"]).agent_manager.stop(),
        ))
        await gs.drain_with_timeout("feed_scheduler", safe_stop(
            "feed_scheduler",
            lambda: __import__("cybernova.network.feeds.scheduler",
                               fromlist=["feed_scheduler"]).feed_scheduler.stop(),
        ))
        await gs.drain_with_timeout("retention_manager", safe_stop(
            "retention_manager",
            lambda: __import__("cybernova.storage.retention",
                               fromlist=["retention_manager"]).retention_manager.stop(),
        ))
        if device_event_processor is not None:
            await gs.drain_with_timeout("device_event_processor",
                                        safe_stop("device_event_processor", device_event_processor.stop()))
        await gs.drain_with_timeout(
            "dlq_worker",
            safe_stop(
                "dlq_worker",
                lambda: __import__(
                    "cybernova.pipeline.dead_letter_worker",
                    fromlist=["dead_letter_worker"],
                ).dead_letter_worker.stop(),
            ),
        )

        # Phase 2: drain in-flight pipeline events
        log.info("Shutdown phase 2: draining pipeline events...")

        # Stop Redis-backed components before closing connections
        await gs.drain_with_timeout(
            "redis_components",
            lifecycle_startup.shutdown_redis_components(),
        )

        if unified_pipeline._running:
            await gs.drain_with_timeout("pipeline_drain", unified_pipeline.drain(
                timeout=gs.remaining() * 0.3,
            ))
        if unified_pipeline._running:
            await gs.drain_with_timeout("pipeline_close", unified_pipeline.close())

        if gs.remaining() > 0:
            for worker in (enrichment_worker, correlation_worker, ai_worker, webhook_worker):
                budget = gs.remaining() / 4
                if budget > 0:
                    await worker.shutdown(timeout=budget)

        await gs.drain_with_timeout("health_monitor", safe_stop(
            "health_monitor",
            lambda: __import__("cybernova.ha.monitor",
                               fromlist=["health_monitor"]).health_monitor.stop(),
        ))
        await gs.drain_with_timeout("leader_election", safe_stop(
            "leader_election",
            lambda: __import__("cybernova.ha.leader",
                               fromlist=["leader_election"]).leader_election.stop(),
        ))
        await gs.drain_with_timeout("backup_manager", safe_stop(
            "backup_manager",
            lambda: __import__("cybernova.backup.manager",
                               fromlist=["backup_manager"]).backup_manager.stop(),
        ))
        await gs.drain_with_timeout("cross_region_replicator", safe_stop(
            "cross_region_replicator",
            lambda: __import__("cybernova.multi_region.replication",
                               fromlist=["cross_region_replicator"]).cross_region_replicator.stop(),
        ))
        await gs.drain_with_timeout("key_rotation", safe_stop(
            "key_rotation",
            lambda: __import__("cybernova.auth.services.key_rotation",
                               fromlist=["key_rotation_service"]).key_rotation_service.stop(),
        ))
        await gs.drain_with_timeout("heartbeat_monitor", safe_stop("heartbeat_monitor", heartbeat_monitor.stop()))

        await gs.drain_with_timeout("oncall_router", safe_stop(
            "oncall_router",
            __import__("cybernova.alerting.oncall", fromlist=["oncall_router"]).oncall_router.stop(),
        ))

        # Phase 3: close connections
        log.info("Shutdown phase 3: closing connections...")
        await gs.drain_with_timeout("close_redis", safe_stop("close_redis", close_redis()))
        await gs.drain_with_timeout("close_db", safe_stop("close_db", close_db()))
        from cybernova.monitoring.tracing import close_tracing
        close_tracing()

        log.info("CyberNova shutdown complete")


# app creation

app = FastAPI(
    title="CyberNova",
    description="""
## Production-Grade Cybersecurity Platform

### Architecture
- **SIEM**: Real-time event ingestion, normalization, and detection
- **SOAR**: Built-in response actions (block IP, isolate device, disable user)
- **AI**: Automated incident investigation and analysis

### Real-Time Pipeline
Events flow through:
1. **Ingestion** → 2. **Normalization** → 3. **Enrichment** → 4. **Detection**
5. **Correlation** → 6. **Alert** → 7. **SOAR** → 8. **AI Investigation**

### Quick Start
```bash
# 1. First run setup (if no users exist)
POST /api/v1/setup/admin

# 2. Ingest agent events
POST /api/v1/ingest/event

# 3. Agent install (Windows)
irm http://localhost:8000/agent.ps1 | iex

# 4. Monitor
GET /api/v1/pipeline/status
```
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# OpenTelemetry tracing middleware (first added = innermost)
from cybernova.monitoring.tracing import TraceMiddleware  # noqa: E402
app.add_middleware(TraceMiddleware)

# WAF middleware — inspects HTTP traffic for attacks
from cybernova.protection.waf_middleware import register_waf_middleware  # noqa: E402
from cybernova.protection.waf import waf_engine  # noqa: E402
register_waf_middleware(app)
log.info("WAF engine loaded: %d rules, cache size=%d", len(waf_engine.all_rules), waf_engine._cache._maxsize)

# Unified rate limiting middleware
from cybernova.security.plan_rate_limiter import PlanRateLimitMiddleware  # noqa: E402
app.add_middleware(PlanRateLimitMiddleware)

# CORS + Security headers + GZip (last added = outermost)
register_middleware(app)

# Include all routers (skip any that failed to import)
for _router in [
    auth_router, device_router, command_router, cmd_agent_router,
    blocklist_router, bl_agent_router, ingestion_router, detection_router,
    response_router, datalake_router, ai_network_router, dashboard_router,
    pipeline_router, audit_router, org_router, admin_devices_router,
    policy_admin_router, dlq_router, metrics_router, analytics_router,
    setup_router, soar_router, agent_ingest_router,
    agent_auth_router, agent_heartbeat_router, agent_telemetry_router, agent_commands_router,
    agent_update_router, agent_download_router, noise_router,
    notifications_router, agent_receiver_router,
    threat_intel_feeds_router, anomaly_router, isolation_router,
    retention_router, testing_router, user_admin_router, automation_router,
    playbook_routes_router, search_router, compliance_router,
    compliance_routes_router, ha_router, performance_router,
    suppression_router, backup_router, multi_region_router,
    marketplace_router, genai_router, worm_router, cloud_router,
    cspm_router, residency_router, abac_router, ml_router, ueba_router,
    ransomware_router, rag_router, tenant_deletion_router,
    tenant_export_router,    analysis_router, security_overview_router, diagnostics_router,
]:
    if _router is not None:
        app.include_router(_router)


# api versioning middleware

from cybernova.api_versioning.middleware import APIVersionMiddleware  # noqa: E402
app.add_middleware(APIVersionMiddleware)


# websocket endpoint

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    tenant_id: str = None,
):
    """
    WebSocket endpoint for real-time updates.

    Connect: ws://localhost:8000/ws?tenant_id=<tenant>

    Authentication: JWT is passed via Sec-WebSocket-Protocol header
    (first sub-protocol value). This avoids leaking tokens in URLs
    (no exposure in nginx logs, browser history, or referrer headers).

    Messages received:
    - ping/pong: Keep-alive
    - subscribe: Subscribe to event types
    - unsubscribe: Unsubscribe from event types
    - get_status: Get pipeline status

    Messages sent:
    - new_alert: New alert created
    - alert_updated: Alert status changed
    - new_incident: Incident created/updated
    - soar_action: SOAR action triggered
    - pipeline_status: Periodic status updates
    """
    sub_protocols = websocket.headers.get("sec-websocket-protocol", "")
    token = sub_protocols.split(",")[0].strip() if sub_protocols else None
    await ws_handler.handle_connection(websocket, token, tenant_id)


# root / health endpoints

@app.get("/", tags=["System"])
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "pipeline": "active" if unified_pipeline._running else "stopped",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health", tags=["System"])
async def health():
    """Enterprise liveness probe — is the process alive?

    Always returns HTTP 200 (process is running) with detailed status.
    - 'status': 'healthy' if all critical components are operational
    - 'status': 'degraded' if non-critical components are down
    - Details include per-component health, startup phases, and uptime.
    """
    # Merge heartbeat_monitor data into health_registry for backward compat
    comp_summary = health_registry.summary()
    # Expose failed module imports so broken routers are visible
    comp_summary["failed_imports"] = _FAILED_IMPORTS
    comp_summary["failed_import_count"] = len(_FAILED_IMPORTS)
    return comp_summary


@app.get("/ready", tags=["System"])
async def ready():
    """Readiness probe — K8s-compatible, enterprise-grade.

    Returns 200 (ready) ONLY when ALL critical dependencies are operational.
    Returns 503 (not_ready) with detailed failure information when any
    critical dependency is down. Kubernetes uses this to route traffic.

    Production note: configure the K8s readiness probe with:
      initialDelaySeconds: 60
      periodSeconds: 30
      failureThreshold: 3
    """
    # Do a live check on DB and Redis for the readiness probe
    redis = await get_redis()
    db_ok = False
    db_pool_stats = {}
    try:
        from cybernova.database.postgres.session import get_db_session, engine
        async for db in get_db_session():
            await db.execute(text("SELECT 1"))
            db_ok = True
            break
        if hasattr(engine, "pool"):
            pool = engine.pool
            db_pool_stats = {
                "size": safe_int(pool.size()),
                "checked_in": safe_int(pool.checkedin()),
                "checked_out": safe_int(pool.checkedout()),
                "overflow": safe_int(pool.overflow()),
            }
    except Exception as e:
        log.warning("Database health check failed: %s", e)

    redis_ok = redis is not None
    redis_pool_stats = {}
    if redis_ok and hasattr(redis, "connection_pool"):
        try:
            rp = redis.connection_pool
            redis_pool_stats = {
                "max_connections": safe_int(getattr(rp, "max_connections", 0)),
                "in_use_connections": safe_int(getattr(rp, "_in_use_connections", 0)),
                "available_connections": safe_int(getattr(rp, "_available_connections", 0)),
            }
        except AttributeError:
            pass

    pipeline_ok = unified_pipeline._running

    # Use the enterprise health registry for component-level readiness
    registry_check = health_registry.readiness_check()
    is_ready = db_ok and redis_ok and registry_check["ready"]
    status_code = 200 if is_ready else 503

    return Response(
        content=json.dumps({
            "status": "ready" if is_ready else "not_ready",
            "uptime_seconds": health_registry.summary()["uptime_seconds"],
            "checks": {
                "database": "ok" if db_ok else "failed",
                "redis": "ok" if redis_ok else "failed",
                "pipeline": "running" if pipeline_ok else "stopped",
                "components": "ok" if registry_check["ready"] else "degraded",
            },
            "critical_unhealthy": registry_check["checks"],
            "pool_stats": {
                "database": db_pool_stats,
                "redis": redis_pool_stats,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, indent=2, default=str),
        media_type="application/json",
        status_code=status_code,
    )


@app.get("/health/detailed", tags=["System"])
async def detailed_health(user: CurrentUser = Depends(get_current_user)):
    """Detailed health check with full system telemetry."""
    redis = await get_redis()
    pipeline_metrics = await unified_pipeline.get_metrics()

    stream_health = {}
    if redis:
        try:
            from cybernova.streaming.reliability import StreamReliabilityEngine
            rel_engine = StreamReliabilityEngine(redis)
            stream_health = await rel_engine.get_stream_health()
        except Exception as e:
            log.warning("Stream health check failed: %s", e)

    comp_health = health_registry.summary()
    return {
        "status": comp_health["status"],
        "ready": comp_health["ready"],
        "version": settings.app_version,
        "environment": settings.environment,
        "uptime_seconds": comp_health["uptime_seconds"],
        "startup_phases": comp_health["startup_phases"],
        "services": {
            "database": "connected",
            "redis": "connected" if redis else "unavailable",
            "event_bus": "active" if redis else "in-memory",
            "pipeline": "running" if unified_pipeline._running else "stopped",
        },
        "components": comp_health["components"],
        "unhealthy_components": comp_health["unhealthy_components"],
        "critical_unhealthy": comp_health["critical_unhealthy"],
        "pipeline_stats": pipeline_metrics,
        "stream_health": stream_health,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.api_route("/api", methods=["GET", "HEAD"], include_in_schema=False)
async def api_root(request: Request):
    """API root — redirect to /docs for API explorer."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")


@app.get("/api/v1/monitoring/metrics", tags=["System"])
async def system_metrics(
    user: CurrentUser = Depends(get_current_user),
):
    from cybernova.monitoring.metrics import metrics
    pipeline_metrics = await unified_pipeline.get_metrics()
    return {
        **metrics.get_all(),
        "pipeline": pipeline_metrics,
    }


@app.get("/api/v1/monitoring/sla", tags=["System"])
async def sla_metrics():
    """SLA metrics including P99 latency, availability, queue depths."""
    from cybernova.monitoring.sla import get_sla_metrics

    metrics = get_sla_metrics()
    return metrics.get_all_metrics()


@app.get("/api/v1/monitoring/circuit-breakers", tags=["System"])
async def circuit_breaker_status():
    """Get status of all circuit breakers."""
    from cybernova.resilience.circuit_breaker import get_all_circuit_breakers_status
    return {"circuit_breakers": await get_all_circuit_breakers_status()}


# ── Prometheus /metrics endpoint ────────────────────────────────────────

@app.get("/metrics", tags=["System"])
async def metrics_endpoint():
    """Prometheus-compatible metrics endpoint (unauthenticated for Prometheus scraping)."""
    from cybernova.monitoring.metrics import metrics
    pipeline_metrics = await unified_pipeline.get_metrics()
    registry = health_registry.summary()
    lines = [
        "# HELP cybernova_uptime_seconds Application uptime in seconds",
        "# TYPE cybernova_uptime_seconds gauge",
        f"cybernova_uptime_seconds {registry.get('uptime_seconds', 0)}",
        "# HELP cybernova_pipeline_running Whether the pipeline is running",
        "# TYPE cybernova_pipeline_running gauge",
        f"cybernova_pipeline_running {1 if unified_pipeline._running else 0}",
        "# HELP cybernova_events_ingested_total Total events ingested",
        "# TYPE cybernova_events_ingested_total counter",
        f"cybernova_events_ingested_total {pipeline_metrics.get('ingested', 0)}",
        "# HELP cybernova_alerts_created_total Total alerts created",
        "# TYPE cybernova_alerts_created_total counter",
        f"cybernova_alerts_created_total {pipeline_metrics.get('alerted', 0)}",
        "# HELP cybernova_errors_total Total pipeline errors",
        "# TYPE cybernova_errors_total counter",
        f"cybernova_errors_total {pipeline_metrics.get('errors', 0)}",
        "# HELP cybernova_pipeline_avg_latency_ms Average pipeline latency in ms",
        "# TYPE cybernova_pipeline_avg_latency_ms gauge",
        f"cybernova_pipeline_avg_latency_ms {pipeline_metrics.get('avg_latency_ms', 0)}",
        "# HELP cybernova_soar_enabled Whether SOAR is enabled",
        "# TYPE cybernova_soar_enabled gauge",
        f"cybernova_soar_enabled {1 if settings.soar_enabled else 0}",
        "# HELP cybernova_active_agents Number of active agents",
        "# TYPE cybernova_active_agents gauge",
        "cybernova_active_agents 0",
    ]
    # Add pending queue depths
    pending = pipeline_metrics.get("pending", {})
    for stage, depth in pending.items():
        lines.append(f"# HELP cybernova_stream_lag Queue depth for {stage}")
        lines.append(f"# TYPE cybernova_stream_lag gauge")
        lines.append(f"cybernova_stream_lag{{stream=\"{stage}\"}} {depth}")
    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# waf security health

@app.get("/api/v1/security/waf/stats", tags=["Security"])
async def waf_stats():
    """WAF engine statistics: cache hit rate, total inspections, rules loaded."""
    from cybernova.protection.waf import waf_engine
    stats = waf_engine.get_stats()
    # Ensure consistent field naming for frontend compatibility
    stats["rules_loaded"] = stats.get("rules_count", 0)
    # Track total blocks from inspection — WAF engine doesn't have _total_blocked
    stats["total_blocked"] = 0
    return stats
