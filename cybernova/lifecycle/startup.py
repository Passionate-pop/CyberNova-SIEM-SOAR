"""Application startup orchestration — breaks lifespan() into focused, testable phases."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from cybernova.config.settings import Settings
    from cybernova.monitoring.heartbeat import HeartbeatMonitor

log = logging.getLogger("cybernova.lifecycle.startup")

# Hold references to components that need explicit shutdown
_cleanup_registry: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Phase 1 — Core Infrastructure
# ---------------------------------------------------------------------------


async def startup_database(settings: "Settings", heartbeat: "HeartbeatMonitor") -> None:
    """Initialize database connection and validate configuration."""
    from cybernova.database.postgres.session import init_db

    try:
        await init_db()
        heartbeat.mark_healthy("database")
        log.info("Database initialized")
    except Exception as e:
        log.critical("DATABASE INITIALIZATION FAILED: %s — starting in degraded mode", e)
        log.critical("Check: 1) postgres reachable? 2) DATABASE_URL correct? 3) POSTGRES_PASSWORD matches?")

    validation_issues = settings.validate()
    if validation_issues:
        for issue in validation_issues:
            log.warning("CONFIG ISSUE: %s", issue)
    else:
        log.info("Configuration validated successfully")


async def startup_redis(settings: "Settings", heartbeat: "HeartbeatMonitor") -> Any:
    """Initialize Redis connection and optional stream infrastructure."""
    from cybernova.database.redis import get_redis

    redis = await get_redis()
    if not redis:
        log.warning("Redis unavailable -- Running with in-memory fallback")
        return None

    log.info("Redis connected -- Real-time features enabled")
    heartbeat.mark_healthy("redis")

    if not settings.disable_streams:
        await _start_stream_groups(redis, settings, heartbeat)
        await _start_reliability_engine(redis, heartbeat)

    await _start_rule_hotreloader(heartbeat)
    await _start_redis_memory_monitor(redis, heartbeat)
    return redis


async def _start_stream_groups(redis: Any, settings: "Settings", heartbeat: "HeartbeatMonitor") -> None:
    """Create Redis stream consumer groups."""
    from cybernova.streaming.streams import CONSUMER_GROUPS

    try:
        for stream, group in CONSUMER_GROUPS.items():
            try:
                await redis.xgroup_create(stream, group, id="0", mkstream=True)
            except Exception as e:
                log.warning("Could not create stream group: %s", e)
        heartbeat.mark_healthy("stream_consumer_groups")
        log.info("Redis Streams consumer groups initialized")
    except Exception as e:
        log.warning("Could not initialize stream groups: %s", e)


async def _start_reliability_engine(redis: Any, heartbeat: "HeartbeatMonitor") -> None:
    """Start stream reliability engine."""
    from cybernova.streaming.reliability import StreamReliabilityEngine

    try:
        engine = StreamReliabilityEngine(redis)
        await engine.start()
        _cleanup_registry["reliability_engine"] = engine
        heartbeat.mark_healthy("reliability_engine")
        log.info("Stream reliability engine started")
    except Exception as e:
        log.warning("Stream reliability engine start error: %s", e)


async def _start_rule_hotreloader(heartbeat: "HeartbeatMonitor") -> None:
    """Start hot-reloader for detection rules."""
    from cybernova.rules.hotreload import rules_hotreloader

    try:
        await rules_hotreloader.start()
        _cleanup_registry["rules_hotreloader"] = rules_hotreloader
        heartbeat.mark_healthy("rule_hotreloader")
        log.info("Rule hot-reloader started")
    except Exception as e:
        log.warning("Rule hot-reloader start error: %s", e)


async def _start_redis_memory_monitor(redis: Any, heartbeat: "HeartbeatMonitor") -> None:
    """Start Redis memory usage monitor."""
    from cybernova.monitoring.redis_memory import RedisMemoryMonitor

    try:
        redis_memory_monitor = RedisMemoryMonitor(redis)
        await redis_memory_monitor.start()
        heartbeat.mark_healthy("redis_memory_monitor")
        log.info("Redis memory monitor started")
    except Exception as e:
        log.warning("Redis memory monitor start error: %s", e)


# ---------------------------------------------------------------------------
# Phase 2 — High Availability
# ---------------------------------------------------------------------------


async def startup_ha(heartbeat: "HeartbeatMonitor") -> Any:
    """Initialize HA leader election and leadership controller."""
    leader_election = None
    try:
        from cybernova.ha.leader import leader_election as _le
        await _le.start()
        heartbeat.mark_healthy("ha_leader_election")
        log.info("HA leader election started (leader: %s)", _le.is_leader)
        leader_election = _le
    except Exception as e:
        log.warning("HA leader election start error: %s", e)

    try:
        from cybernova.ha.leadership import leadership_controller
        await leadership_controller.start()
        log.info("Leadership controller registered")
    except Exception as e:
        log.warning("Leadership controller start error: %s", e)

    return leader_election


def resolve_is_leader(leader_election: Any) -> bool:
    """Determine if this replica is the active leader."""
    if leader_election is None:
        return False
    return leader_election.is_leader or getattr(leader_election, "_local_mode", False)


# ---------------------------------------------------------------------------
# Phase 3 — Pipeline
# ---------------------------------------------------------------------------


async def startup_pipeline(
    settings: "Settings",
    is_leader: bool,
    heartbeat: "HeartbeatMonitor",
) -> None:
    """Start the unified event processing pipeline (leader only)."""
    if not is_leader:
        log.info("Pipeline deferred — waiting for leadership promotion")
        return
    if settings.environment == "test":
        log.info("Pipeline disabled in test mode")
        return

    from cybernova.pipeline.unified_pipeline import unified_pipeline

    try:
        await unified_pipeline.initialize()
        await unified_pipeline.start()
        log.info("UNIFIED PIPELINE STARTED (this replica is leader)")
        heartbeat.mark_healthy("unified_pipeline")
        log.info("  -> Events: Ingestion -> Normalize -> Enrich")
        log.info("  -> Detection: Static + Stateful + DSL rule evaluation")
        log.info("  -> SOAR: Built-in response actions (block/isolate/disable)")
        log.info("  -> Pipeline stages communicate via event bus")
    except Exception as e:
        log.error("Failed to start unified pipeline: %s", e)


# ---------------------------------------------------------------------------
# Phase 4 — Integrations
# ---------------------------------------------------------------------------


async def startup_integrations(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Initialize third-party integrations (leader only)."""
    if not is_leader:
        log.info("Integrations deferred — leader only")
        return

    from cybernova.integrations.registry import integration_registry

    try:
        count = await integration_registry.initialize_all()
        heartbeat.mark_healthy("integrations")
        log.info("INTEGRATIONS INITIALIZED: %d connectors registered", count)
        for c in integration_registry.list_all():
            log.info("  -> %s v%s (%s)", c["name"], c["version"], c["type"])
    except Exception as e:
        log.warning("Integration initialization error: %s", e)

    log.info("SOAR: Built-in actions + external webhook dispatch enabled")


# ---------------------------------------------------------------------------
# Phase 5 — Ingestion Sources
# ---------------------------------------------------------------------------


async def startup_syslog(
    settings: "Settings",
    is_leader: bool,
    unified_pipeline: Any,
    heartbeat: "HeartbeatMonitor",
) -> None:
    """Start Syslog receiver (leader only)."""
    if not is_leader or not getattr(settings, "syslog_enabled", False):
        return

    from cybernova.ingestion.syslog_receiver import syslog_receiver

    try:
        syslog_receiver.on_event = lambda msg: unified_pipeline.ingest(
            raw_data=msg, tenant_id="default", source="syslog", source_type="syslog",
        )
        await syslog_receiver.start()
        heartbeat.mark_healthy("syslog_receiver")
        log.info("Syslog receiver started (-> unified pipeline)")
    except Exception as e:
        log.warning("Syslog receiver failed to start: %s", e)


async def startup_file_watcher(
    settings: "Settings",
    is_leader: bool,
    unified_pipeline: Any,
    heartbeat: "HeartbeatMonitor",
) -> None:
    """Start log file watcher (leader only)."""
    log_watch_paths = getattr(settings, "log_watch_paths", [])
    if not is_leader or not log_watch_paths or settings.environment == "test":
        return

    from cybernova.ingestion.file_watcher import file_watcher

    try:
        async def _file_watcher_handler(events, source="log_file", source_type="log", tenant_id="default"):
            for event in events:
                await unified_pipeline.ingest(event, tenant_id, source, source_type)

        file_watcher.on_events = _file_watcher_handler
        for path_config in log_watch_paths:
            if isinstance(path_config, dict):
                file_watcher.add_file(
                    path=path_config.get("path", ""),
                    source=path_config.get("source", "log_file"),
                    source_type=path_config.get("source_type", "log"),
                )
            else:
                file_watcher.add_file(path=str(path_config))
        await file_watcher.start()
        heartbeat.mark_healthy("file_watcher")
        log.info("Log file watcher started: %d files (-> unified pipeline)", len(log_watch_paths))
    except Exception as e:
        log.warning("Log file watcher failed to start: %s", e)


# ---------------------------------------------------------------------------
# Phase 6 — WebSocket & Dashboard
# ---------------------------------------------------------------------------


async def startup_ws_dashboard(heartbeat: "HeartbeatMonitor") -> None:
    """Initialize WebSocket handler and dashboard push worker."""
    from cybernova.api.websocket import ws_handler

    await ws_handler.initialize()
    heartbeat.mark_healthy("websocket_handler")
    log.info("WebSocket handler initialized")

    try:
        from cybernova.dashboard.websocket_worker import dashboard_push_worker
        asyncio.create_task(dashboard_push_worker.start())
        heartbeat.mark_healthy("dashboard_push_worker")
        log.info("Dashboard push worker started (interval: 10s)")
    except Exception as e:
        log.warning("Dashboard push worker start error: %s", e)


# ---------------------------------------------------------------------------
# Phase 7 — Machine Learning
# ---------------------------------------------------------------------------


async def startup_ml_training(
    is_leader: bool,
    heartbeat: "HeartbeatMonitor",
) -> list[asyncio.Task]:
    """Start ML training pipeline, baseline computation, drift detection, and scheduler."""
    tasks: list[asyncio.Task] = []
    if not is_leader:
        return tasks

    # Training pipeline (every 5 min)
    task = await _start_periodic_task(
        "training_pipeline", "ML training pipeline",
        _run_training_cycle, interval=300, heartbeat=heartbeat,
    )
    if task:
        tasks.append(task)

    # Baseline computer (every 6h)
    task = await _start_periodic_task(
        "baseline_computer", "ML baseline computer",
        _run_baseline_cycle, interval=21600, heartbeat=heartbeat,
    )
    if task:
        tasks.append(task)

    # Drift detector (every 15 min)
    task = await _start_periodic_task(
        "drift_detector", "ML drift detector",
        _run_drift_cycle, interval=900, heartbeat=heartbeat,
    )
    if task:
        tasks.append(task)

    # Training scheduler (every 24h)
    task = await _start_periodic_task(
        "training_scheduler", "ML model training scheduler",
        _run_scheduler_cycle, interval=86400, heartbeat=heartbeat,
    )
    if task:
        tasks.append(task)

    return tasks


async def startup_ml_model(is_leader: bool, redis: Any, heartbeat: "HeartbeatMonitor") -> None:
    """Load trained ML model into memory."""
    if not is_leader:
        return
    try:
        from cybernova.ml.inference import refresh_active_model
        loaded = await refresh_active_model(redis=redis)
        if loaded:
            heartbeat.mark_healthy("ml_model_loaded")
            log.info("Active ML model loaded for anomaly detection")
        else:
            log.info("No trained ML model available yet — inference will use fallback")
    except Exception as e:
        log.warning("ML model load error (non-fatal): %s", e)


async def _run_training_cycle() -> None:
    from cybernova.ml.training_pipeline import training_pipeline
    from cybernova.database.postgres.session import get_db
    async for db in get_db():
        await training_pipeline.run_once(db)
        break


async def _run_baseline_cycle() -> None:
    from cybernova.ml.baseline import baseline_computer
    from cybernova.database.postgres.session import get_db
    async for db in get_db():
        await baseline_computer.compute_all(db)
        break


async def _run_drift_cycle() -> None:
    from cybernova.ml.drift import drift_detector
    from cybernova.database.postgres.session import get_db
    async for db in get_db():
        detected = await drift_detector.check_all(db)
        if detected:
            log.info("Drift detected for %d entities", len(detected))
        break


async def _run_scheduler_cycle() -> None:
    from cybernova.ml.scheduler import training_scheduler
    from cybernova.database.postgres.session import get_db
    from cybernova.database.redis import get_redis
    async for db in get_db():
        redis = await get_redis()
        await training_scheduler.train_once(db, redis=redis)
        break


async def _start_periodic_task(
    name: str,
    label: str,
    coro_factory: Callable,
    interval: int,
    heartbeat: "HeartbeatMonitor",
) -> asyncio.Task | None:
    """Create a background loop task with heartbeat registration."""
    try:
        async def _loop():
            while True:
                try:
                    await coro_factory()
                except Exception as exc:
                    log.warning("%s cycle error: %s", name, exc)
                await asyncio.sleep(interval)

        task = asyncio.create_task(_loop())
        heartbeat.mark_healthy(name)
        log.info("%s started (interval: %ss)", label, interval)
        return task
    except Exception as e:
        log.warning("%s start error: %s", name, e)
        heartbeat.mark_unhealthy(name, str(e))
        return None


# ---------------------------------------------------------------------------
# Phase 8 — Agent & Threat Intelligence
# ---------------------------------------------------------------------------


async def startup_agent_manager(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start agent telemetry manager (leader only)."""
    if not is_leader:
        return
    try:
        from cybernova.ingestion.agent.manager import agent_manager
        await agent_manager.start()
        heartbeat.mark_healthy("agent_manager")
        log.info("Agent telemetry manager started")
    except Exception as e:
        log.warning("Agent manager start error: %s", e)


async def startup_threat_feeds(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start threat intel feed scheduler (leader only)."""
    if not is_leader:
        return
    try:
        from cybernova.network.feeds.scheduler import feed_scheduler
        await feed_scheduler.start(interval=3600)
        heartbeat.mark_healthy("feed_scheduler")
        log.info("Threat intel feed scheduler started (interval: 3600s)")
    except Exception as e:
        log.warning("Feed scheduler start error: %s", e)


# ---------------------------------------------------------------------------
# Phase 9 — Data Management
# ---------------------------------------------------------------------------


async def startup_retention(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start retention manager (leader only)."""
    if not is_leader:
        return
    try:
        from cybernova.storage.retention import retention_manager
        await retention_manager.start(interval=86400)
        heartbeat.mark_healthy("retention_manager")
        log.info("Retention manager started (interval: 86400s)")
    except Exception as e:
        log.warning("Retention manager start error: %s", e)


async def startup_device_processor(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start device event processor (leader only)."""
    if not is_leader:
        return
    from cybernova.pipeline.device_processor import device_event_processor

    try:
        await device_event_processor.start()
        heartbeat.mark_healthy("device_event_processor")
        log.info("Device event processor started")
    except Exception as e:
        log.warning("Device processor failed to start: %s", e)


async def startup_dlq_worker(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start dead-letter queue processing worker (leader only)."""
    if not is_leader:
        return
    try:
        from cybernova.pipeline.dead_letter_worker import dead_letter_worker
        asyncio.create_task(dead_letter_worker.start())
        heartbeat.mark_healthy("dlq_worker")
        log.info("DLQ processing worker started (interval: 30s)")
    except Exception as e:
        log.warning("DLQ worker start error: %s", e)


# ---------------------------------------------------------------------------
# Phase 10 — Seeding
# ---------------------------------------------------------------------------


async def startup_seeding(is_leader: bool) -> None:
    """Seed default playbooks, suppression rules, and demo data (leader only)."""
    if not is_leader:
        return

    try:
        from cybernova.response.automation.engine import seed_default_playbooks
        seed_default_playbooks()
        log.info("Default playbooks seeded")
    except Exception as e:
        log.warning("Failed to seed default playbooks: %s", e)

    try:
        from cybernova.suppression.engine import seed_default_suppression_rules
        await seed_default_suppression_rules()
        log.info("Default suppression rules seeded")
    except Exception as e:
        log.warning("Failed to seed suppression rules: %s", e)

    # Auto-seed demo data on first startup so the dashboard isn't blank
    await _auto_seed_demo_data()


# ---------------------------------------------------------------------------
# Phase 11 — Background Services
# ---------------------------------------------------------------------------


async def startup_ha_health_monitor(heartbeat: "HeartbeatMonitor") -> None:
    """Start HA health monitor."""
    try:
        from cybernova.ha.monitor import health_monitor
        await health_monitor.start()
        heartbeat.mark_healthy("ha_health_monitor")
        log.info("HA health monitor started")
    except Exception as e:
        log.warning("HA health monitor start error: %s", e)


async def startup_backup(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start backup manager."""
    try:
        from cybernova.backup.manager import backup_manager
        await backup_manager.start(interval=86400)
        heartbeat.mark_healthy("backup_manager")
        log.info("Backup manager started (interval: 86400s)")
    except Exception as e:
        log.warning("Backup manager start error: %s", e)


async def _auto_seed_demo_data() -> None:
    """Auto-seed demo alerts and incidents on first startup so dashboard isn't blank."""
    try:
        from cybernova.database.postgres.session import async_session_factory
        from cybernova.database.postgres.models import Alert, Device
        from sqlalchemy import select, func
        from cybernova.core.utils.helpers import new_id, utcnow
        from datetime import timedelta
        import random  # nosec - demo seeding

        async with async_session_factory() as db:
            # Check if alerts already exist — skip if so
            count_result = await db.execute(select(func.count(Alert.id)))
            if (count_result.scalar() or 0) > 0:
                log.info("Demo data already exists — skipping auto-seed")
                return

            # Get the default tenant
            from cybernova.database.postgres.models import Tenant
            tenant_result = await db.execute(select(Tenant).limit(1))
            tenant = tenant_result.scalars().first()
            if not tenant:
                log.info("No tenant found — skipping demo data seed")
                return

            tenant_id = tenant.id

            # Seed realistic demo alerts
            sample_alerts = [
                {"rule": "failed_login_brute_force", "severity": "high", "desc": "Multiple failed login attempts from external IP 203.0.113.42 — possible brute force", "ip": "203.0.113.42", "host": "DC-PRIMARY"},
                {"rule": "malicious_process_detected", "severity": "critical", "desc": "Suspicious process mimikatz.exe detected on domain controller — credential dumping attempt", "ip": "10.0.0.5", "host": "DC-PRIMARY"},
                {"rule": "c2_beacon_detected", "severity": "high", "desc": "Outbound connection to known C2 server 45.33.32.156:443 detected on port 8443", "ip": "45.33.32.156", "host": "WS-FINANCE03"},
                {"rule": "privilege_escalation", "severity": "critical", "desc": "Unauthorized privilege escalation: user jdoe gained SYSTEM-level access", "ip": "10.0.0.22", "host": "WS-DEV07"},
                {"rule": "data_exfiltration_suspected", "severity": "high", "desc": "Large data transfer (2.3GB) to external IP 203.0.113.50 detected", "ip": "203.0.113.50", "host": "WS-HR02"},
                {"rule": "encoded_powershell_execution", "severity": "critical", "desc": "Base64 encoded PowerShell command execution — potential malware download", "ip": "10.0.0.44", "host": "WS-SALES01"},
                {"rule": "anomalous_dns_query", "severity": "medium", "desc": "High-volume DNS queries to suspicious domain x7z9k.malware.xyz", "ip": "10.0.0.15", "host": "WS-MKT01"},
                {"rule": "unauthorized_rdp_access", "severity": "medium", "desc": "RDP connection from unknown external IP 198.51.100.23", "ip": "198.51.100.23", "host": "SRV-DB01"},
            ]

            created = 0
            for sample in sample_alerts:
                hours_ago = random.randint(1, 72)  # nosec - demo data
                alert = Alert(
                    id=new_id(),
                    tenant_id=tenant_id,
                    rule_name=sample["rule"],
                    severity=sample["severity"],
                    risk_score={"critical": 95, "high": 75, "medium": 50}.get(sample["severity"], 30),
                    description=sample["desc"],
                    status="new",  # 'new' matches dashboard_router.py active_threats query
                    source_ip=sample["ip"],
                    extra_data={"source_ip": sample["ip"], "hostname": sample["host"]},
                    created_at=utcnow() - timedelta(hours=hours_ago),
                )
                db.add(alert)
                created += 1

            # Seed demo devices so the dashboard 'My Device' / 'Connected Servers' panel isn't empty
            demo_devices = [
                {"hostname": "DC-PRIMARY", "ip": "10.0.0.5", "os": "Windows Server 2022", "status": "active"},
                {"hostname": "WS-FINANCE03", "ip": "10.0.0.33", "os": "Windows 11", "status": "active"},
                {"hostname": "WS-DEV07", "ip": "10.0.0.22", "os": "Windows 11", "status": "active"},
                {"hostname": "SRV-DB01", "ip": "10.0.0.10", "os": "Ubuntu 22.04", "status": "active"},
            ]
            device_count = 0
            for dev in demo_devices:
                device = Device(
                    id=new_id(),
                    tenant_id=tenant_id,
                    hostname=dev["hostname"],
                    ip_address=dev["ip"],
                    os_type=dev["os"],
                    is_active=True,
                    is_isolated=False,
                    last_heartbeat=utcnow() - timedelta(minutes=random.randint(1, 30)),  # nosec - demo
                )
                db.add(device)
                device_count += 1

            await db.commit()
            log.info("AUTO-SEEDED %d demo alerts + %d demo devices for tenant %s", created, device_count, tenant_id)

    except Exception as e:
        log.warning("Auto-seed demo data failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Companion shutdown helpers
# ---------------------------------------------------------------------------


async def shutdown_redis_components() -> None:
    """Stop Redis-backed components registered during startup.

    These are called during the shutdown phase before Redis closes.
    """
    if "reliability_engine" in _cleanup_registry:
        try:
            await _cleanup_registry["reliability_engine"].stop()
            log.info("Reliability engine stopped")
        except Exception as e:
            log.warning("Reliability engine stop error: %s", e)
    if "rules_hotreloader" in _cleanup_registry:
        try:
            await _cleanup_registry["rules_hotreloader"].stop()
            log.info("Rule hot-reloader stopped")
        except Exception as e:
            log.warning("Rule hot-reloader stop error: %s", e)


async def startup_marketplace() -> None:
    """Load marketplace registry."""
    try:
        from cybernova.marketplace.registry import marketplace_registry
        await marketplace_registry.load_all()
        log.info("Marketplace registry loaded")
    except Exception as e:
        log.warning("Marketplace registry load error: %s", e)


async def startup_genai() -> None:
    """Initialize GenAI SOC investigator."""
    try:
        from cybernova.genai.investigator import genai_investigator
        await genai_investigator.initialize()
        log.info("GenAI SOC investigator initialized")
    except Exception as e:
        log.warning("GenAI investigator init error: %s", e)


async def startup_cross_region(heartbeat: "HeartbeatMonitor") -> None:
    """Start cross-region replication if enabled."""
    try:
        from cybernova.multi_region.config import region_config
        if region_config.enabled:
            from cybernova.multi_region.replication import cross_region_replicator
            await cross_region_replicator.start()
            heartbeat.mark_healthy("cross_region_replicator")
            log.info("Cross-region replicator started")
    except Exception as e:
        log.warning("Cross-region replicator start error: %s", e)


async def startup_key_rotation(is_leader: bool, heartbeat: "HeartbeatMonitor") -> None:
    """Start API key rotation service (leader only)."""
    if not is_leader:
        return
    try:
        from cybernova.auth.services.key_rotation import key_rotation_service
        await key_rotation_service.start(interval=86400)
        heartbeat.mark_healthy("key_rotation")
        log.info("API key rotation service started (interval: 86400s)")
    except Exception as e:
        log.warning("Key rotation service start error: %s", e)


# ---------------------------------------------------------------------------
# Phase 12 — On-Call & Runbooks
# ---------------------------------------------------------------------------


async def startup_oncall(settings: "Settings") -> None:
    """Initialize on-call router with alert escalation."""
    try:
        from cybernova.alerting.oncall import oncall_router
        oncall_router._oncall_email = settings.oncall_email
        oncall_router.register()
        oncall_router.start_periodic_health_check()
        log.info("On-call router started (P1->PD/Opsgenie, P2->email)")
    except Exception as e:
        log.warning("On-call router start error: %s", e)


async def startup_runbooks() -> None:
    """Generate runbooks and ingest into RAG."""
    try:
        from cybernova.alerting.runbook_generator import generate_and_ingest
        from cybernova.ai.rag import rag_service
        asyncio.create_task(generate_and_ingest(rag_service))
        log.info("Runbook generation + RAG ingest task scheduled")
    except Exception as e:
        log.warning("Runbook generation/ingest error: %s", e)
