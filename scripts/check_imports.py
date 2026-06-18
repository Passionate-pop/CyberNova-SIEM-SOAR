"""Check all CyberNova backend imports for broken modules."""
import sys
import traceback

sys.path.insert(0, ".")

# All routers imported by main.py
ROUTERS = [
    ("cybernova.auth.routes.auth_router", "router"),
    ("cybernova.devices.router", "router"),
    ("cybernova.devices.commands", "router"),
    ("cybernova.devices.commands", "agent_router"),
    ("cybernova.devices.blocklist", "router"),
    ("cybernova.devices.blocklist", "agent_router"),
    ("cybernova.pipeline.device_processor", "device_event_processor"),
    ("cybernova.ingestion.routes.ingest_router", "router"),
    ("cybernova.detection.routes.detection_router", "router"),
    ("cybernova.response.routes.response_router", "router"),
    ("cybernova.datalake.router", "router"),
    ("cybernova.api.routes", "router"),
    ("cybernova.api.routes.dashboard_router", "router"),
    ("cybernova.pipeline.router", "router"),
    ("cybernova.audit.routes", "router"),
    ("cybernova.api.organizations", "router"),
    ("cybernova.api.routes.admin_devices", "router"),
    ("cybernova.api.routes.policy_admin", "router"),
    ("cybernova.api.routes.dlq", "router"),
    ("cybernova.api.routes.metrics", "router"),
    ("cybernova.analytics.routes", "router"),
    ("cybernova.api.routes.setup", "router"),
    ("cybernova.response.routes.soar_actions", "router"),
    ("cybernova.response.automation.router", "router"),
    ("cybernova.api.routes.playbook_routes", "router"),
    ("cybernova.ingestion.routes.agent_ingest", "router"),
    ("cybernova.api.routes.demo", "router"),
    ("cybernova.api.routes.notifications_router", "router"),
    ("cybernova.api.routes.agent_download", "router"),
    ("cybernova.api.routes.agent_auth", "router"),
    ("cybernova.api.routes.agent_heartbeat", "router"),
    ("cybernova.api.routes.agent_commands", "router"),
    ("cybernova.api.routes.agent_update", "router"),
    ("cybernova.detection.routes.noise_routes", "router"),
    ("cybernova.ingestion.agent_receiver", "router"),
    ("cybernova.network.feeds.router", "router"),
    ("cybernova.detection.anomaly.router", "router"),
    ("cybernova.detection.isolation.router", "router"),
    ("cybernova.storage.router", "router"),
    ("cybernova.testing.router", "router"),
    ("cybernova.auth.routes.user_admin_router", "router"),
    ("cybernova.search.router", "router"),
    ("cybernova.compliance.router", "router"),
    ("cybernova.api.routes.compliance_routes", "router"),
    ("cybernova.ha.router", "router"),
    ("cybernova.performance.router", "router"),
    ("cybernova.suppression.router", "router"),
    ("cybernova.backup.router", "router"),
    ("cybernova.multi_region.router", "router"),
    ("cybernova.marketplace.router", "router"),
    ("cybernova.genai.router", "router"),
    ("cybernova.worm.router", "router"),
    ("cybernova.cloud.router", "router"),
    ("cybernova.cspm.router", "router"),
    ("cybernova.residency.router", "router"),
    ("cybernova.abac.router", "router"),
    ("cybernova.ml.router", "router"),
    ("cybernova.ueba.router", "router"),
    ("cybernova.detection.ransomware.router", "router"),
    ("cybernova.ai.rag.router", "router"),
    ("cybernova.api.routes.tenant_deletion", "router"),
    ("cybernova.api.routes.tenant_export", "router"),
    ("cybernova.api.routes.security_overview", "router"),
]

# Core infrastructure imports
CORE = [
    ("cybernova.config.settings", "get_settings"),
    ("cybernova.config.logging", "setup_json_logging"),
    ("cybernova.database.postgres.session", "init_db"),
    ("cybernova.database.postgres.session", "get_db"),
    ("cybernova.database.redis", "get_redis"),
    ("cybernova.monitoring.heartbeat", "heartbeat_monitor"),
    ("cybernova.monitoring.health", "health_registry"),
    ("cybernova.monitoring.tracing", "setup_tracing"),
    ("cybernova.monitoring.metrics", "metrics"),
    ("cybernova.pipeline.bus", "create_bus"),
    ("cybernova.pipeline.unified_pipeline", "unified_pipeline"),
    ("cybernova.api.websocket", "ws_handler"),
    ("cybernova.api.middleware.stack", "register_middleware"),
    ("cybernova.lifecycle.startup", "startup_database"),
    ("cybernova.lifecycle.shutdown", "GracefulShutdown"),
    ("cybernova.ingestion.syslog_receiver", "syslog_receiver"),
    ("cybernova.ingestion.file_watcher", "file_watcher"),
]

ok = 0
failed = 0
skipped = 0

print("=" * 70)
print("CyberNova Import Health Check")
print("=" * 70)

print("\n--- Core Infrastructure ---")
for mod_path, attr in CORE:
    try:
        mod = __import__(mod_path, fromlist=[attr])
        getattr(mod, attr)
        print(f"  OK  {mod_path}.{attr}")
        ok += 1
    except Exception as e:
        print(f"  FAIL {mod_path}.{attr}: {e}")
        failed += 1

print("\n--- Router Imports (main.py safe_import targets) ---")
for mod_path, attr in ROUTERS:
    try:
        mod = __import__(mod_path, fromlist=[attr])
        getattr(mod, attr)
        print(f"  OK  {mod_path}.{attr}")
        ok += 1
    except ImportError as e:
        print(f"  SKIP {mod_path}.{attr}: {e}")
        skipped += 1
    except Exception as e:
        print(f"  FAIL {mod_path}.{attr}: {e}")
        failed += 1

print("\n" + "=" * 70)
print(f"Results: {ok} OK | {failed} FAILED | {skipped} SKIPPED (import error)")
print("=" * 70)

if failed > 0:
    sys.exit(1)
