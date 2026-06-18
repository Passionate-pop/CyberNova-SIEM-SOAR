#!/bin/bash
set -e

# ── Utility function: safe run with error tolerance ──
safe_run() {
    local label="$1"
    shift
    echo "[setup] $label..."
    "$@" 2>&1 | while IFS= read -r line; do echo " $line"; done || echo "[warn] $label failed — continuing"
}

echo "============================================"
echo " CyberNova Comprehensive Entrypoint"
echo " Environment: ${ENVIRONMENT:-development}"
echo "============================================"

# ── Docker Secrets Resolution ─────────────────────────────────────
# If a *_FILE env var points to a secret, read it into the base env var.
# This mirrors the Python settings.py _load_file_secrets() logic.
resolve_secret() {
    local base_var="$1"
    local file_var="${base_var}_FILE"
    local file_path="${!file_var}"
    if [ -n "$file_path" ] && [ -f "$file_path" ]; then
        export "$base_var"="$(tr -d '\r\n' < "$file_path")"
    fi
}

resolve_secret "JWT_SECRET"
resolve_secret "POSTGRES_PASSWORD"
resolve_secret "REDIS_PASSWORD"
resolve_secret "SMTP_PASSWORD"
resolve_secret "ADMIN_PASSWORD"
resolve_secret "AGENT_PASSWORD"
resolve_secret "SECRET_KEY"

# Export secrets so Python Pydantic settings picks them up at import time
# Settings is cached via @lru_cache — env vars MUST be set BEFORE any Python import
[ -n "$JWT_SECRET" ] && export JWT_SECRET
[ -n "$POSTGRES_PASSWORD" ] && export POSTGRES_PASSWORD
[ -n "$REDIS_PASSWORD" ] && export REDIS_PASSWORD
[ -n "$SMTP_PASSWORD" ] && export SMTP_PASSWORD
[ -n "$ADMIN_PASSWORD" ] && export ADMIN_PASSWORD
[ -n "$AGENT_PASSWORD" ] && export AGENT_PASSWORD
[ -n "$SECRET_KEY" ] && export SECRET_KEY

echo "[setup] Secrets resolved (REDIS_PASSWORD=${REDIS_PASSWORD:+***SET***})"

# ── Track background PIDs for graceful shutdown ────────────────────
_BG_PIDS=()
_cleanup() {
    echo ""
    echo "[shutdown] Stopping background services..."
    for pid in "${_BG_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "[shutdown] Stopping PID $pid..."
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    echo "[shutdown] Background services stopped"
}
trap _cleanup EXIT TERM INT

# ── Ensure data directories exist ──────────────────────────────────
mkdir -p /app/data /data /data/rag_store /data/cold_storage /data/blocklist
chmod 755 /app/data /data

# ── Database Migration ───────────────────────────────────────────
# NOTE: init_db() and policy seeding are handled by main.py's lifespan handler.
# Do NOT add DB operations here.
echo "[setup] Database init deferred to main.py lifespan"

# ── Service Launcher ──────────────────────────────────────────────
# Only launch background services when running in default mode (no CMD override).
# When a CMD is provided (e.g. pipeline-worker), skip background services to avoid
# duplicates — the CMD is responsible for its own process tree.
if [ $# -eq 0 ] && [ "${RUN_ALL_SERVICES:-true}" = "true" ]; then
    echo "[config] RUN_ALL_SERVICES=true - enabling all optional services"
    export START_LOCAL_AGENT=${START_LOCAL_AGENT:-true}
    export START_WORKER_PROCESSOR=${START_WORKER_PROCESSOR:-true}
    export START_SYSLOG_LISTENER=${START_SYSLOG_LISTENER:-true}
    export START_FILE_WATCHER=${START_FILE_WATCHER:-true}
    export START_ALL_WORKERS=${START_ALL_WORKERS:-true}
fi

# Start Host Security Agent (endpoint monitoring) — if script exists
_start_bg() {
    local label="$1"
    shift
    echo "[service] Starting $label..."
    "$@" &
    local pid=$!
    _BG_PIDS+=("$pid")
    echo "[service] $label started (PID $pid)"
}

if [ "${START_LOCAL_AGENT:-true}" = "true" ] && [ -f /app/host_agent.py ]; then
    if [ -n "${AGENT_PASSWORD:-}" ]; then
        _start_bg "Host Security Agent" python /app/host_agent.py \
            --backend "${BACKEND_URL:-http://localhost:8000}" \
            --username "${AGENT_USERNAME:-admin}" \
            --password "${AGENT_PASSWORD}"
    else
        echo "[warn] AGENT_PASSWORD not set — host agent disabled"
    fi
fi

# Start Background Worker (processes events from Redis Streams)
if [ "${START_WORKER_PROCESSOR:-true}" = "true" ]; then
    _start_bg "Background Worker Processor" python -c "
import asyncio
from cybernova.pipeline.device_processor import device_event_processor
from cybernova.database.postgres.session import init_db
from cybernova.database.redis import get_redis
async def main():
    await init_db()
    redis = await get_redis()
    if redis:
        await device_event_processor.start()
        print('[worker] Device event processor started')
    else:
        print('[worker] Started without Redis (in-memory fallback)')
asyncio.run(main())
"
fi

# Start Syslog Listener (UDP/TCP)
if [ "${START_SYSLOG_LISTENER:-true}" = "true" ]; then
    _start_bg "Syslog Listener" python -c "
import asyncio
from cybernova.ingestion.syslog_receiver import syslog_receiver
from cybernova.pipeline.unified_pipeline import unified_pipeline

async def _syslog_handler(msg):
    await unified_pipeline.ingest(
        raw_data=msg, tenant_id='default', source='syslog', source_type='syslog'
    )

async def main():
    syslog_receiver.on_event = _syslog_handler
    await syslog_receiver.start()
    print('[syslog] Syslog listener started')
    await asyncio.Event().wait()
asyncio.run(main())
"
fi

# Start File Watcher (log file monitoring)
if [ "${START_FILE_WATCHER:-true}" = "true" ]; then
    _start_bg "File Watcher" python -c "
import asyncio
from cybernova.ingestion.file_watcher import file_watcher
from cybernova.pipeline.unified_pipeline import unified_pipeline

async def _file_watcher_handler(events, source='log_file', source_type='log', tenant_id='default'):
    for event in events:
        await unified_pipeline.ingest(event, tenant_id, source, source_type)

async def main():
    file_watcher.on_events = _file_watcher_handler
    await file_watcher.start()
    print('[filewatcher] File watcher started')
    await asyncio.Event().wait()
asyncio.run(main())
"
fi

# Start Kernel Module (CyberNova LSM — file execution interception)
if [ "${START_KERNEL_MODULE:-false}" = "true" ]; then
    echo "[service] Loading CyberNova LSM kernel module..."
    MODULE_PATH=$(find /lib/modules -name "cybernova_lsm.ko" 2>/dev/null | head -1)
    if [ -n "$MODULE_PATH" ]; then
        insmod "$MODULE_PATH" 2>/dev/null && \
            echo "[service] Kernel module loaded: cybernova_lsm.ko" || \
            echo "[service] Kernel module load skipped (not supported in this environment)"
    else
        echo "[service] Kernel module not found — skipping"
    fi
fi

# Start All Pipeline Workers (enrichment, correlation, AI, SOAR)
if [ "${START_ALL_WORKERS:-true}" = "true" ] && [ -f /app/scripts/run_workers.py ]; then
    _start_bg "Pipeline Workers" python /app/scripts/run_workers.py
fi

echo "============================================"
echo " All requested services started"
echo " Starting CyberNova API server..."
echo "============================================"

# ── Hand off to CMD or default uvicorn ───────────────────────────
# Always exec CMD first — the entrypoint's job is setup, not process management.
# This ensures pipeline-worker (command: [python3, run_workers.py]) actually runs.
if [ $# -gt 0 ]; then
    echo "[config] Executing CMD: $*"
    exec "$@"
fi

# No CMD provided — determine what to run
if [ "${START_API_SERVER:-true}" = "false" ]; then
    echo "[config] START_API_SERVER=false — API server disabled (worker mode)"
    # Keep container alive by tailing the worker logs
    exec tail -f /dev/null
fi

# Default: launch the API server
exec python3 -m uvicorn cybernova.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --timeout-keep-alive 30 \
    --no-server-header
