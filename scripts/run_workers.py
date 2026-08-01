#!/usr/bin/env python3
"""
CyberNova Worker Launcher
Entry point for the pipeline-worker container.
Initializes DB + Redis, then starts all background workers:
  - device_event_processor: Process host agent telemetry events
  - enrichment_worker: Enrich events with threat intel / geoip
  - detection_worker: Run detection rules on normalized events
  - correlation_worker: Correlate alerts across rules
  - soar_worker: Execute automated response actions
  - notification_worker: Send alert notifications

This script is the container CMD for the pipeline-worker service.
"""

import asyncio
import logging
import os
import signal
import sys

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("run_workers")


# ── Worker registry ───────────────────────────────────────────────────────
WORKERS = []


async def init_workers():
    """Import and collect all worker coroutines based on config."""
    from cybernova.database.postgres.session import init_db
    from cybernova.database.redis import get_redis

    log.info("Initializing database...")
    await init_db()
    log.info("Database initialized")

    log.info("Connecting to Redis...")
    redis = await get_redis()
    if redis is not None:
        log.info("Redis connected")
    else:
        log.warning("Redis NOT available -- some features degraded")

    # ── Device event processor ───────────────────────────────────────
    try:
        from cybernova.pipeline.device_processor import device_event_processor
        WORKERS.append(("device_event_processor", device_event_processor.start()))
        log.info("Registered: device_event_processor")
    except (ImportError, AttributeError) as exc:
        log.warning("device_event_processor skipped: %s", exc)

    # ── Enrichment worker ────────────────────────────────────────────
    try:
        from cybernova.streaming.pipeline_worker import PipelineWorker
        worker = PipelineWorker(redis, stage="enrichment")
        WORKERS.append(("enrichment_worker", worker.start()))
        log.info("Registered: enrichment_worker")
    except (ImportError, AttributeError) as exc:
        log.warning("enrichment_worker skipped: %s", exc)

    # ── Detection worker ─────────────────────────────────────────────
    try:
        from cybernova.streaming.pipeline_worker import PipelineWorker
        worker = PipelineWorker(redis, stage="detection")
        WORKERS.append(("detection_worker", worker.start()))
        log.info("Registered: detection_worker")
    except (ImportError, AttributeError) as exc:
        log.warning("detection_worker skipped: %s", exc)

    # ── Correlation worker ───────────────────────────────────────────
    try:
        from cybernova.streaming.pipeline_worker import PipelineWorker
        worker = PipelineWorker(redis, stage="correlation")
        WORKERS.append(("correlation_worker", worker.start()))
        log.info("Registered: correlation_worker")
    except (ImportError, AttributeError) as exc:
        log.warning("correlation_worker skipped: %s", exc)

    # ── SOAR worker ──────────────────────────────────────────────────
    try:
        from cybernova.streaming.soar_worker import SoarWorker
        worker = SoarWorker(redis)
        WORKERS.append(("soar_worker", worker.start()))
        log.info("Registered: soar_worker")
    except (ImportError, AttributeError) as exc:
        log.warning("soar_worker skipped: %s", exc)

    # ── Notification worker ──────────────────────────────────────────
    try:
        from cybernova.response.notifications.notification_service import notification_service
        # notification_service runs inline -- no dedicated worker needed
        log.info("Notification service: inline")
    except (ImportError, AttributeError) as exc:
        log.warning("Notification service skipped: %s", exc)

    log.info("Worker registration complete: %d workers loaded", len(WORKERS))


async def run_workers():
    """Run all registered workers concurrently."""
    if not WORKERS:
        log.warning("No workers registered -- nothing to do")
        log.info("Falling back to device_event_processor only")
        from cybernova.pipeline.device_processor import device_event_processor
        await device_event_processor.start()
        return

    tasks = []
    for name, coro in WORKERS:
        log.info("Starting worker: %s", name)
        tasks.append(asyncio.create_task(coro, name=name))

    log.info("All workers launched -- running %d tasks concurrently", len(tasks))

    # Wait for all workers to complete (they run until shutdown)
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    # If any worker raised, cancel the rest and re-raise
    for task in done:
        if task.exception() and not isinstance(task.exception(), asyncio.CancelledError):
            log.error("Worker %s failed: %s", task.get_name(), task.exception())
            for p in pending:
                p.cancel()
            raise task.exception()


async def main():
    log.info("=" * 60)
    log.info("CyberNova Worker Launcher")
    log.info("Environment: %s", os.getenv("ENVIRONMENT", "development"))
    log.info("=" * 60)

    await init_workers()
    await run_workers()


if __name__ == "__main__":
    log.info("Worker process starting...")

    # Handle graceful shutdown
    shutdown_event = asyncio.Event()

    def _handle_signal(sig):
        log.info("Received signal %s -- shutting down gracefully", sig)
        shutdown_event.set()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda s=sig: _handle_signal(s))
        except (NotImplementedError, ValueError):
            pass  # Windows doesn't support add_signal_handler

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        log.info("Shut down by user")
    except Exception as exc:
        log.exception("Fatal worker error: %s", exc)
        sys.exit(1)
    finally:
        try:
            loop.run_until_complete(shutdown_event.wait())
        except (KeyboardInterrupt, RuntimeError):
            pass
        finally:
            loop.close()
            log.info("Worker process shut down complete")
