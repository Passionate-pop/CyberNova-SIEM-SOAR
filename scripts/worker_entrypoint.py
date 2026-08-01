import asyncio
import logging
import os
import sys

from cybernova.pipeline.device_processor import device_event_processor
from cybernova.database.postgres.session import init_db
from cybernova.database.redis import get_redis

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("worker_entrypoint")


async def main():
    log.info("Initializing database...")
    await init_db()
    log.info("Worker DB initialized")

    log.info("Connecting to Redis...")
    redis = await get_redis()
    if redis is not None:
        log.info("Worker Redis connected")
    else:
        log.warning("Worker started WITHOUT Redis — some features may be degraded")

    log.info("Starting device_event_processor...")
    await device_event_processor.start()
    log.info("Worker started successfully — processing events")


if __name__ == "__main__":
    log.info("Worker entrypoint starting up...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Worker shut down by signal")
    except Exception as exc:
        log.exception("Worker crashed: %s", exc)
        sys.exit(1)
