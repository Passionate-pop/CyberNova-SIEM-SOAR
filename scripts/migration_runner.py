#!/usr/bin/env python3
"""Run database migrations for CyberNova."""
import asyncio
import logging
import sys

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("migration_runner")


async def run_migrations():
    from cybernova.database.postgres.session import init_db, close_db
    from cybernova.database.postgres.models import Base
    from cybernova.database.postgres.session import engine

    log.info("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("Database migration complete")


if __name__ == "__main__":
    asyncio.run(run_migrations())
