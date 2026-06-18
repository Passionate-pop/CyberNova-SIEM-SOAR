"""CyberNova — Alembic Migration Environment (Async)

Uses async SQLAlchemy engine for PostgreSQL, falls back to sync for SQLite.
"""
from __future__ import annotations
import asyncio
import logging
from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import create_engine

from cybernova.config.settings import get_settings
from cybernova.database.postgres.session import Base

config = context.config
settings = get_settings()
log = logging.getLogger("alembic.env")

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — generates SQL script without connecting."""
    url = settings.effective_database_url
    context.configure(
        url=url.replace("+psycopg", "").replace("+aiosqlite", ""),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using async engine (PostgreSQL)."""
    url = settings.effective_database_url
    if url.startswith("sqlite"):
        # SQLite: use sync engine (async DDL unreliable)
        sync_url = url.replace("sqlite+aiosqlite", "sqlite")
        sync_engine = create_engine(sync_url)
        with sync_engine.begin() as conn:
            do_run_migrations(conn)
    else:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(do_run_migrations)
        await engine.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
