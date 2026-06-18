"""
CyberNova — Database Session Layer
Async SQLAlchemy engine supporting PostgreSQL (prod) and SQLite (dev).

Auto-fallback: If PostgreSQL is unreachable at startup, the system
automatically switches to a local SQLite database so the application
can run in degraded mode without crashing.

Connection pool sizing (PostgreSQL only):
  pool_size = auto-calculated from expected_eps x batch_size:
    - base = max(10, min(50, expected_eps / 1000 + batch_size / 50))
    - clamped to prevent PostgreSQL max_connections exhaustion
  max_overflow = pool_size // 2 (minimum 5)
  Total connections per worker = pool_size + max_overflow

Read replica support:
  When database_url_replica is configured, dashboard queries route to the
  read replica. Falls back to primary when replica is not configured.
"""
from __future__ import annotations

import logging
import math
from typing import AsyncGenerator, Any, Optional, Dict

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event, text

from pathlib import Path

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.database")

settings = get_settings()
effective_database_url = settings.effective_database_url
_is_sqlite = effective_database_url.startswith("sqlite")



def _sqlite_fallback_url() -> str:
    """Build a SQLite fallback URL in the project root."""
    db_path = Path(__file__).resolve().parent.parent.parent / "cybernova.db"
    return f"sqlite+aiosqlite:///{db_path}"


def compute_pool_size() -> int:
    """Calculate optimal pool_size from EPS and batch size."""
    if settings.db_pool_size > 0:
        return settings.db_pool_size
    eps = max(settings.db_expected_eps, 1000)
    batch = max(settings.db_batch_size, 1)
    raw = eps / 1000 + batch / 50
    return max(10, min(50, math.ceil(raw)))


def compute_max_overflow() -> int:
    if settings.db_max_overflow > 0:
        return settings.db_max_overflow
    return max(5, compute_pool_size() // 2)


def _build_engine_args(url: str) -> dict[str, Any]:
    """Build engine creation args based on whether the URL is PostgreSQL or SQLite."""
    args: dict[str, Any] = {"echo": settings.environment == "development"}
    if not url.startswith("sqlite"):
        pool_size = compute_pool_size()
        max_overflow = compute_max_overflow()
        args.update({
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_timeout": settings.db_pool_timeout,
            "pool_pre_ping": True,
            "pool_recycle": settings.db_pool_recycle,
            "pool_use_lifo": True,
            "connect_args": {
                "timeout": 10,
                "command_timeout": 30,
                "server_settings": {
                    "statement_timeout": "30000",
                    "idle_in_transaction_session_timeout": "30000",
                },
            },
        })
        log.info(
            "PostgreSQL pool: size=%d overflow=%d max_total=%d recycle=%ds "
            "driver=asyncpg eps=%d batch=%d",
            pool_size, max_overflow, pool_size + max_overflow,
            settings.db_pool_recycle,
            settings.db_expected_eps, settings.db_batch_size,
        )
    return args


# ── Engine Creation ──────────────────────────────────────────────────────────

engine_args = _build_engine_args(effective_database_url)
engine = create_async_engine(effective_database_url, **engine_args)


# ── Read Replica Engine ─────────────────────────────────────────────────────

replica_url = settings.effective_replica_database_url
replica_engine: Optional[Any] = None
_replica_configured = bool(replica_url)

if _replica_configured:
    replica_args: dict[str, Any] = _build_engine_args(replica_url)
    replica_engine = create_async_engine(replica_url, **replica_args)
    log.info("Read replica configured: %s", replica_url)
else:
    log.info("No read replica configured — all queries use primary database")


def _register_pool_monitor(eng) -> None:
    """Attach event listeners to track pool utilization."""
    if eng is None or str(eng.url).startswith("sqlite"):
        return

    @event.listens_for(eng.sync_engine, "checkout")
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        log.debug("Pool checkout: connections in use=%d, pool size=%d",
                   connection_record.info.get("in_use", 0),
                   connection_record.info.get("pool_size", 0))

    @event.listens_for(eng.sync_engine, "checkin")
    def receive_checkin(dbapi_connection, connection_record):
        log.debug("Pool checkin")

    @event.listens_for(eng.sync_engine, "connect")
    def receive_connect(dbapi_connection, connection_record):
        log.debug("New DB connection established (pool growth)")


if not _is_sqlite:
    _register_pool_monitor(engine)
    if _replica_configured and replica_engine:
        _register_pool_monitor(replica_engine)


# ── Session Factories ────────────────────────────────────────────────────────

async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False,
)

replica_session_factory: Optional[async_sessionmaker] = None
if replica_engine:
    replica_session_factory = async_sessionmaker(
        replica_engine, class_=AsyncSession, expire_on_commit=False,
    )


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    __abstract__ = True


# ── Primary Session (reads + writes) ────────────────────────────────────────


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields an async DB session (primary, read-write).

    Commits on exit if the session is still active. Routes that call
    db.commit() explicitly are safe because SQLAlchemy commit is
    idempotent when there are no pending changes.
    """
    async with async_session_factory() as session:
        try:
            yield session
            if session.is_active:
                await session.commit()
        except Exception:
            if session.is_active:
                await session.rollback()
            log.exception("Database session error, rolling back")
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Alias for get_db() — for use in services outside FastAPI routes."""
    async with async_session_factory() as session:
        try:
            yield session
            if session.is_active:
                await session.commit()
        except Exception:
            if session.is_active:
                await session.rollback()
            log.exception("Database session error, rolling back")
            raise


# ── Read Replica Session (read-only queries) ───────────────────────────────


def _get_read_session_factory():
    """Return the replica factory if configured, else fall back to primary."""
    return replica_session_factory or async_session_factory


async def get_db_readonly() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields an async DB session routed to read replica.

    Falls back to primary when no replica is configured.
    Uses a read-only transaction to prevent accidental writes.
    """
    factory = _get_read_session_factory()
    async with factory() as session:
        try:
            await session.execute(text("SET TRANSACTION READ ONLY"))
        except Exception as e:
            log.debug("SET TRANSACTION READ ONLY not supported by this backend: %s", e)
        try:
            yield session
        except Exception:
            await session.rollback()
            log.exception("Read-only session error, rolling back")
            raise
        finally:
            await session.close()


async def get_db_session_readonly() -> AsyncGenerator[AsyncSession, None]:
    """Non-route variant of get_db_readonly() for background services."""
    factory = _get_read_session_factory()
    async with factory() as session:
        try:
            await session.execute(text("SET TRANSACTION READ ONLY"))
        except Exception as e:
            log.debug("SET TRANSACTION READ ONLY not supported by this backend: %s", e)
        try:
            yield session
        except Exception:
            await session.rollback()
            log.exception("Read-only session error, rolling back")
            raise
        finally:
            await session.close()


# ── Health ────────────────────────────────────────────────────────────────────


async def get_replica_health() -> Dict[str, Any]:
    """Check read replica connectivity. Returns dict with status."""
    result = {"configured": _replica_configured, "healthy": False, "pool_stats": {}}
    engine_to_check = replica_engine or engine
    try:
        from sqlalchemy import text as sql_text
        async with _get_read_session_factory()() as session:
            await session.execute(sql_text("SELECT 1"))
            result["healthy"] = True
        if hasattr(engine_to_check, "pool"):
            pool = engine_to_check.pool
            result["pool_stats"] = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
            }
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Init / Close ─────────────────────────────────────────────────────────────


async def init_db() -> None:
    """Initialize database schema at startup.

    Strategy:
      1. Probe PostgreSQL connectivity (3s timeout).
      2. If unreachable → auto-fallback to local SQLite.
      3. SQLite: use create_all() from current model definitions.
      4. PostgreSQL: try Alembic first (60s timeout), then create_all.
    """
    global engine, async_session_factory, effective_database_url, _is_sqlite

    from cybernova.database.postgres import models  # noqa: F401

    # ── Step 1: Probe PostgreSQL if configured ───────────────────────────
    if not _is_sqlite:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine as _cae
            probe = _cae(effective_database_url, pool_pre_ping=True,
                         pool_size=1, max_overflow=0, pool_timeout=3,
                         connect_args={"timeout": 3})
            async with probe.connect() as conn:
                await conn.execute(text("SELECT 1"))
            await probe.dispose()
            log.info("PostgreSQL connectivity confirmed")
        except Exception as pg_err:
            await _swap_to_sqlite(pg_err)

    # ── Step 2: Create schema ───────────────────────────────────────────
    if _is_sqlite:
        # SQLite: always use create_all from current model definitions.
        sync_url = effective_database_url.replace("sqlite+aiosqlite", "sqlite")
        from sqlalchemy import create_engine
        sync_eng = create_engine(sync_url)
        with sync_eng.begin() as conn:
            Base.metadata.create_all(conn)
        sync_eng.dispose()
        log.info("SQLite schema created from current models (create_all)")
    else:
        # PostgreSQL: try Alembic first for proper migration handling
        try:
            await _run_alembic_upgrade()
            log.info("Database schema up to date (Alembic)")
        except Exception as e:
            log.warning(
                "Alembic sync migration skipped: %s — using async create_all. "
                "NOTE: Run 'alembic upgrade head' manually for schema migrations.",
                e,
            )
            try:
                async with engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
                log.info("Database tables created via asyncpg engine")
            except Exception as e2:
                await _swap_to_sqlite(e2)
                # Now create schema on SQLite
                sync_url = effective_database_url.replace("sqlite+aiosqlite", "sqlite")
                from sqlalchemy import create_engine as _se
                sync_eng = _se(sync_url)
                with sync_eng.begin() as conn:
                    Base.metadata.create_all(conn)
                sync_eng.dispose()
                log.info("SQLite schema created as final fallback")

    await create_default_admin()


async def _swap_to_sqlite(error: Exception) -> None:
    """Swap engine and session factory to SQLite fallback."""
    global engine, async_session_factory, replica_session_factory, effective_database_url, _is_sqlite

    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    _is_sqlite = True
    fallback_url = _sqlite_fallback_url()
    log.warning("AUTO-FALLBACK to SQLite: %s (error: %s)", fallback_url, error)
    log.warning("The system will run in degraded mode. Install and start PostgreSQL for production use.")

    await engine.dispose()
    engine = _cae(fallback_url, echo=settings.environment == "development")
    async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    effective_database_url = fallback_url

    if replica_engine:
        await replica_engine.dispose()
    replica_session_factory = None


async def _run_alembic_upgrade() -> None:
    """Run Alembic migrations programmatically at startup."""
    from alembic.config import Config
    from alembic import command
    import asyncio

    alembic_cfg = Config()
    script_location = str(Path(__file__).resolve().parent.parent.parent / "alembic")
    alembic_cfg.set_main_option("script_location", script_location)
    alembic_cfg.set_main_option("sqlalchemy.url", settings.sync_database_url)

    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, command.upgrade, alembic_cfg, "head"),
            timeout=60,
        )
    except asyncio.TimeoutError:
        log.warning("Alembic migration timed out after 60s — falling back to create_all")
        raise RuntimeError("Alembic timeout — will use create_all fallback")


async def create_default_admin() -> None:
    """Create default admin user if not exists."""
    from cybernova.auth.services.auth_service import auth_service
    from sqlalchemy import select
    from cybernova.database.postgres.models import User
    from cybernova.config.settings import get_settings

    settings = get_settings()
    admin_password = settings.admin_password
    if not admin_password or admin_password in ("admin", "CHANGE_ME_ADMIN_PASSWORD_STRONG_64_CHARS"):
        log.warning("[DB] ADMIN_PASSWORD not set or is default — skipping default admin creation")
        return

    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        existing = result.scalars().first()

        if not existing:
            try:
                await auth_service.register(
                    db, "admin", "admin@cybernova.local", admin_password,
                    tenant_name="Default", roles=["admin"],
                )
                await db.commit()
                log.info("Default admin user created from ADMIN_PASSWORD env var")
            except Exception as e:
                log.debug("Admin user creation skipped: %s", e)


async def close_db() -> None:
    """Dispose engine connections. Called at shutdown."""
    if engine is not None:
        await engine.dispose()
    if replica_engine is not None:
        await replica_engine.dispose()
    log.info("Database connections closed")
