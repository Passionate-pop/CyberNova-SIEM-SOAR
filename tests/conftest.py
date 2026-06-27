"""
pytest fixtures for CyberNova tests.
Uses in-memory SQLite for test isolation.
"""
from __future__ import annotations

import os
import asyncio
import warnings
from typing import AsyncGenerator, Generator
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
import pytest_asyncio


def pytest_configure(config):
    """Configure pytest — register custom markers and suppress deprecation warnings.
    
    - Registers @pytest.mark.slow for load/performance tests
    - Suppresses OpenTelemetry's deprecated SelectableGroups warning
    """
    config.addinivalue_line(
        "filterwarnings",
        "ignore::DeprecationWarning:opentelemetry.util._importlib_metadata",
    )
    # Register custom markers
    config.addinivalue_line("markers", "slow: mark test as a slow/load/performance test (deselect with '-m \"not slow\"')")
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
os.environ["REDIS_HOST"] = "localhost"
os.environ["REDIS_PORT"] = "6379"
# Prevent long timeouts when Redis is unavailable — fail fast
os.environ["REDIS_URL_OVERRIDE"] = "redis://localhost:1/0"
os.environ["DISABLE_STREAMS"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_PASSWORD"] = ""


# ── In-memory Redis mock for tests ─────────────────────────────────────────
# Both async (auth lockout) and sync (detection rules) code paths try to
# connect to Redis at import time or on first call.  When no Redis is
# running the connection attempt blocks, causing test timeouts.
#
# The codebase already has in-memory fallback paths — we just need to
# ensure Redis is reported as unavailable so those paths activate.
#
# CRITICAL: rule_engine is a module-level singleton whose stateful rules
# (BruteForceRule, PortScanRule, etc.) call _get_sync_redis() in __init__.
# If the module was already imported before this fixture runs (e.g. during
# test collection), those rules hold a real Redis client reference.  We
# therefore also null out the _redis attribute on every stateful rule in
# the singleton so the in-memory fallback is always used.
# ───────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _patch_redis_unavailable():
    """Patch all Redis connection points to return None.

    This forces every component to use its built-in in-memory fallback:
      - auth lockout: _failed_attempts_local dict
      - brute force / port scan rules: _fallback dict
      - rate limiter: local dict

    Each patch is independent — a failure in one won't disable the others.
    """
    patches = []

    def _safe_patch(target, **kwargs):
        """Try to apply a patch; silently skip if the target doesn't exist."""
        try:
            p = patch(target, **kwargs)
            p.start()
            patches.append(p)
        except (AttributeError, ModuleNotFoundError):
            pass

    # 1. Core Redis connection — affects get_redis() globally
    _safe_patch(
        "cybernova.database.redis.get_redis",
        new_callable=AsyncMock,
        return_value=None,
    )
    # 2. Auth lockout: _get_redis_lockout() calls get_redis() locally
    #    Patching _get_redis_lockout itself avoids import-order issues
    _safe_patch(
        "cybernova.auth.services.auth_service._get_redis_lockout",
        new_callable=AsyncMock,
        return_value=None,
    )
    # 3. Sync Redis for detection rules (BruteForceRule, PortScanRule, etc.)
    _safe_patch(
        "cybernova.detection.rules_engine.rules._get_sync_redis",
        return_value=None,
    )
    # 4. Rate limiter Redis
    _safe_patch(
        "cybernova.detection.rules_engine.rate_limiter.get_redis",
        new_callable=AsyncMock,
        return_value=None,
    )
    # 5. Session manager Redis
    _safe_patch(
        "cybernova.auth.services.session_manager.get_redis",
        new_callable=AsyncMock,
        return_value=None,
    )
    # 6. Anomaly baseline sync Redis
    _safe_patch(
        "cybernova.detection.anomaly.baseline._get_sync_redis",
        return_value=None,
    )

    # 7. Null out _redis on all stateful rules in the module-level singleton.
    #    This is necessary because rule_engine is created at import time and
    #    the rules may already hold a Redis client reference before our
    #    patches are applied.
    try:
        from cybernova.detection.rules_engine.rules import rule_engine
        for stateful_rule in rule_engine.stateful_rules:
            if hasattr(stateful_rule, "_redis"):
                stateful_rule._redis = None
    except (ImportError, AttributeError):
        pass

    # 8. Null out _redis on the anomaly baseline module-level singleton.
    #    EventBaseline.__init__() calls _get_sync_redis() at module import
    #    time, so even with the function patched above, the singleton already
    #    holds a real Redis client reference.
    try:
        from cybernova.detection.anomaly.baseline import event_baseline
        if hasattr(event_baseline, "_redis"):
            event_baseline._redis = None
    except (ImportError, AttributeError):
        pass

    yield

    for p in patches:
        p.stop()


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///./test.db", echo=False)
    async with engine.begin() as conn:
        from cybernova.database.postgres.models import Base
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession)
    async with session_factory() as session:
        yield session
        await session.rollback()
