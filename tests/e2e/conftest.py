"""e2e conftest: shared fixtures for E2E and integration tests.

Provides:
  - In-memory SQLite database with all tables created
  - Rate limiter disabled (both slowapi and PlanRateLimitMiddleware)
  - Async HTTP test client against the FastAPI app
"""
from __future__ import annotations

import os
from typing import AsyncGenerator
from unittest.mock import patch

import httpx
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from cybernova.database.postgres.models import Base
from cybernova.main import app

# Force in-memory DB for e2e tests
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Async HTTP client with in-memory SQLite and rate limiter disabled.

    Patches:
      1. get_db -> in-memory SQLite with all tables created
      2. slowapi Limiter._check_request_limit -> no-op (no 429 from decorators)
      3. PlanRateLimitMiddleware._should_exclude -> always True (no 429 from middleware)
    """
    # 1. Create in-memory SQLite engine with all tables
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )

    # 2. Override get_db dependency
    async def _override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    from cybernova.database.postgres.session import (
        get_db,
        get_db_readonly,
        get_db_session,
    )
    # Override ALL DB dependencies — including get_db_readonly (used by
    # dashboard routes) and get_db_session — so every route uses the same
    # in-memory SQLite engine with all tables created. Otherwise read-only
    # routes spin up a separate empty in-memory DB and fail with
    # "no such table: alerts".
    for dep in (get_db, get_db_readonly, get_db_session):
        app.dependency_overrides[dep] = _override_get_db

    # 3. Apply patches
    #    slowapi: the @limiter.limit() decorator wraps endpoint functions at
    #    import time.  The wrapper calls _check_request_limit → __evaluate_limits
    #    which sets request.state.view_rate_limit, then the wrapper reads it
    #    back for the response header.  If we patch _check_request_limit to a
    #    no-op, __evaluate_limits never runs and view_rate_limit is never set,
    #    causing AttributeError in async_wrapper.
    #
    #    The correct fix: patch __evaluate_limits to only set the state attr
    #    (no actual rate-limiting check).
    def _noop_evaluate_limits(self, request, endpoint, limits):
        request.state.view_rate_limit = None

    patches = [
        patch(
            "slowapi.extension.Limiter._Limiter__evaluate_limits",
            _noop_evaluate_limits,
        ),
        # Disable PlanRateLimitMiddleware by making it skip all paths
        patch(
            "cybernova.security.plan_rate_limiter._should_exclude",
            return_value=True,
        ),
    ]
    for p in patches:
        p.start()

    # 4. Create test client with follow_redirects to handle 307s
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Content-Type": "application/json"},
        timeout=30.0,
        follow_redirects=True,
    ) as ac:
        yield ac

    # 5. Cleanup
    for p in patches:
        p.stop()
    app.dependency_overrides.clear()
    await engine.dispose()
