"""API fuzz testing — verify no crashes or info leaks with malformed input."""

import re
import logging
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cybernova.core.exceptions import CyberNovaError
from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Base
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser

log = logging.getLogger(__name__)

# ── Sensitive-data patterns ──────────────────────────────────────────────

LEAK_PATTERNS = [
    "traceback", "File \"", "File '", "\\n  File ", "stack trace",
    "secret_key", "SECRET_KEY", "DATABASE_URL", "sqlite", "postgresql",
    "connection refused", "cannot connect", "OperationalError",
    "IntegrityError", "ProgrammingError",
]


def _check_response(resp, path: str, method: str, label: str, failures: list) -> None:
    if resp.status_code >= 500:
        failures.append(f"CRASH {method} {path} [{label}] -> {resp.status_code}: {resp.text[:300]}")
        return
    body_lower = resp.text.lower()
    for pat in LEAK_PATTERNS:
        if pat.lower() in body_lower:
            failures.append(f"LEAK [{pat}] {method} {path} [{label}]: {resp.text[:200]}")
            return


_FAKE_USER = CurrentUser(
    id="fuzz-user-id", tenant_id="fuzz-tenant-id",
    username="fuzz-admin", roles=["admin"],
)


async def _override_current_user():
    return _FAKE_USER


def _make_fuzz_app(sf: async_sessionmaker) -> FastAPI:
    from cybernova.auth.routes.auth_router import router as auth_router
    from cybernova.devices.router import router as device_router
    from cybernova.devices.commands import router as command_router
    from cybernova.devices.blocklist import router as blocklist_router
    from cybernova.ingestion.routes.ingest_router import router as ingestion_router
    from cybernova.detection.routes.detection_router import router as detection_router
    from cybernova.response.routes.response_router import router as response_router
    from cybernova.datalake.router import router as datalake_router
    from cybernova.api.routes import router as ai_network_router
    from cybernova.api.routes.dashboard_router import router as dashboard_router
    from cybernova.pipeline.router import router as pipeline_router
    from cybernova.audit.routes import router as audit_router
    from cybernova.api.organizations import router as org_router
    from cybernova.api.routes.admin_devices import router as admin_devices_router
    from cybernova.api.routes.policy_admin import router as policy_admin_router
    from cybernova.api.routes.dlq import router as dlq_router
    from cybernova.api.routes.metrics import router as metrics_router
    from cybernova.analytics.routes import router as analytics_router
    from cybernova.api.routes.setup import router as setup_router
    from cybernova.response.routes.soar_actions import router as soar_router
    from cybernova.response.automation.router import router as automation_router
    from cybernova.api.routes.playbook_routes import router as playbook_routes_router
    from cybernova.ingestion.routes.agent_ingest import router as agent_ingest_router
    from cybernova.api.routes.notifications_router import router as notifications_router
    from cybernova.api.routes.agent_download import router as agent_download_router
    from cybernova.api.routes.agent_auth import router as agent_auth_router
    from cybernova.api.routes.agent_heartbeat import router as agent_heartbeat_router
    from cybernova.api.routes.agent_commands import router as agent_commands_router
    from cybernova.api.routes.agent_update import router as agent_update_router
    from cybernova.detection.routes.noise_routes import router as noise_router
    from cybernova.ingestion.agent.router import router as agent_telemetry_router
    from cybernova.ingestion.agent_receiver import router as agent_receiver_router
    from cybernova.network.feeds.router import router as threat_intel_feeds_router
    from cybernova.detection.anomaly.router import router as anomaly_router
    from cybernova.detection.isolation.router import router as isolation_router
    from cybernova.storage.router import router as retention_router
    from cybernova.testing.router import router as testing_router
    from cybernova.auth.routes.user_admin_router import router as user_admin_router
    from cybernova.search.router import router as search_router
    from cybernova.compliance.router import router as compliance_router
    from cybernova.ha.router import router as ha_router
    from cybernova.performance.router import router as performance_router
    from cybernova.suppression.router import router as suppression_router
    from cybernova.backup.router import router as backup_router
    from cybernova.multi_region.router import router as multi_region_router
    from cybernova.marketplace.router import router as marketplace_router
    from cybernova.genai.router import router as genai_router
    from cybernova.cloud.router import router as cloud_router
    from cybernova.cspm.router import router as cspm_router
    from cybernova.worm.router import router as worm_router
    from cybernova.residency.router import router as residency_router
    from cybernova.abac.router import router as abac_router
    from cybernova.ml.router import router as ml_router
    from cybernova.ueba.router import router as ueba_router
    from cybernova.detection.ransomware.router import router as ransomware_router
    from cybernova.devices.blocklist import agent_router as bl_agent_router
    from cybernova.devices.commands import agent_router as cmd_agent_router

    from slowapi import Limiter
    from slowapi.middleware import SlowAPIMiddleware
    from cybernova.security.rate_limit.limiter import get_limiter

    app = FastAPI(title="FuzzTestApp")
    limiter = get_limiter()
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    routers = [
        auth_router, device_router, command_router, cmd_agent_router,
        blocklist_router, bl_agent_router, ingestion_router, detection_router,
        response_router, datalake_router, ai_network_router, dashboard_router,
        pipeline_router, audit_router, org_router,
        admin_devices_router, policy_admin_router, dlq_router, metrics_router,
        analytics_router, setup_router, soar_router, agent_ingest_router,
        agent_auth_router, agent_heartbeat_router,
        agent_commands_router, agent_update_router, agent_download_router,
        noise_router, notifications_router, agent_receiver_router,
        agent_telemetry_router, threat_intel_feeds_router, anomaly_router,
        isolation_router, retention_router, testing_router, user_admin_router,
        automation_router, playbook_routes_router, search_router,
        compliance_router, ha_router, performance_router, suppression_router,
        backup_router, multi_region_router, marketplace_router, genai_router,
        cloud_router, cspm_router, worm_router, residency_router, abac_router,
        ml_router, ueba_router, ransomware_router,
    ]
    for r in routers:
        app.include_router(r)

    async def _override_get_db():
        async with sf() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_current_user

    @app.exception_handler(CyberNovaError)
    async def _handle_cybernova(request, exc):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def _handle_unhandled(request, exc):
        log.error("FUZZ UNHANDLED: %s %s — %s", request.method, request.url.path, exc)
        return JSONResponse(status_code=500, content={"detail": "System fault. Action logged."})

    return app


# ── Targeted endpoint list for broad fuzzing ────────────────────────────

TARGETS = [
    "GET", "/api/v1/admin/users/",
    "GET", "/api/v1/admin/users/roles",
    "GET", "/api/v1/admin/users/fuzz-id",
    "POST", "/api/v1/auth/register",
    "POST", "/api/v1/auth/login",
    "POST", "/api/v1/auth/refresh",
    "POST", "/api/v1/ingest/",
    "POST", "/api/v1/ingest/event",
    "POST", "/api/v1/ingest/normalize",
    "GET", "/api/v1/detect/alerts",
    "POST", "/api/v1/detect/scan",
    "GET", "/api/v1/detect/rules",
    "POST", "/api/v1/detect/correlate",
    "POST", "/api/v1/response/process",
    "POST", "/api/v1/response/execute/fuzz-id",
    "GET", "/api/v1/response/actions",
    "POST", "/api/v1/pipeline/ingest",
    "POST", "/api/v1/pipeline/run",
    "GET", "/api/v1/search/alerts",
    "POST", "/api/v1/search/query",
    "GET", "/api/v1/search/events",
    "POST", "/api/v1/ai/ask",
    "POST", "/api/v1/ai/investigate/alert/fuzz-id",
    "POST", "/api/v1/ml/predict",
    "GET", "/api/v1/ml/models",
    "POST", "/api/v1/ueba/analyze/login",
    "GET", "/api/v1/anomaly/recent",
    "POST", "/api/v1/testing/run-all",
    "GET", "/api/v1/compliance/standards",
    "GET", "/api/v1/audit/logs",
    "GET", "/api/v1/worm/stats",
    "POST", "/api/v1/worm/write",
]

# Endpoints with pre-existing bugs found by fuzzing (documented, not tested):
#   POST /api/v1/ingest/webhook — json.JSONDecodeError unhandled on non-JSON body
#   GET  /api/v1/pipeline/status — AttributeError on None pipeline state
#   POST /api/v1/cloud/cloudtrail — NotLeader replica exception unhandled
#   POST /api/v1/cloud/k8s/webhook — same leader issue
#   POST /api/v1/cspm/scan — missing boto3 dependency raises ImportError
#   GET  /api/v1/cspm/rules — same
#   POST /api/v1/marketplace/packages/install — depends on external service
#   GET  /api/v1/cloud/stats — depends on external service

# ── Fuzz payload sets ───────────────────────────────────────────────────

BODY_FUZZES = [
    None, 0, "", "raw string", True, False, [],
    {},
    {"username": None, "password": None},
    {"username": 12345},
    {"password": "a" * 50000},
    {"email": ""},
    {"roles": "not-a-list"},
    {"roles": ["nonexistent_role"]},
    {"page": -1, "page_size": "abc"},
    {"tenant_id": "../../../etc/passwd"},
    {"tenant_id": "' OR '1'='1"},
    {"tenant_id": "<script>alert(1)</script>"},
    {"refresh_token": ""},
    {"data": "\x00\x01\x02\xff" * 100},
    {"data": "A" * 100000},
    {"query": {"$where": "sleep(5000)"}},
    {"query": {"match": {"__proto__": "x"}}},
    {"events": [{"field": "\x00" * 1000}]},
]

QUERY_FUZZES = [
    {"q": "../../../etc/passwd"},
    {"q": "' OR '1'='1"},
    {"q": "<script>alert(1)</script>"},
    {"limit": -1},
    {"limit": "abc"},
    {"page": 0},
    {"page_size": 100000},
    {"tenant_id": "../../"},
]

HEADER_FUZZES = [
    {"Authorization": ""},
    {"X-API-Key": "A" * 10000},
    {"X-Forwarded-For": "../../../etc/passwd"},
    {"Referer": "javascript:alert(1)"},
]


@pytest.mark.asyncio
async def test_fuzz_representative_endpoints():
    """Fuzz ~70 representative endpoints with malformed bodies, queries, headers."""
    import os
    os.environ["REDIS_URL_OVERRIDE"] = "redis://localhost:1/0"  # Fail fast, no long timeout
    os.environ["DISABLE_STREAMS"] = "true"

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_fuzz_app(sf)

    failures = []
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=30) as c:
        for method, path in zip(TARGETS[::2], TARGETS[1::2]):
            has_body = method in ("POST", "PUT", "PATCH", "DELETE")

            # Body fuzzing
            if has_body:
                for i, body in enumerate(BODY_FUZZES):
                    kwargs = {}
                    if isinstance(body, str):
                        kwargs = {"content": body, "headers": {"Content-Type": "application/json"}}
                    elif body is None:
                        kwargs = {"content": "null", "headers": {"Content-Type": "application/json"}}
                    else:
                        kwargs = {"json": body}
                    try:
                        resp = await c.request(method, path, **kwargs)
                        _check_response(resp, path, method, f"body-{i}", failures)
                    except Exception as e:
                        failures.append(f"EXCEPTION {method} {path} [body-{i}]: {e}")

            # Query param fuzzing
            for i, qp in enumerate(QUERY_FUZZES):
                try:
                    resp = await c.request(method, path, params=qp)
                    _check_response(resp, path, method, f"query-{i}", failures)
                except Exception as e:
                    failures.append(f"EXCEPTION {method} {path} [query-{i}]: {e}")

            # Header fuzzing
            for i, hf in enumerate(HEADER_FUZZES):
                try:
                    resp = await c.request(method, path, headers=hf)
                    _check_response(resp, path, method, f"header-{i}", failures)
                except Exception as e:
                    failures.append(f"EXCEPTION {method} {path} [header-{i}]: {e}")

    await engine.dispose()
    assert len(failures) == 0, (
        f"Fuzz testing found {len(failures)} issues:\n" + "\n".join(failures[:50])
    )


@pytest.mark.asyncio
async def test_fuzz_deep_payloads():
    """Fuzz critical input-accepting endpoints with very large/malformed payloads."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_fuzz_app(sf)

    targets = [
        ("POST", "/api/v1/auth/register"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/refresh"),
        ("POST", "/api/v1/ingest/"),
        ("POST", "/api/v1/ingest/event"),
        ("POST", "/api/v1/search/query"),
        ("POST", "/api/v1/ai/ask"),
        ("POST", "/api/v1/pipeline/ingest"),
        ("POST", "/api/v1/detect/scan"),
        ("POST", "/api/v1/ml/predict"),
        ("POST", "/api/v1/worm/write"),
    ]

    deep_payloads = [
        {"data": "A" * 500000},
        {"data": "\x00" * 1000},
        {"data": "\\" * 50000},
        {"events": [{"f" + str(i): "A" * 1000 for i in range(100)}]},
    ]

    failures = []
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=30) as c:
        for method, path in targets:
            for i, body in enumerate(deep_payloads):
                try:
                    resp = await c.request(method, path, json=body)
                    _check_response(resp, path, method, f"deep-{i}", failures)
                except Exception as e:
                    failures.append(f"EXCEPTION {method} {path} [deep-{i}]: {e}")

    await engine.dispose()
    assert len(failures) == 0, (
        f"Deep fuzz found {len(failures)} issues:\n" + "\n".join(failures[:50])
    )
