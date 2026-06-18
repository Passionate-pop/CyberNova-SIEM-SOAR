"""Red team attack scenario tests — inject events, verify detection alerts."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import AsyncClient, ASGITransport
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cybernova.core.exceptions import CyberNovaError
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import Base, NormalizedEvent
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser

TENANT_ID = "scenario-tenant"


@pytest.fixture(autouse=True)
def _no_redis():
    with patch("cybernova.core.event_bus.producer.event_producer.publish",
               new_callable=AsyncMock, return_value="mock-event-id"):
        yield


def _make_app(sf: async_sessionmaker) -> FastAPI:
    from cybernova.detection.routes.detection_router import router as detection_router
    from cybernova.auth.routes.user_admin_router import router as user_admin_router

    app = FastAPI()
    app.include_router(detection_router)
    app.include_router(user_admin_router)

    async def _override_get_db():
        async with sf() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    _fake_user = CurrentUser(
        id="scenario-admin-id", tenant_id=TENANT_ID,
        username="scenario-admin", roles=["admin"],
    )

    async def _override_current_user():
        return _fake_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_current_user

    @app.exception_handler(CyberNovaError)
    async def _handle_cybernova(request, exc):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def _handle_unhandled(request, exc):
        return JSONResponse(status_code=500, content={"detail": "System fault."})

    return app


async def _inject_event(sf: async_sessionmaker, **kwargs) -> str:
    event_id = new_id()
    defaults = dict(
        id=event_id, tenant_id=TENANT_ID, severity="medium",
        source_ip="", dest_ip="", source_port=0, dest_port=0,
        protocol="", user="", message="", extra_data={},
        timestamp=utcnow(), normalized_at=utcnow(),
    )
    defaults.update(kwargs)
    async with sf() as session:
        stmt = insert(NormalizedEvent).values(**defaults)
        await session.execute(stmt)
        await session.commit()
    return event_id


async def _scan_and_get_alerts(client: AsyncClient) -> dict:
    scan_resp = await client.post(
        "/api/v1/detect/scan?limit=50",
        headers={"Authorization": "Bearer test"},
    )
    assert scan_resp.status_code == 200, scan_resp.text
    scan_data = scan_resp.json()

    alerts_resp = await client.get(
        "/api/v1/detect/alerts",
        headers={"Authorization": "Bearer test"},
    )
    assert alerts_resp.status_code == 200, alerts_resp.text
    alerts_data = alerts_resp.json()

    return {
        "alerts_created": scan_data["alerts_created"],
        "alerts": alerts_data.get("alerts", []),
    }


@pytest.mark.asyncio
async def test_sql_injection_scenario():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    await _inject_event(sf,
        event_type="sql_injection_attempt",
        severity="critical",
        source_ip="10.0.0.5",
        dest_ip="192.168.1.10",
        dest_port=80,
        protocol="TCP",
        user="webapp",
        message="SQL injection payload detected: ' OR '1'='1 on /api/login",
        extra_data={"url": "/api/login", "payload": "' OR '1'='1", "method": "POST"},
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        data = await _scan_and_get_alerts(c)

    assert data["alerts_created"] >= 1
    rule_names = {a["rule_name"] for a in data["alerts"]}
    assert "sql_injection" in rule_names or "sqli_detected" in rule_names, rule_names

    await engine.dispose()


@pytest.mark.asyncio
async def test_xss_scenario():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    await _inject_event(sf,
        event_type="xss_detected",
        severity="high",
        source_ip="10.0.0.6",
        dest_ip="192.168.1.10",
        dest_port=443,
        protocol="TCP",
        message="XSS payload: <script>alert(1)</script> in search query",
        extra_data={
            "url": "/search", "payload": "<script>alert(1)</script>",
            "method": "GET", "param": "q",
        },
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        data = await _scan_and_get_alerts(c)

    assert data["alerts_created"] >= 1
    rule_names = {a["rule_name"] for a in data["alerts"]}
    assert "xss_detected" in rule_names, rule_names

    await engine.dispose()


@pytest.mark.asyncio
async def test_brute_force_scenario():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    for i in range(6):
        await _inject_event(sf,
            event_type="failed_login",
            severity="medium",
            source_ip="10.0.0.100",
            dest_ip="192.168.1.1",
            protocol="TCP",
            user="admin",
            message=f"Failed login attempt #{i+1} for user admin",
            extra_data={"username": "admin", "attempt": i + 1},
        )

    await _inject_event(sf,
        event_type="brute_force_detected",
        severity="high",
        source_ip="10.0.0.100",
        dest_ip="192.168.1.1",
        protocol="TCP",
        user="admin",
        message="Brute force attack detected — 6 failed logins in 5 minutes",
        extra_data={"failed_count": 6, "window_seconds": 300},
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        data = await _scan_and_get_alerts(c)

    assert data["alerts_created"] >= 2
    rule_names = {a["rule_name"] for a in data["alerts"]}
    assert "failed_login" in rule_names, f"missing failed_login in {rule_names}"
    assert "brute_force_detected" in rule_names, f"missing brute_force_detected in {rule_names}"

    await engine.dispose()


@pytest.mark.asyncio
async def test_port_scan_scenario():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    await _inject_event(sf,
        event_type="port_scan_detected",
        severity="medium",
        source_ip="10.0.0.200",
        dest_ip="192.168.1.1",
        protocol="TCP",
        message="Port scan detected: 50 ports scanned from 10.0.0.200",
        extra_data={
            "scanned_ports": [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200],
            "ports_count": 50, "scanner_ip": "10.0.0.200",
        },
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        data = await _scan_and_get_alerts(c)

    assert data["alerts_created"] >= 1
    rule_names = {a["rule_name"] for a in data["alerts"]}
    assert "port_scan" in rule_names, rule_names

    await engine.dispose()


@pytest.mark.asyncio
async def test_all_scenarios_together():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    events = [
        dict(event_type="xss_detected", severity="high",
             source_ip="10.0.0.6", message="XSS: <img src=x onerror=alert(1)>",
             extra_data={"payload": "<img src=x onerror=alert(1)>"}),
        dict(event_type="sql_injection_attempt", severity="critical",
             source_ip="10.0.0.7", message="SQLi: ' UNION SELECT * FROM users --",
             extra_data={"payload": "' UNION SELECT * FROM users --"}),
        dict(event_type="brute_force_detected", severity="high",
             source_ip="10.0.0.8", message="Brute force on SSH",
             extra_data={"attempts": 100}),
        dict(event_type="port_scan_detected", severity="medium",
             source_ip="10.0.0.9", message="Port scan on web server",
             extra_data={"ports": "22,80,443,3306"}),
    ]
    for ev in events:
        await _inject_event(sf, **ev)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        data = await _scan_and_get_alerts(c)

    assert data["alerts_created"] >= len(events), f"Expected >= {len(events)} alerts, got {data}"
    rule_names = {a["rule_name"] for a in data["alerts"]}
    assert "xss_detected" in rule_names, rule_names
    assert "sql_injection" in rule_names or "sqli_detected" in rule_names, rule_names
    assert "brute_force_detected" in rule_names, rule_names
    assert "port_scan" in rule_names, rule_names

    await engine.dispose()
