"""Integration test: register → login → JWT → protected routes → RBAC enforcement."""

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybernova.auth.routes.user_admin_router import router as user_admin_router
from cybernova.auth.schemas import LoginRequest, RegisterRequest
from cybernova.auth.services.auth_service import auth_service
from cybernova.core.exceptions import CyberNovaError
from cybernova.database.postgres.session import get_db

# ── Minimal auth router (no slowapi rate limiter decorators) ──────────────────

_test_auth_router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@_test_auth_router.post("/register")
async def _register(request: Request, payload: RegisterRequest,
                    db: AsyncSession = Depends(get_db)):
    result = await auth_service.register(
        db, payload.username, payload.email, payload.password,
        tenant_name=payload.tenant_name, roles=payload.roles,
        org_key=payload.org_key,
    )
    return result


@_test_auth_router.post("/login")
async def _login(request: Request, payload: LoginRequest,
                 db: AsyncSession = Depends(get_db)):
    return await auth_service.login(db, payload.username, payload.password,
                                    ip=_client_ip(request))


def _make_app(session_factory):
    app = FastAPI()
    app.include_router(_test_auth_router)
    app.include_router(user_admin_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db

    @app.exception_handler(CyberNovaError)
    async def _handle_cybernova(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    return app


@pytest.mark.asyncio
async def test_auth_full_flow():
    """Register → Login → JWT → protected route → RBAC enforcement.
    Uses a fresh in-memory SQLite database for full isolation.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        from cybernova.database.postgres.models import Base
        await conn.run_sync(Base.metadata.create_all)

    sf = async_sessionmaker(engine, class_=AsyncSession)
    app = _make_app(sf)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        try:

            # ── 1. Register admin user ──────────────────────────────────────────
            resp = await c.post("/api/v1/auth/register", json={
                "username": "admin-user",
                "email": "admin@test.com",
                "password": "AdminPass1!",
                "tenant_name": "test-tenant",
                "roles": ["admin"],
            })
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            admin_token = data["access_token"]

            # ── 2. Login as admin ───────────────────────────────────────────────
            resp = await c.post("/api/v1/auth/login", json={
                "username": "admin-user",
                "password": "AdminPass1!",
            })
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert "access_token" in data
            admin_token = data["access_token"]

            # ── 3. Call protected route with valid admin JWT ────────────────────
            resp = await c.get(
                "/api/v1/admin/users/",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert "users" in body
            assert body["total"] >= 1

            # ── 4. Register viewer user (same tenant) ───────────────────────────
            resp = await c.post("/api/v1/auth/register", json={
                "username": "viewer-user",
                "email": "viewer@test.com",
                "password": "ViewerPass1!",
                "tenant_name": "test-tenant",
                "roles": ["viewer"],
            })
            assert resp.status_code == 200, resp.text
            viewer_token = resp.json()["access_token"]

            # Admin sees both users in tenant listing
            resp = await c.get(
                "/api/v1/admin/users/",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["total"] == 2

            # ── 5. RBAC: viewer can LIST users (has USERS_VIEW) but denied from create ──
            resp = await c.get(
                "/api/v1/admin/users/",
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            assert resp.status_code == 200, resp.text  # viewers have USERS_VIEW

            # Viewer cannot CREATE users (no USERS_CREATE)
            resp = await c.post(
                "/api/v1/admin/users/",
                headers={"Authorization": f"Bearer {viewer_token}"},
                json={"username": "new-user", "email": "new@test.com", "password": "NewPass1!", "roles": ["viewer"]},
            )
            assert resp.status_code == 403, resp.text
            assert "Insufficient permissions" in resp.json().get("detail", "")

            # ── 6. Invalid credentials returns 401 ──────────────────────────────
            resp = await c.post("/api/v1/auth/login", json={
                "username": "admin-user",
                "password": "wrongpassword",
            })
            assert resp.status_code == 401, resp.text
            assert "Invalid username or password" in resp.json().get("detail", "")

            # ── 7. No token returns 401 ─────────────────────────────────────────
            resp = await c.get("/api/v1/admin/users/")
            assert resp.status_code == 401, resp.text

            # ── 8. JWT decode + verify payload ──────────────────────────────────
            from cybernova.security.encryption.jwt_handler import decode_access_token
            payload = decode_access_token(admin_token)
            assert payload["type"] == "access"
            assert payload["username"] == "admin-user"
            assert "admin" in payload.get("roles", [])
            assert "tenant_id" in payload
            assert "user_id" in payload

        finally:
            await engine.dispose()
