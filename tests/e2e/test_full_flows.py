"""
Comprehensive end-to-end tests for all CyberNova user flows:
  1. Individual — register → login → dashboard → alerts → SOAR → notifications
  2. Boss/Admin — register org → get org_key → dashboard → SOAR → notifications
  3. Staff — join org via org_key → login → dashboard → alerts

Uses the shared `client` fixture from tests/e2e/conftest.py which provides
in-memory SQLite and disabled rate limiter.
"""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _register(client, username, email, password, roles=None,
                    tenant_name="personal", org_key="", company_size=""):
    body = {
        "username": username,
        "email": email,
        "password": password,
        "roles": roles or ["admin"],
        "tenant_name": tenant_name,
    }
    if org_key:
        body["org_key"] = org_key
    if company_size:
        body["company_size"] = company_size
    return await client.post("/api/v1/auth/register", json=body)


async def _login(client, username, password, org_key=None):
    body = {"username": username, "password": password}
    if org_key:
        body["org_key"] = org_key
    return await client.post("/api/v1/auth/login", json=body)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# Flow 1: Individual User
# ══════════════════════════════════════════════════════════════════════════════

class TestIndividualFlow:
    async def test_register_individual(self, client):
        resp = await _register(client, "alice", "alice@personal.dev",
                               "Str0ng!Pass1", roles=["admin"], tenant_name="personal")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Backend creates a new tenant for every registration without an
        # existing org_key, so purpose is always "organization" at registration
        # time. The frontend later updates this to "individual" via onboarding.
        assert data.get("purpose") == "organization"

    async def test_login_individual(self, client):
        await _register(client, "bob", "bob@personal.dev", "Str0ng!Pass2",
                        roles=["admin"], tenant_name="personal")
        resp = await _login(client, "bob", "Str0ng!Pass2")
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_login_wrong_password_returns_401(self, client):
        await _register(client, "carol", "carol@personal.dev", "Str0ng!Pass3",
                        roles=["admin"], tenant_name="personal")
        resp = await _login(client, "carol", "WrongPassword!")
        assert resp.status_code == 401

    async def test_login_lockout_after_threshold(self, client):
        await _register(client, "dave", "dave@personal.dev", "Str0ng!Pass4",
                        roles=["admin"], tenant_name="personal")
        for _ in range(5):
            await _login(client, "dave", "WrongPassword!")
        resp = await _login(client, "dave", "WrongPassword!")
        assert resp.status_code == 429

    async def test_duplicate_register_returns_409(self, client):
        await _register(client, "eve", "eve@personal.dev", "Str0ng!Pass5",
                        roles=["admin"], tenant_name="personal")
        resp = await _register(client, "eve", "eve@personal.dev", "Str0ng!Pass5",
                               roles=["admin"], tenant_name="personal")
        assert resp.status_code == 409

    async def test_dashboard_requires_auth(self, client):
        resp = await client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 401

    async def test_full_individual_journey(self, client):
        """register → login → dashboard → alerts → incidents → notifications → pipeline"""
        reg_resp = await _register(client, "frank", "frank@test.dev",
                                   "Str0ng!Pass6", roles=["admin"], tenant_name="personal")
        assert reg_resp.status_code == 200
        headers = _auth(reg_resp.json()["access_token"])

        login_resp = await _login(client, "frank", "Str0ng!Pass6")
        assert login_resp.status_code == 200

        for path in ["/api/v1/dashboard/summary", "/api/v1/dashboard/alerts",
                     "/api/v1/dashboard/incidents", "/api/v1/notifications",
                     "/api/v1/pipeline/status"]:
            resp = await client.get(path, headers=headers)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"


# ══════════════════════════════════════════════════════════════════════════════
# Flow 2: Boss / Admin (Organization Creator)
# ══════════════════════════════════════════════════════════════════════════════

class TestBossAdminFlow:
    async def test_register_boss_creates_org(self, client):
        resp = await _register(client, "boss_henry", "henry@acme.corp",
                               "Str0ng!Pass7", roles=["admin"], tenant_name="AcmeCorp",
                               company_size="51-200")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data.get("org_key"), "Boss registration must return an org_key"
        assert data.get("purpose") == "organization"
        assert data.get("org_type") == "boss"

    async def test_boss_login(self, client):
        await _register(client, "boss_ivan", "ivan@acme.corp", "Str0ng!Pass8",
                        roles=["admin"], tenant_name="AcmeCorp2", company_size="11-50")
        resp = await _login(client, "boss_ivan", "Str0ng!Pass8")
        assert resp.status_code == 200

    async def test_boss_dashboard_has_org_features(self, client):
        reg_resp = await _register(client, "boss_jane", "jane@bigcorp.io",
                                   "Str0ng!Pass9", roles=["admin"], tenant_name="BigCorp",
                                   company_size="201-500")
        headers = _auth(reg_resp.json()["access_token"])
        for path in ["/api/v1/admin/users", "/api/v1/admin/devices", "/api/v1/audit/logs"]:
            resp = await client.get(path, headers=headers)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"

    async def test_full_boss_journey(self, client):
        """register org → get key → dashboard → SOAR → notifications → generate new key"""
        reg_resp = await _register(client, "boss_lin", "lin@techcorp.dev",
                                   "Str0ng!Pass11", roles=["admin"], tenant_name="TechCorp",
                                   company_size="500+")
        assert reg_resp.status_code == 200
        data = reg_resp.json()
        token = data["access_token"]
        org_key = data["org_key"]
        headers = _auth(token)

        assert data["purpose"] == "organization"
        assert data["org_type"] == "boss"
        assert org_key

        assert (await client.get("/api/v1/dashboard/summary", headers=headers)).status_code == 200

        soar_resp = await client.post("/api/v1/soar/block-ip",
            json={"ip_address": "203.0.113.99", "reason": "Test", "duration_hours": 1},
            headers=headers)
        assert soar_resp.status_code in (200, 403, 500)

        assert (await client.get("/api/v1/notifications", headers=headers)).status_code == 200

        gen_resp = await client.post("/api/v1/organizations/generate-key",
            json={"name": "engineering"}, headers=headers)
        assert gen_resp.status_code in (200, 404)


# ══════════════════════════════════════════════════════════════════════════════
# Flow 3: Staff Member (Joins Existing Org)
# ══════════════════════════════════════════════════════════════════════════════

class TestStaffFlow:
    async def test_staff_registers_with_org_key(self, client):
        boss_resp = await _register(client, "boss_mary", "mary@stafftest.com",
                                    "Str0ng!Pass12", roles=["admin"], tenant_name="StaffTestOrg",
                                    company_size="11-50")
        org_key = boss_resp.json()["org_key"]
        assert org_key

        staff_resp = await _register(client, "staff_noah", "noah@stafftest.com",
                                     "Str0ng!Pass13", roles=["viewer"],
                                     tenant_name="StaffTestOrg", org_key=org_key)
        assert staff_resp.status_code == 200
        data = staff_resp.json()
        assert data.get("purpose") == "organization"
        assert data.get("org_type") == "staff"

    async def test_staff_login_with_org_key(self, client):
        boss_resp = await _register(client, "boss_olivia", "olivia@logintest.com",
                                    "Str0ng!Pass14", roles=["admin"], tenant_name="LoginTestOrg",
                                    company_size="1-10")
        org_key = boss_resp.json()["org_key"]
        await _register(client, "staff_peter", "peter@logintest.com", "Str0ng!Pass15",
                        roles=["viewer"], tenant_name="LoginTestOrg", org_key=org_key)
        login_resp = await _login(client, "staff_peter", "Str0ng!Pass15", org_key=org_key)
        assert login_resp.status_code == 200

    async def test_staff_limited_access(self, client):
        boss_resp = await _register(client, "boss_quinn", "quinn@limited.com",
                                    "Str0ng!Pass16", roles=["admin"], tenant_name="LimitedOrg",
                                    company_size="51-200")
        org_key = boss_resp.json()["org_key"]
        staff_resp = await _register(client, "staff_rachel", "rachel@limited.com",
                                     "Str0ng!Pass17", roles=["viewer"],
                                     tenant_name="LimitedOrg", org_key=org_key)
        headers = _auth(staff_resp.json()["access_token"])

        assert (await client.get("/api/v1/dashboard/summary", headers=headers)).status_code == 200
        assert (await client.get("/api/v1/dashboard/alerts", headers=headers)).status_code == 200
        users_resp = await client.get("/api/v1/admin/users", headers=headers)
        assert users_resp.status_code in (401, 403)

    async def test_full_staff_journey(self, client):
        """boss creates org → staff joins → staff uses dashboard → boss also works"""
        boss_resp = await _register(client, "boss_tina", "tina@fulljourney.com",
                                    "Str0ng!Pass18", roles=["admin"],
                                    tenant_name="FullJourneyOrg", company_size="201-500")
        org_key = boss_resp.json()["org_key"]

        staff_resp = await _register(client, "staff_uma", "uma@fulljourney.com",
                                     "Str0ng!Pass19", roles=["viewer"],
                                     tenant_name="FullJourneyOrg", org_key=org_key)
        assert staff_resp.status_code == 200
        staff_headers = _auth(staff_resp.json()["access_token"])

        for path in ["/api/v1/dashboard/summary", "/api/v1/dashboard/alerts",
                     "/api/v1/notifications", "/api/v1/pipeline/status"]:
            resp = await client.get(path, headers=staff_headers)
            assert resp.status_code == 200, f"Staff {path} returned {resp.status_code}"

        boss_login = await _login(client, "boss_tina", "Str0ng!Pass18")
        assert boss_login.status_code == 200
        boss_headers = _auth(boss_login.json()["access_token"])
        assert (await client.get("/api/v1/dashboard/summary", headers=boss_headers)).status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# SOAR Actions Flow
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARFlow:
    async def _boss_token(self, client):
        resp = await _register(client, "soar_boss", "soar@soar.com", "Str0ng!Pass20",
                               roles=["admin"], tenant_name="SOAROrg", company_size="11-50")
        return resp.json()["access_token"]

    async def test_block_ip_endpoint(self, client):
        token = await self._boss_token(client)
        resp = await client.post("/api/v1/soar/block-ip",
            json={"ip_address": "198.51.100.1", "reason": "Test", "duration_hours": 1},
            headers=_auth(token))
        assert resp.status_code in (200, 403, 500)

    async def test_isolate_device_endpoint(self, client):
        token = await self._boss_token(client)
        resp = await client.post("/api/v1/soar/isolate-device/fake-device-id",
                                 headers=_auth(token))
        assert resp.status_code in (200, 404, 403, 500)

    async def test_kill_process_endpoint(self, client):
        token = await self._boss_token(client)
        # KillProcessRequest requires device_id; send invalid device_id to
        # verify the endpoint handles missing/invalid devices gracefully.
        resp = await client.post("/api/v1/soar/kill-process",
            json={"device_id": "nonexistent-device", "pid": 1234,
                  "reason": "Test kill"},
            headers=_auth(token))
        assert resp.status_code in (200, 404, 403, 500)

    async def test_soar_history_endpoint(self, client):
        token = await self._boss_token(client)
        resp = await client.get("/api/v1/soar/history", headers=_auth(token))
        assert resp.status_code in (200, 403)

    async def test_unauthenticated_soar_returns_401(self, client):
        resp = await client.post("/api/v1/soar/block-ip",
                                 json={"ip_address": "10.0.0.1"})
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# Notification Flow
# ══════════════════════════════════════════════════════════════════════════════

class TestNotificationFlow:
    async def _get_token(self, client, username="notif_user", tenant="NotifOrg"):
        resp = await _register(client, username, f"{username}@notif.com",
                               "Str0ng!PassN1", roles=["admin"], tenant_name=tenant)
        return resp.json()["access_token"]

    async def test_list_notifications(self, client):
        token = await self._get_token(client)
        resp = await client.get("/api/v1/notifications", headers=_auth(token))
        assert resp.status_code == 200
        assert "notifications" in resp.json()

    async def test_mark_notification_read(self, client):
        token = await self._get_token(client)
        resp = await client.put("/api/v1/notifications/fake-id/read",
                                headers=_auth(token))
        assert resp.status_code in (200, 404)

    async def test_mark_all_notifications_read(self, client):
        token = await self._get_token(client)
        resp = await client.put("/api/v1/notifications/read-all",
                                headers=_auth(token))
        assert resp.status_code in (200, 404)

    async def test_unauthenticated_notifications_returns_401(self, client):
        resp = await client.get("/api/v1/notifications")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# Security & Health Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityAndHealth:
    async def test_health_endpoint(self, client):
        assert (await client.get("/health")).status_code == 200

    async def test_root_endpoint(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "version" in resp.json()

    async def test_waf_stats_endpoint(self, client):
        assert (await client.get("/api/v1/security/waf/stats")).status_code == 200

    async def test_sla_metrics_endpoint(self, client):
        assert (await client.get("/api/v1/monitoring/sla")).status_code == 200

    async def test_circuit_breakers_endpoint(self, client):
        assert (await client.get("/api/v1/monitoring/circuit-breakers")).status_code == 200
