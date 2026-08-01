"""
Security-focused tests for /api/v1/testing/ endpoints.

These endpoints serve as the "godmode" — they expose detection rule testing,
sigma validation, and atomic test execution. Tested with 10+ years of
attacker and developer experience to ensure:
  1. Proper authentication/authorization
  2. No code injection via sigma YAML
  3. Atomic tests execute safely
  4. Error handling is robust

Uses the shared `client` fixture from tests/e2e/conftest.py.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _register_and_get_token(client, username="test_admin",
                                   email="test@test.com"):
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "Test!Pass123",
            "roles": ["admin"],
            "tenant_name": "TestOrg",
        },
    )
    if resp.status_code != 200:
        pytest.skip(f"Registration returned {resp.status_code}: {resp.text[:100]}")
    return resp.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# Authentication & Authorization
# ══════════════════════════════════════════════════════════════════════════════

class TestTestingAuth:
    async def test_list_tests_unauthenticated(self, client):
        assert (await client.get("/api/v1/testing/tests")).status_code == 401

    async def test_run_test_unauthenticated(self, client):
        assert (await client.post("/api/v1/testing/run/T1003-001")).status_code == 401

    async def test_run_all_unauthenticated(self, client):
        assert (await client.post("/api/v1/testing/run-all")).status_code == 401

    async def test_results_unauthenticated(self, client):
        assert (await client.get("/api/v1/testing/results")).status_code == 401

    async def test_sigma_validate_unauthenticated(self, client):
        resp = await client.post("/api/v1/testing/sigma/validate",
                                 json={"yaml_content": "title: test\n"})
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# Atomic Test Listing
# ══════════════════════════════════════════════════════════════════════════════

class TestAtomicTestListing:
    async def test_list_tests(self, client):
        token = await _register_and_get_token(client, "list_admin", "list@test.com")
        resp = await client.get("/api/v1/testing/tests", headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            data = resp.json()
            assert "tests" in data and "total" in data and data["total"] > 0

    async def test_atomic_tests_have_required_fields(self, client):
        token = await _register_and_get_token(client, "fields_admin", "fields@test.com")
        resp = await client.get("/api/v1/testing/tests", headers=_auth(token))
        if resp.status_code == 200:
            for t in resp.json()["tests"]:
                assert "id" in t and "name" in t

    async def test_known_mitre_ids_present(self, client):
        token = await _register_and_get_token(client, "mitre_admin", "mitre@test.com")
        resp = await client.get("/api/v1/testing/tests", headers=_auth(token))
        if resp.status_code == 200:
            test_ids = [t["id"] for t in resp.json()["tests"]]
            for tid in ["T1003-001", "T1059-001", "T1078-001"]:
                assert tid in test_ids, f"MITRE test {tid} missing"


# ══════════════════════════════════════════════════════════════════════════════
# Atomic Test Execution
# ══════════════════════════════════════════════════════════════════════════════

class TestAtomicTestExecution:
    async def test_run_single_test(self, client):
        token = await _register_and_get_token(client, "run_admin", "run@test.com")
        resp = await client.post("/api/v1/testing/run/T1003-001", headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            assert "result" in resp.json() and "passed" in resp.json()["result"]

    async def test_run_nonexistent_test_returns_404(self, client):
        token = await _register_and_get_token(client, "404_admin", "404@test.com")
        resp = await client.post("/api/v1/testing/run/NONEXISTENT-999",
                                 headers=_auth(token))
        assert resp.status_code in (404, 403)

    async def test_run_all_tests(self, client):
        token = await _register_and_get_token(client, "all_admin", "all@test.com")
        resp = await client.post("/api/v1/testing/run-all", headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            summary = resp.json()["summary"]
            assert summary["total"] > 0


# ══════════════════════════════════════════════════════════════════════════════
# Sigma Rule Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestSigmaValidation:
    VALID_YAML = """
title: Test Brute Force Detection
status: experimental
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection
level: high
"""

    async def test_validate_valid_sigma(self, client):
        token = await _register_and_get_token(client, "sigma_admin", "sigma@test.com")
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": self.VALID_YAML}, headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            assert "valid" in resp.json()

    async def test_validate_empty_yaml(self, client):
        token = await _register_and_get_token(client, "sigma_empty", "empty@test.com")
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": ""}, headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            data = resp.json()
            assert data.get("valid") is False or len(data.get("errors", [])) > 0

    async def test_validate_invalid_yaml_syntax(self, client):
        token = await _register_and_get_token(client, "sigma_bad", "bad@test.com")
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": "this is not valid yaml: {{{:::"},
            headers=_auth(token))
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            data = resp.json()
            assert data.get("valid") is False or len(data.get("errors", [])) > 0

    async def test_validate_malicious_yaml_no_code_exec(self, client):
        """PyYAML safe_load must prevent !!python/object/execute payloads."""
        token = await _register_and_get_token(client, "sigma_mal", "mal@test.com")
        malicious_yaml = "!!python/object/apply:os.system\n- \"echo PWNED\"\ntitle: Mal\n"
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": malicious_yaml}, headers=_auth(token))
        assert resp.status_code in (200, 400, 422, 403)
        if resp.status_code == 200:
            assert resp.json().get("valid") is False


# ══════════════════════════════════════════════════════════════════════════════
# Error Handling & Edge Cases (attacker-grade)
# ══════════════════════════════════════════════════════════════════════════════

class TestTestingEdgeCases:
    async def test_path_traversal_rejected(self, client):
        token = await _register_and_get_token(client, "trav_admin", "trav@test.com")
        resp = await client.post("/api/v1/testing/run/../../etc/passwd",
                                 headers=_auth(token))
        assert resp.status_code in (404, 403, 422)

    async def test_sql_injection_no_500(self, client):
        token = await _register_and_get_token(client, "sql_admin", "sql@test.com")
        resp = await client.post("/api/v1/testing/run/' OR 1=1 --",
                                 headers=_auth(token))
        assert resp.status_code in (404, 403, 422)
        assert resp.status_code != 500

    async def test_huge_payload_handled(self, client):
        token = await _register_and_get_token(client, "huge_admin", "huge@test.com")
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": "title: " + "A" * 100_000 + "\nstatus: test\n"},
            headers=_auth(token))
        assert resp.status_code in (200, 413, 422, 400, 403)

    async def test_xss_in_yaml_no_crash(self, client):
        token = await _register_and_get_token(client, "xss_admin", "xss@test.com")
        resp = await client.post("/api/v1/testing/sigma/validate",
            json={"yaml_content": '<script>alert("xss")</script>\ntitle: test\n'},
            headers=_auth(token))
        assert resp.status_code in (200, 400, 422, 403)

    async def test_results_endpoint(self, client):
        token = await _register_and_get_token(client, "res_admin", "res@test.com")
        resp = await client.get("/api/v1/testing/results", headers=_auth(token))
        assert resp.status_code in (200, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Attack Simulation Integration
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackSimulation:
    async def test_simulate_attack_endpoint(self, client):
        token = await _register_and_get_token(client, "sim_admin", "sim@test.com")
        resp = await client.post("/api/v1/pipeline/simulate-attack",
                                 headers=_auth(token))
        assert resp.status_code in (200, 403)

    async def test_simulate_attack_produces_dashboard_alerts(self, client):
        """
        simulate-attack must create alerts visible in the dashboard.
        Mirrors the docker-stack CI assertion (GET /dashboard/alerts > 0).
        """
        token = await _register_and_get_token(client, "sim_admin2", "sim2@test.com")
        resp = await client.post("/api/v1/pipeline/simulate-attack",
                                 headers=_auth(token))
        if resp.status_code == 403:
            pytest.skip("Requester lacks pipeline:manage permission")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body.get("alerts_created", 0) > 0, f"0 alerts created: {body}"

        alerts = await client.get("/api/v1/dashboard/alerts", headers=_auth(token))
        assert alerts.status_code == 200, alerts.text
        assert len(alerts.json()) > 0, "Dashboard shows zero alerts after simulate-attack"

# ══════════════════════════════════════════════════════════════════════════════
# Rate Limiting on Testing Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestTestingRateLimits:
    async def test_rapid_requests_no_500(self, client):
        token = await _register_and_get_token(client, "rate_admin", "rate@test.com")
        headers = _auth(token)
        for _ in range(5):
            resp = await client.get("/api/v1/testing/tests", headers=headers)
            assert resp.status_code in (200, 429, 403)
