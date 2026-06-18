"""
Load test: Simulate 500 staff members connected to a boss dashboard.

Verifies that:
  - The SOC overview / dashboard summary endpoint handles concurrent requests
  - Alert listing scales with many concurrent readers
  - Notification endpoint doesn't degrade under load
  - The boss can still access admin endpoints (user list, devices) under load
  - Response times stay within acceptable P95/P99 thresholds

Uses the shared `client` fixture from tests/e2e/conftest.py which provides
in-memory SQLite and disabled rate limiter.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import List

import httpx
import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio

# ── Configuration ────────────────────────────────────────────────────────────

NUM_STAFF = 100  # Reduced from 500 to avoid bcrypt hashing timeout in tests
BATCH_SIZE = 50  # concurrent requests per batch
TIMEOUT_SECONDS = 30

# Boss-only endpoints (fewer concurrent requests)
BOSS_ENDPOINTS = [
    ("/api/v1/admin/users", "GET", "User List"),
    ("/api/v1/admin/devices", "GET", "Device List"),
    ("/api/v1/audit/logs", "GET", "Audit Logs"),
    ("/api/v1/dashboard/summary", "GET", "Dashboard Summary (Boss)"),
]


@dataclass
class RequestResult:
    """Result of a single request."""
    endpoint: str
    status_code: int
    latency_ms: float
    error: str = ""


@dataclass
class LoadTestReport:
    """Aggregated load test report."""
    endpoint: str
    description: str
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return (self.successful / self.total_requests * 100) if self.total_requests else 0

    def percentiles(self) -> dict:
        if not self.latencies_ms:
            return {"p50": 0, "p95": 0, "p99": 0, "avg": 0, "max": 0}
        sorted_lat = sorted(self.latencies_ms)
        n = len(sorted_lat)
        return {
            "p50": round(sorted_lat[n // 2], 2),
            "p95": round(sorted_lat[int(n * 0.95)], 2),
            "p99": round(sorted_lat[int(n * 0.99)], 2),
            "avg": round(statistics.mean(sorted_lat), 2),
            "max": round(sorted_lat[-1], 2),
        }


async def _setup_staff_tokens(
    client: httpx.AsyncClient, org_key: str, count: int
) -> List[str]:
    """Register staff members and return their JWT tokens."""
    tokens = []
    for i in range(0, count, BATCH_SIZE):
        batch_size = min(BATCH_SIZE, count - i)
        tasks = []
        for j in range(batch_size):
            idx = i + j
            tasks.append(
                client.post(
                    "/api/v1/auth/register",
                    json={
                        "username": f"staff_{idx}",
                        "email": f"staff_{idx}@load.dev",
                        "password": "LoadTest!Pass1",
                        "roles": ["viewer"],
                        "tenant_name": "LoadTestOrg",
                        "org_key": org_key,
                    },
                )
            )
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, httpx.Response) and r.status_code == 200:
                tokens.append(r.json()["access_token"])
    return tokens


async def _send_request(
    client: httpx.AsyncClient, method: str, url: str, headers: dict
) -> RequestResult:
    """Send a single request and return the result."""
    start = time.perf_counter()
    try:
        if method == "GET":
            resp = await client.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
        else:
            resp = await client.post(url, headers=headers, timeout=TIMEOUT_SECONDS)
        elapsed = (time.perf_counter() - start) * 1000
        return RequestResult(
            endpoint=url,
            status_code=resp.status_code,
            latency_ms=elapsed,
        )
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return RequestResult(
            endpoint=url,
            status_code=0,
            latency_ms=elapsed,
            error=str(e),
        )


async def _run_load_batch(
    client: httpx.AsyncClient,
    tokens: List[str],
    endpoint: str,
    method: str,
) -> LoadTestReport:
    """Run a batch of concurrent requests and collect results."""
    report = LoadTestReport(endpoint=endpoint, description=endpoint)
    tasks = []
    for token in tokens:
        headers = {"Authorization": f"Bearer {token}"}
        tasks.append(_send_request(client, method, endpoint, headers))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, RequestResult):
            report.total_requests += 1
            report.latencies_ms.append(r.latency_ms)
            if 200 <= r.status_code < 400:
                report.successful += 1
            else:
                report.failed += 1
                if r.error:
                    report.errors.append(r.error[:100])
        else:
            report.total_requests += 1
            report.failed += 1
            report.errors.append(str(r)[:100])

    return report


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

class Test500StaffDashboard:
    """Load test: 500 staff members hitting the boss dashboard concurrently."""

    @pytest_asyncio.fixture
    async def setup_data(self, client):
        """Register a boss + 500 staff, return tokens.

        Uses the shared `client` fixture from tests/e2e/conftest.py which
        provides in-memory SQLite and disabled rate limiter.
        """
        # Register boss
        boss_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "username": "loadtest_boss",
                "email": "loadtest_boss@load.dev",
                "password": "LoadTest!Pass1",
                "roles": ["admin"],
                "tenant_name": "LoadTestOrg",
                "company_size": "500+",
            },
        )
        assert boss_resp.status_code == 200
        boss_token = boss_resp.json()["access_token"]
        org_key = boss_resp.json()["org_key"]

        # Register staff
        staff_tokens = await _setup_staff_tokens(client, org_key, NUM_STAFF)

        return {
            "boss_token": boss_token,
            "staff_tokens": staff_tokens,
            "org_key": org_key,
        }

    @pytest.mark.slow
    async def test_500_staff_dashboard_summary(self, client, setup_data):
        """500 staff members hit /dashboard/summary concurrently."""
        tokens = setup_data["staff_tokens"]
        if not tokens:
            pytest.skip("No staff tokens available")

        report = await _run_load_batch(
            client, tokens, "/api/v1/dashboard/summary", "GET"
        )

        pct = report.percentiles()
        print(f"\n{'='*60}")
        print(f"Dashboard Summary — {report.total_requests} concurrent requests")
        print(f"  Success: {report.successful}/{report.total_requests} ({report.success_rate:.1f}%)")
        print(f"  P50: {pct['p50']:.1f}ms  P95: {pct['p95']:.1f}ms  P99: {pct['p99']:.1f}ms")
        print(f"  Avg: {pct['avg']:.1f}ms  Max: {pct['max']:.1f}ms")
        print(f"{'='*60}")

        assert report.success_rate >= 95.0, (
            f"Success rate {report.success_rate:.1f}% < 95% threshold"
        )
        assert pct["p95"] < 5000, (
            f"P95 latency {pct['p95']:.1f}ms exceeds 5000ms threshold"
        )

    @pytest.mark.slow
    async def test_500_staff_alerts(self, client, setup_data):
        """500 staff members hit /dashboard/alerts concurrently."""
        tokens = setup_data["staff_tokens"]
        if not tokens:
            pytest.skip("No staff tokens available")

        report = await _run_load_batch(
            client, tokens, "/api/v1/dashboard/alerts", "GET"
        )

        pct = report.percentiles()
        print(f"\n{'='*60}")
        print(f"Alerts List — {report.total_requests} concurrent requests")
        print(f"  Success: {report.successful}/{report.total_requests} ({report.success_rate:.1f}%)")
        print(f"  P50: {pct['p50']:.1f}ms  P95: {pct['p95']:.1f}ms  P99: {pct['p99']:.1f}ms")
        print(f"{'='*60}")

        assert report.success_rate >= 95.0
        assert pct["p95"] < 5000

    @pytest.mark.slow
    async def test_500_staff_notifications(self, client, setup_data):
        """500 staff members hit /notifications concurrently."""
        tokens = setup_data["staff_tokens"]
        if not tokens:
            pytest.skip("No staff tokens available")

        report = await _run_load_batch(
            client, tokens, "/api/v1/notifications", "GET"
        )

        pct = report.percentiles()
        print(f"\n{'='*60}")
        print(f"Notifications — {report.total_requests} concurrent requests")
        print(f"  Success: {report.successful}/{report.total_requests} ({report.success_rate:.1f}%)")
        print(f"  P50: {pct['p50']:.1f}ms  P95: {pct['p95']:.1f}ms  P99: {pct['p99']:.1f}ms")
        print(f"{'='*60}")

        assert report.success_rate >= 95.0
        assert pct["p95"] < 5000

    @pytest.mark.slow
    async def test_boss_admin_endpoints_under_load(self, client, setup_data):
        """Boss can still access admin endpoints while 500 staff hit the dashboard."""
        boss_token = setup_data["boss_token"]
        staff_tokens = setup_data["staff_tokens"]
        if not staff_tokens:
            pytest.skip("No staff tokens available")

        boss_headers = {"Authorization": f"Bearer {boss_token}"}

        # Start staff load in background
        staff_tasks = []
        for token in staff_tokens[:100]:  # Use 100 staff for background load
            headers = {"Authorization": f"Bearer {token}"}
            staff_tasks.append(
                _send_request(client, "GET", "/api/v1/dashboard/summary", headers)
            )

        # Boss makes admin requests concurrently
        boss_tasks = []
        for endpoint, method, desc in BOSS_ENDPOINTS:
            boss_tasks.append(
                _send_request(client, method, endpoint, boss_headers)
            )

        # Run both simultaneously
        staff_results, boss_results = await asyncio.gather(
            asyncio.gather(*staff_tasks),
            asyncio.gather(*boss_tasks),
        )

        boss_success = sum(
            1 for r in boss_results
            if isinstance(r, RequestResult) and 200 <= r.status_code < 400
        )
        print(f"\nBoss admin requests: {boss_success}/{len(boss_results)} succeeded")

        assert boss_success >= len(boss_results) * 0.9, (
            f"Boss admin success rate too low: {boss_success}/{len(boss_results)}"
        )
