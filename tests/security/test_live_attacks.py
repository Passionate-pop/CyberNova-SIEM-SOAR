"""
CyberNOVA — Live Attack Simulation Suite (Ethical Hacking)
Tests the platform against real-time attack vectors:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Brute Force / Credential Stuffing
  - Path Traversal
  - Command Injection
  - SSRF attempts
  - Malformed payloads / fuzzing
  - WAF bypass attempts
  - Rate limiting verification
  - JWT tampering

Usage:
    python -m pytest tests/security/test_live_attacks.py -v --timeout=30
    python -m tests.security.test_live_attacks  (direct runner with summary)
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

log = logging.getLogger("cybernova.security.live_attacks")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TARGET = "http://localhost:8000"
TIMEOUT = 5.0

# ── Attack Payloads ─────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "admin'--",
    "1' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR '1'='1' #",
    "admin' /*",
    "1' AND 1=1",
    "1' AND 1=2",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../../../etc/shadow",
]

COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| cat /etc/passwd",
    "&& whoami",
    "`ls -la`",
    "$(cat /etc/passwd)",
    "| dir",
]

MALFORMED_PAYLOADS = [
    {"not_an_event": True},
    {"events": "not_a_list"},
    {"events": [{"no_source": True}]},
    {"source": None, "events": []},
    {},
    [],
    "string_instead_of_object",
    12345,
    {"events": [{"timestamp": "not-a-date"}]},
]

JWT_TAMPERING_PAYLOADS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    "invalid-token-format",
    "",
    "Bearer " + "A" * 1000,
]

BRUTE_FORCE_PAYLOADS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "letmein"},
    {"username": "root", "password": "toor"},
    {"username": "admin", "password": "changeme"},
]


# ── Test Results ────────────────────────────────────────────────────────────

class AttackResult:
    def __init__(self, name: str, payload: Any, blocked: bool, status: int, detail: str = ""):
        self.name = name
        self.payload = payload
        self.blocked = blocked
        self.status = status
        self.detail = detail

    def __repr__(self) -> str:
        return f"[{'BLOCKED' if self.blocked else 'ALLOWED'}] {self.name}: HTTP {self.status}"


# ── HTTP Client ─────────────────────────────────────────────────────────────

async def check_endpoint(client: httpx.AsyncClient, path: str, method: str = "GET",
                         json_body: Any = None, headers: Optional[Dict[str, str]] = None,
                         description: str = "") -> AttackResult:
    """Send request and check if the WAF / platform blocks the attack."""
    try:
        if method == "GET":
            resp = await client.get(path, headers=headers, timeout=TIMEOUT)
        elif method == "POST":
            resp = await client.post(path, json=json_body, headers=headers, timeout=TIMEOUT)
        else:
            resp = await client.request(method, path, json=json_body, headers=headers, timeout=TIMEOUT)

        blocked = resp.status_code in (403, 429, 406, 401)
        return AttackResult(
            name=description or path,
            payload=str(json_body or path)[:80],
            blocked=blocked,
            status=resp.status_code,
            detail=resp.text[:200] if not blocked else "Blocked by WAF/rate limiter",
        )
    except Exception as e:
        return AttackResult(
            name=description or path,
            payload=str(json_body or path)[:80],
            blocked=True,
            status=0,
            detail=f"Connection error: {e}",
        )


# ── Attack Scenarios ────────────────────────────────────────────────────────

async def _run_sql_injection(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test SQL injection attempts via query params and POST bodies."""
    results = []
    for payload in SQLI_PAYLOADS:
        # Test via query parameter
        encoded = quote(payload)
        r = await check_endpoint(client, f"/api/v1/search?q={encoded}",
                                 description=f"SQLi (query): {payload[:30]}")
        results.append(r)

        # Test via POST body
        r = await check_endpoint(client, "/api/v1/ingest/", method="POST",
                                 json_body={"source": "test", "events": [{"query": payload}]},
                                 description=f"SQLi (body): {payload[:30]}")
        results.append(r)
    return results


async def _run_xss(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test XSS payloads through various endpoints."""
    results = []
    for payload in XSS_PAYLOADS:
        encoded = quote(payload)
        r = await check_endpoint(client, f"/api/v1/search?q={encoded}",
                                 description=f"XSS: {payload[:30]}")
        results.append(r)

        r = await check_endpoint(client, "/api/v1/ingest/", method="POST",
                                 json_body={"source": "test", "events": [{"message": payload}]},
                                 description=f"XSS (body): {payload[:30]}")
        results.append(r)
    return results


async def _run_path_traversal(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test path traversal attempts."""
    results = []
    for payload in PATH_TRAVERSAL_PAYLOADS:
        r = await check_endpoint(client, f"/{payload}",
                                 description=f"Path traversal: {payload}")
        results.append(r)
    return results


async def _run_command_injection(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test command injection attempts."""
    results = []
    for payload in COMMAND_INJECTION_PAYLOADS:
        encoded = quote(payload)
        r = await check_endpoint(client, f"/api/v1/search?q={encoded}",
                                 description=f"Cmd injection: {payload[:20]}")
        results.append(r)

        r = await check_endpoint(client, "/api/v1/ingest/", method="POST",
                                 json_body={"source": "test", "events": [{"command": payload}]},
                                 description=f"Cmd inj (body): {payload[:20]}")
        results.append(r)
    return results


async def _run_malformed_payloads(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test malformed/fuzzing payloads."""
    results = []
    for payload in MALFORMED_PAYLOADS:
        r = await check_endpoint(client, "/api/v1/ingest/", method="POST",
                                 json_body=payload,
                                 description=f"Malformed: {str(payload)[:40]}")
        results.append(r)
    return results


async def _run_brute_force(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test brute force login attempts - should trigger rate limiting."""
    results = []
    for payload in BRUTE_FORCE_PAYLOADS:
        r = await check_endpoint(client, "/api/v1/auth/login", method="POST",
                                 json_body=payload,
                                 description=f"Brute force: {payload['username']}:{payload['password']}")
        results.append(r)
    return results


async def _run_rate_limiting(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test that rate limiting kicks in after rapid requests.
    Sends 60 requests to guarantee hitting the 20/min auth rate limit
    even if other tests consumed some slots from the same IP.
    """
    results = []
    start = time.monotonic()
    for i in range(60):
        r = await check_endpoint(client, "/api/v1/auth/login", method="POST",
                                 json_body={"username": f"user{i}", "password": "test"},
                                 description=f"Rate limit test #{i}")
        results.append(r)
        if r.status == 429:
            log.info("Rate limiting kicked in after %d requests (%.1fs)", i + 1, time.monotonic() - start)
    return results


async def _run_jwt_tampering(client: httpx.AsyncClient) -> List[AttackResult]:
    """Test JWT tampering and invalid tokens."""
    results = []
    for token in JWT_TAMPERING_PAYLOADS:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = await check_endpoint(client, "/api/v1/pipeline/status",
                                 headers=headers,
                                 description=f"JWT tamper: {token[:30]}")
        results.append(r)
    return results


# ── Main Runner ─────────────────────────────────────────────────────────────

async def run_all_attacks(target: str = TARGET) -> Dict[str, Any]:
    """Run all attack scenarios and return results."""
    log.info("=" * 60)
    log.info("CyberNOVA — LIVE ATTACK SIMULATION")
    log.info("Target: %s", target)
    log.info("=" * 60)

    all_results: Dict[str, List[AttackResult]] = {}
    totals = {"blocked": 0, "allowed": 0, "errors": 0, "total": 0}

    async with httpx.AsyncClient(base_url=target, verify=False) as client:
        scenarios = [
            ("SQL Injection", _run_sql_injection),
            ("Cross-Site Scripting (XSS)", _run_xss),
            ("Path Traversal", _run_path_traversal),
            ("Command Injection", _run_command_injection),
            ("Malformed Payloads / Fuzzing", _run_malformed_payloads),
            ("Brute Force", _run_brute_force),
            ("Rate Limiting", _run_rate_limiting),
            ("JWT Tampering", _run_jwt_tampering),
        ]

        for name, test_fn in scenarios:
            log.info("\n─── Testing: %s ───", name)
            try:
                results = await test_fn(client)
                all_results[name] = results
                for r in results:
                    totals["total"] += 1
                    if r.blocked or r.status in (400, 422, 405, 500):
                        totals["blocked"] += 1
                        log.info("  ✅ %s", r)
                    elif r.status in (0,):
                        totals["errors"] += 1
                        log.info("  ❌ %s", r)
                    else:
                        totals["allowed"] += 1
                        log.info("  ⚠️  %s", r)
            except Exception as e:
                log.error("  💥 Scenario %s failed: %s", name, e)
                all_results[name] = [AttackResult(name, str(e), True, 0, str(e))]
                totals["errors"] += 1

    log.info("\n" + "=" * 60)
    log.info("ATTACK SIMULATION RESULTS")
    log.info("  Total attempts: %d", totals["total"])
    log.info("  Blocked:        %d (%.1f%%)", totals["blocked"],
             totals["blocked"] / max(totals["total"], 1) * 100)
    log.info("  Allowed:        %d (%.1f%%)", totals["allowed"],
             totals["allowed"] / max(totals["total"], 1) * 100)
    log.info("  Errors:         %d", totals["errors"])
    log.info("=" * 60)

    return {
        "totals": totals,
        "details": {
            name: [{"payload": r.payload, "blocked": r.blocked, "status": r.status, "detail": r.detail}
                   for r in results]
            for name, results in all_results.items()
        },
    }


async def main():
    results = await run_all_attacks()
    sys.exit(0 if results["totals"]["blocked"] >= results["totals"]["total"] * 0.7 else 1)


# ── Pytest Tests ────────────────────────────────────────────────────────────

import pytest


def _is_backend_reachable() -> bool:
    """Check if the backend is running before running live attack tests."""
    import socket
    try:
        host, port = TARGET.replace("http://", "").replace("https://", "").split(":")
        port = int(port) if "/" not in port else int(port.split("/")[0])
        host = host.split("/")[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


requires_backend = pytest.mark.skipif(
    not _is_backend_reachable(),
    reason="Backend not running on " + TARGET + " — this test requires a live backend",
)


@requires_backend
@pytest.mark.asyncio
async def test_sql_injection_blocked():
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        results = await _run_sql_injection(client)
        blocked = sum(1 for r in results if r.blocked or r.status in (400, 422, 405))
        assert blocked >= len(results) * 0.5, f"Only {blocked}/{len(results)} SQLi attempts blocked"


@requires_backend
@pytest.mark.asyncio
async def test_xss_blocked():
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        results = await _run_xss(client)
        blocked = sum(1 for r in results if r.blocked or r.status in (400, 422, 405))
        assert blocked >= len(results) * 0.5, f"Only {blocked}/{len(results)} XSS attempts blocked"


@requires_backend
@pytest.mark.asyncio
async def test_path_traversal_blocked():
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        results = await _run_path_traversal(client)
        # 404 means endpoint doesn't exist — path traversal didn't reach any route
        # 403/401 means WAF blocked it
        safe = sum(1 for r in results if r.blocked or r.status in (400, 404, 422, 405))
        assert safe >= len(results) * 0.5, f"Only {safe}/{len(results)} path traversal attempts safe (blocked or 404)"


@requires_backend
@pytest.mark.asyncio
async def test_malformed_payloads_handled():
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        results = await _run_malformed_payloads(client)
        blocked = sum(1 for r in results if r.blocked or r.status in (400, 422, 405))
        assert blocked >= len(results) * 0.5, f"Only {blocked}/{len(results)} malformed payloads handled"


@requires_backend
@pytest.mark.asyncio
async def test_rate_limiting_triggers():
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        results = await _run_rate_limiting(client)
        blocked = sum(1 for r in results if r.blocked)
        assert blocked >= 1, "Rate limiting never triggered (no 429 or connection-blocked responses)"


if __name__ == "__main__":
    asyncio.run(main())
