"""
CyberNOVA — Real-World Attacker Simulation (Advanced Penetration Test)
======================================================================
Tests the platform like a real adversary, going beyond standard automated
scans to include sophisticated multi-vector attacks:

  - JWT attacks: alg=none, KID injection, expired/forged tokens
  - IDOR & privilege escalation: tenant hopping, role manipulation, forced browsing
  - NoSQL injection, SSTI, CRLF injection, header injection
  - Business logic flaws: race conditions, mass assignment, parameter pollution
  - WAF bypass: Unicode normalization, case variations, comment injection, encodings
  - Information disclosure: debug endpoints, version leaks, verbose errors
  - SSRF & internal network probing: URL scheme abuse, host header injection
  - CORS/CSRF misconfiguration testing
  - API abuse: pagination fishing, mass enumeration, rate limit behavior analysis
  - Supply chain: malicious package upload attempts

Usage:
    python -m pytest tests/security/test_real_world_attacker.py -v --timeout=120
    python tests/security/test_real_world_attacker.py  (direct runner)
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import secrets
import string
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

log = logging.getLogger("cybernova.security.real_world_attacker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TARGET = "http://localhost:8000"
TIMEOUT = 15.0

# ── Severity levels ─────────────────────────────────────────────────────
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"


# ── Finding Representation ──────────────────────────────────────────────

class Finding:
    """Represents a penetration test finding."""

    def __init__(
        self,
        category: str,
        name: str,
        severity: str,
        description: str,
        affected_endpoint: str,
        payload: str = "",
        status_code: int = 0,
        evidence: str = "",
        remediation: str = "",
    ):
        self.category = category
        self.name = name
        self.severity = severity
        self.description = description
        self.affected_endpoint = affected_endpoint
        self.payload = payload
        self.status_code = status_code
        self.evidence = evidence
        self.remediation = remediation

    def __repr__(self) -> str:
        status = "VULN" if self.severity in (SEV_CRITICAL, SEV_HIGH) else "INFO"
        return f"[{status}] [{self.severity}] {self.name} — {self.affected_endpoint}"

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "endpoint": self.affected_endpoint,
            "payload": self.payload[:200],
            "status_code": self.status_code,
            "evidence": self.evidence[:300],
            "remediation": self.remediation,
        }


# ── Helper ──────────────────────────────────────────────────────────────

def _random_string(length: int = 8) -> str:
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))


# ═════════════════════════════════════════════════════════════════════════
# 1. AUTHENTICATION ATTACKS
# ═════════════════════════════════════════════════════════════════════════

async def _test_jwt_alg_none(client: httpx.AsyncClient) -> List[Finding]:
    """Test JWT algorithm confusion — 'none' algorithm should be rejected."""
    findings = []
    # JWT with alg: none, no signature
    none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsInRlbmFudF9pZCI6InRlbmFudC0wMDEifQ."
    resp = await client.get(
        "/api/v1/pipeline/status",
        headers={"Authorization": f"Bearer {none_jwt}"},
        timeout=TIMEOUT,
    )
    if resp.status_code not in (401, 403):
        findings.append(Finding(
            category="Authentication",
            name="JWT alg=none Accepted",
            severity=SEV_CRITICAL,
            description="Server accepted a JWT with algorithm 'none' — attacker can forge arbitrary tokens",
            affected_endpoint="/api/v1/pipeline/status",
            payload=f"JWT: {none_jwt[:60]}...",
            status_code=resp.status_code,
            evidence=resp.text[:200],
            remediation="Reject tokens with alg: none. Configure JWT library to require a valid signature.",
        ))

    # JWT with modified algorithm — HS256 when public key is used
    # This tests if the server uses the public key for verification when alg is changed
    modified_header_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.dQw4w9WgXcQ"
    resp = await client.get(
        "/api/v1/pipeline/status",
        headers={"Authorization": f"Bearer {modified_header_jwt}"},
        timeout=TIMEOUT,
    )
    if resp.status_code not in (401, 403):
        findings.append(Finding(
            category="Authentication",
            name="JWT Algorithm Confusion",
            severity=SEV_CRITICAL,
            description="Server accepted JWT with algorithm confusion attack — possible key confusion vulnerability",
            affected_endpoint="/api/v1/pipeline/status",
            payload="HS256 alg JWT sent to RS256 endpoint",
            status_code=resp.status_code,
            evidence=resp.text[:200],
            remediation="Explicitly restrict accepted algorithms. Use asymmetric keys correctly.",
        ))
    return findings


async def _test_jwt_kid_injection(client: httpx.AsyncClient) -> List[Finding]:
    """Test JWT KID (Key ID) header injection — path traversal and SQLi."""
    findings = []

    # KID path traversal
    kid_payloads = [
        "../../../dev/null",
        "../../../etc/passwd",
        "/proc/self/environ",
        "|cat /etc/passwd",
    ]

    for kid in kid_payloads:
        # Craft JWT with malicious KID header
        header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9"  # KID: /dev/null
        payload_b64 = "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9"
        sig = "dQw4w9WgXcQ"  # doesn't matter for this test

        resp = await client.get(
            "/api/v1/pipeline/status",
            headers={"Authorization": f"Bearer {header_b64}.{payload_b64}.{sig}"},
            timeout=TIMEOUT,
        )
        if resp.status_code not in (401, 403, 500):
            findings.append(Finding(
                category="Authentication",
                name=f"JWT KID Injection - {kid[:20]}",
                severity=SEV_CRITICAL if kid == "/proc/self/environ" else SEV_HIGH,
                description=f"JWT KID header accepted with path: {kid}. May allow key bypass.",
                affected_endpoint="/api/v1/pipeline/status",
                payload=f"KID: {kid}",
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Validate KID against whitelist. Reject path traversal characters.",
            ))

    # Expired token acceptance
    expired_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMDAsInN1YiI6ImFkbWluIn0"
    resp = await client.get(
        "/api/v1/pipeline/status",
        headers={"Authorization": f"Bearer {expired_jwt}.invalidsig"},
        timeout=TIMEOUT,
    )
    # Check if error message reveals information
    if "expired" in resp.text.lower() or "exp" in resp.text.lower():
        findings.append(Finding(
            category="Authentication",
            name="Token Expiration Info Leak",
            severity=SEV_LOW,
            description="Server reveals token expiration details in error messages",
            affected_endpoint="/api/v1/pipeline/status",
            payload="Expired JWT",
            status_code=resp.status_code,
            evidence=resp.text[:200],
            remediation="Return generic 'unauthorized' for all token validation failures.",
        ))

    return findings


async def _test_password_spraying(client: httpx.AsyncClient) -> List[Finding]:
    """Test password spraying across multiple usernames with common passwords."""
    findings = []

    common_passwords = ["Password123!", "Welcome1", "Admin123!", "P@ssw0rd", "Summer2024"]
    usernames = ["admin", "root", "administrator", "demo", "test", "admin@cybernova.io"]

    spray_count = 0
    for username in usernames:
        for password in common_passwords:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": password},
                timeout=TIMEOUT,
            )
            spray_count += 1
            # 429 after threshold = good rate limiting
            if resp.status_code == 429:
                findings.append(Finding(
                    category="Authentication",
                    name="Password Spraying Rate-Limited",
                    severity=SEV_INFO,
                    description=f"Rate limiting triggered after {spray_count} password spray attempts — good",
                    affected_endpoint="/api/v1/auth/login",
                    payload=f"user={username}, attempts={spray_count}",
                    status_code=429,
                    evidence=resp.text[:200],
                    remediation="Rate limiting is working. Continue monitoring thresholds.",
                ))
                break
        else:
            continue
        break
    else:
        # No rate limiting triggered
        findings.append(Finding(
            category="Authentication",
            name="No Password Spray Rate Limit",
            severity=SEV_MEDIUM,
            description=f"No rate limiting detected after {spray_count} password spray attempts across {len(usernames)} users",
            affected_endpoint="/api/v1/auth/login",
            payload=f"{spray_count} attempts",
            status_code=200,
            evidence="No 429 responses received",
            remediation="Implement per-IP rate limiting on login endpoint. Consider account lockout policies.",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 2. AUTHORIZATION / PRIVILEGE ESCALATION
# ═════════════════════════════════════════════════════════════════════════

async def _test_idor_tenant_hopping(client: httpx.AsyncClient, auth_token: str) -> List[Finding]:
    """Test Insecure Direct Object References via tenant ID manipulation."""
    findings = []
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Try to access other tenants' data
    tenant_ids_to_test = ["tenant-001", "tenant-002", "default", "admin", "../../etc/passwd"]

    endpoints_to_test = [
        "/api/v1/admin/users/?tenant_id={}",
        "/api/v1/detect/alerts?tenant_id={}",
    ]

    for tenant_id in tenant_ids_to_test:
        for endpoint_template in endpoints_to_test:
            endpoint = endpoint_template.format(tenant_id)
            resp = await client.get(endpoint, headers=headers, timeout=TIMEOUT)
            # 200 with data from a different tenant = IDOR
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append(Finding(
                    category="Authorization",
                    name=f"Potential IDOR via tenant_id ({tenant_id})",
                    severity=SEV_HIGH,
                    description=f"Endpoint returned 200 with data when accessing tenant_id={tenant_id}",
                    affected_endpoint=endpoint,
                    payload=f"tenant_id={tenant_id}",
                    status_code=resp.status_code,
                    evidence=resp.text[:200],
                    remediation="Enforce tenant isolation in all queries. Validate tenant_id belongs to current user.",
                ))

    # Test forced browsing — admin endpoints as regular user
    admin_endpoints = [
        "/api/v1/admin/users/",
        "/api/v1/admin/devices/",
        "/api/v1/backup/create",
        "/api/v1/system/config",
    ]

    for endpoint in admin_endpoints:
        resp = await client.get(endpoint, headers=headers, timeout=TIMEOUT)
        # Access to admin endpoint is a finding regardless of auth
        if resp.status_code not in (401, 403, 404):
            findings.append(Finding(
                category="Authorization",
                name=f"Forced Browsing — {endpoint}",
                severity=SEV_HIGH,
                description=f"Admin endpoint {endpoint} accessible without admin privileges",
                affected_endpoint=endpoint,
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Implement proper RBAC checks on all admin endpoints.",
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 3. ADVANCED INJECTION
# ═════════════════════════════════════════════════════════════════════════

async def _test_nosql_injection(client: httpx.AsyncClient) -> List[Finding]:
    """Test NoSQL injection via JSON operators ($ne, $gt, $regex, $where)."""
    findings = []

    nosql_payloads = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": "admin", "password": {"$regex": ".*"}},
        {"username": {"$in": ["admin", "root"]}, "password": {"$exists": True}},
        {"$where": "sleep(5000)"},
        {"username": {"$ne": 1}, "password": {"$where": "1==1"}},
    ]

    for payload in nosql_payloads:
        resp = await client.post(
            "/api/v1/auth/login",
            json=payload,
            timeout=TIMEOUT,
        )
        # 200 or 5xx means NoSQLi might have worked
        if resp.status_code == 200:
            findings.append(Finding(
                category="Injection",
                name=f"NoSQL Injection — {str(payload)[:40]}",
                severity=SEV_CRITICAL,
                description="NoSQL injection payload returned 200 — possible authentication bypass",
                affected_endpoint="/api/v1/auth/login",
                payload=str(payload)[:100],
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Sanitize JSON input. Use parameterized queries. Reject MongoDB operators in auth fields.",
            ))
        elif resp.status_code >= 500:
            findings.append(Finding(
                category="Injection",
                name=f"NoSQL Injection — Server Error",
                severity=SEV_HIGH,
                description=f"NoSQL payload caused server error: {str(payload)[:40]}",
                affected_endpoint="/api/v1/auth/login",
                payload=str(payload)[:100],
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Validate and sanitize all JSON input. Use allowlist for expected fields.",
            ))

    return findings


async def _test_ssti_injection(client: httpx.AsyncClient) -> List[Finding]:
    """Test Server-Side Template Injection."""
    findings = []

    ssti_payloads = [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self._TemplateReference__context}}",
    ]

    for payload in ssti_payloads:
        encoded = quote(payload)
        endpoints = [
            f"/api/v1/search?q={encoded}",
            f"/api/v1/search/query",
        ]

        for endpoint in endpoints:
            if "query" in endpoint:
                resp = await client.post(endpoint, json={"query": payload}, timeout=TIMEOUT)
            else:
                resp = await client.get(endpoint, timeout=TIMEOUT)

            # Check if expression was evaluated
            if "49" in resp.text and "{{7*7}}" not in resp.text:
                findings.append(Finding(
                    category="Injection",
                    name=f"SSTI — {payload[:20]}",
                    severity=SEV_CRITICAL,
                    description=f"Template injection payload evaluated: {payload}",
                    affected_endpoint=endpoint,
                    payload=payload,
                    status_code=resp.status_code,
                    evidence=resp.text[:200],
                    remediation="Never render user input as templates. Use context-aware escaping.",
                ))

    return findings


async def _test_crlf_injection(client: httpx.AsyncClient) -> List[Finding]:
    """Test CRLF injection in headers and parameters."""
    findings = []

    crlf_payloads = [
        "test%0d%0aX-Injected:true",
        "test%0aInjected:true",
        "value\r\nX-Injected: injected",
        "test\nX-Injected: injected",
    ]

    for payload in crlf_payloads:
        resp = await client.get(
            f"/api/v1/search?q={quote(payload)}",
            timeout=TIMEOUT,
        )
        # Check response headers for injected header
        injected_headers = ["x-injected", "injected"]
        for hdr in resp.headers:
            if hdr.lower() in injected_headers:
                findings.append(Finding(
                    category="Injection",
                    name="CRLF Injection",
                    severity=SEV_CRITICAL,
                    description=f"CRLF injection succeeded — injected header '{hdr}' found in response",
                    affected_endpoint=f"/api/v1/search?q={quote(payload)[:30]}",
                    payload=payload[:50],
                    status_code=resp.status_code,
                    evidence=f"Header: {hdr}: {resp.headers[hdr]}",
                    remediation="Sanitize newline characters from all user input. Use proper header encoding.",
                ))
                break

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 4. API ABUSE & BUSINESS LOGIC
# ═════════════════════════════════════════════════════════════════════════

async def _test_pagination_abuse(client: httpx.AsyncClient, auth_token: str) -> List[Finding]:
    """Test pagination parameter abuse — trying to extract all data."""
    findings = []
    headers = {"Authorization": f"Bearer {auth_token}"}

    abuse_params = [
        {"limit": 100000, "page": 0},
        {"limit": -1, "page": 1},
        {"limit": "all", "page": 0},
        {"limit": 999999999, "page_size": 999999999},
        {"limit": None},
        {"cursor": "../../../etc/passwd"},
        {"offset": 99999999},
    ]

    for params in abuse_params:
        resp = await client.get(
            "/api/v1/detect/alerts",
            params=params,
            headers=headers,
            timeout=TIMEOUT,
        )
        # Large response or 500 = finding
        if resp.status_code >= 500:
            findings.append(Finding(
                category="API Abuse",
                name=f"Pagination Abuse — Server Error",
                severity=SEV_MEDIUM,
                description=f"Pagination parameter caused server error: {params}",
                affected_endpoint="/api/v1/detect/alerts",
                payload=str(params),
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Set sane limits on pagination parameters. Validate range of all numeric inputs.",
            ))
        elif resp.status_code == 200 and len(resp.content) > 100000:
            findings.append(Finding(
                category="API Abuse",
                name="Excessive Data Exposure via Pagination",
                severity=SEV_MEDIUM,
                description=f"Pagination parameters returned {len(resp.content)} bytes of data. Potential data leak.",
                affected_endpoint="/api/v1/detect/alerts",
                payload=str(params),
                status_code=resp.status_code,
                evidence=f"Response size: {len(resp.content)} bytes",
                remediation="Enforce maximum page size. Implement cursor-based pagination with hard limits.",
            ))

    return findings


async def _test_mass_assignment(client: httpx.AsyncClient) -> List[Finding]:
    """Test mass assignment — trying to set protected fields via API."""
    findings = []

    sensitive_fields = [
        {"is_admin": True},
        {"role": "admin"},
        {"roles": ["admin", "superadmin"]},
        {"is_superuser": True},
        {"permissions": ["*"]},
        {"tenant_id": "tenant-other"},
        {"password": "newpassword123", "password_confirmation": "newpassword123"},
        {"email_verified": True},
    ]

    # Try registering with extra fields
    for extra_fields in sensitive_fields:
        registration = {
            "username": f"mass_assign_{_random_string(4)}",
            "email": f"mass_assign_{_random_string(4)}@test.com",
            "password": "TestPass123!",
        }
        registration.update(extra_fields)

        resp = await client.post(
            "/api/v1/auth/register",
            json=registration,
            timeout=TIMEOUT,
        )
        # Check if registration succeeded with elevated privileges
        if resp.status_code in (200, 201):
            data = resp.json()
            for key in extra_fields:
                if key in data and data[key] == extra_fields[key]:
                    findings.append(Finding(
                        category="API Abuse",
                        name=f"Mass Assignment — {key}",
                        severity=SEV_CRITICAL,
                        description=f"User registered with protected field '{key}' set to '{extra_fields[key]}'",
                        affected_endpoint="/api/v1/auth/register",
                        payload=str(extra_fields)[:100],
                        status_code=resp.status_code,
                        evidence=f"Response contained {key}: {data.get(key)}",
                        remediation="Use DTOs/request schemas that whitelist allowed fields. Never directly bind request body to models.",
                    ))

    return findings


async def _test_race_condition(client: httpx.AsyncClient) -> List[Finding]:
    """Test race conditions on key endpoints."""
    findings = []

    # Fire concurrent registration requests with same username
    test_username = f"race_{_random_string(4)}"
    registration = {
        "username": test_username,
        "email": f"{test_username}@test.com",
        "password": "TestPass123!",
    }

    # Send 5 concurrent requests
    async def _register():
        try:
            return await client.post("/api/v1/auth/register", json=registration, timeout=TIMEOUT)
        except Exception:
            return None

    tasks = [_register() for _ in range(5)]
    responses = await asyncio.gather(*tasks)

    success_count = sum(1 for r in responses if r is not None and r.status_code in (200, 201))
    if success_count > 1:
        findings.append(Finding(
            category="Business Logic",
            name="Race Condition — Duplicate Registration",
            severity=SEV_HIGH,
            description=f"Multiple concurrent registrations succeeded for same username ({success_count}x). Possible race condition.",
            affected_endpoint="/api/v1/auth/register",
            payload=f"username={test_username}",
            status_code=200,
            evidence=f"{success_count} registrations succeeded for {test_username}",
            remediation="Use unique constraints with proper transaction isolation. Implement optimistic locking.",
        ))
    elif success_count > 0:
        findings.append(Finding(
            category="Business Logic",
            name="Race Condition Test — Clean",
            severity=SEV_INFO,
            description=f"No race condition detected — only {success_count} registration succeeded",
            affected_endpoint="/api/v1/auth/register",
            evidence=f"Attempted 5 concurrent registrations, {success_count} succeeded",
            remediation="No action needed — race condition handling appears adequate.",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 5. WAF BYPASS TECHNIQUES
# ═════════════════════════════════════════════════════════════════════════

async def _test_waf_bypass(client: httpx.AsyncClient) -> List[Finding]:
    """Test various WAF bypass techniques."""
    findings = []

    # SQLi bypass payloads
    sqli_bypasses = [
        "'/**/OR/**/1=1--",
        "'/**/UNION/**/SELECT/**/1,2,3--",
        "'%25u006f%25u0072%25u00201=1--",
        "'OR+1=1--",  # URL-encoded space
        "'||1=1||",
        "'/*!or*/1=1--",
        "'\\x6f\\x72 1=1--",  # Hex encoding 'or'
        "1' AND 1=1 AND '%'='",
        "'OR 1=1 LIMIT 1--",
        "'OR '1'='1' /*!50000 UNION */ SELECT 1,2,3--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(0))A) --",
        "' OR '1'='1' ORDER BY 1--",
    ]

    for payload in sqli_bypasses:
        encoded = quote(payload)
        resp = await client.get(f"/api/v1/search?q={encoded}", timeout=TIMEOUT)
        # 200 with data = bypass possible
        if resp.status_code == 200 and len(resp.text) > 50:
            findings.append(Finding(
                category="WAF Bypass",
                name=f"SQLi WAF Bypass — {payload[:25]}",
                severity=SEV_CRITICAL,
                description=f"WAF bypass payload returned 200: {payload[:40]}",
                affected_endpoint=f"/api/v1/search?q={encoded[:30]}",
                payload=payload[:80],
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Use parameterized queries on the backend. WAF should not be sole defense.",
            ))

    # XSS bypass payloads
    xss_bypasses = [
        "<ScRiPt>alert(1)</sCriPt>",
        "<img src=x onerror=alert(1)//",
        "<img src=x onerror=alert(1)><!--",
        "javascript:/*</title></style></textarea></script>*/alert(1)",
        "<svg/onload=alert(1)>",
        "<body/onload=alert(1)>",
        "'';!--\"<XSS>=&{()}",
        "<IMG SRC=\"javascript:alert('XSS');\">",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG \"\"\"><script>alert(\"XSS\")</script>\">",
        "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
        "<a onmouseover=alert(document.cookie)>xxs link</a>",
    ]

    for payload in xss_bypasses:
        encoded = quote(payload)
        resp = await client.get(f"/api/v1/search?q={encoded}", timeout=TIMEOUT)
        if resp.status_code == 200 and payload[:20].lower().replace("<","") in resp.text.lower():
            findings.append(Finding(
                category="WAF Bypass",
                name=f"XSS WAF Bypass — {payload[:20]}",
                severity=SEV_CRITICAL,
                description=f"XSS payload reflected in response without sanitization",
                affected_endpoint=f"/api/v1/search?q={encoded[:30]}",
                payload=payload[:80],
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Implement output encoding. Use Content-Security-Policy headers. WAF is not sufficient.",
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 6. INFORMATION DISCLOSURE
# ═════════════════════════════════════════════════════════════════════════

async def _test_information_disclosure(client: httpx.AsyncClient) -> List[Finding]:
    """Test for information disclosure vulnerabilities."""
    findings = []

    # Check security headers
    resp = await client.get("/", timeout=TIMEOUT)
    security_headers = {
        "strict-transport-security": "HSTS header missing",
        "x-content-type-options": "MIME-sniffing protection missing",
        "x-frame-options": "Clickjacking protection missing",
        "x-xss-protection": "XSS filter header missing",
        "content-security-policy": "CSP header missing",
    }

    for header, desc in security_headers.items():
        if header not in resp.headers:
            findings.append(Finding(
                category="Information Disclosure",
                name=f"Missing Security Header — {header}",
                severity=SEV_LOW,
                description=desc,
                affected_endpoint="/",
                status_code=resp.status_code,
                remediation=f"Add the '{header}' HTTP response header.",
            ))

    # Try common debug/disclosure endpoints
    discovery_paths = [
        "/.env",
        "/debug",
        "/api/docs",
        "/api/openapi.json",
        "/api/redoc",
        "/swagger.json",
        "/.git/config",
        "/.git/HEAD",
        "/admin/",
        "/console",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/metrics",
        "/health",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
    ]

    for path in discovery_paths:
        resp = await client.get(path, timeout=TIMEOUT)
        if resp.status_code == 200 and len(resp.text) > 50:
            findings.append(Finding(
                category="Information Disclosure",
                name=f"Sensitive Endpoint Exposed — {path}",
                severity=SEV_MEDIUM,
                description=f"Endpoint {path} returned 200 with data — may leak sensitive configuration",
                affected_endpoint=path,
                status_code=resp.status_code,
                evidence=resp.text[:200],
                remediation="Remove or restrict access to debug/info endpoints in production.",
            ))

    # Check for verbose error messages
    error_payloads = [
        {"not_a_field": "test"},
        "not json",
        None,
        {"username": 1, "password": 2, "email": 3},
        {"a": "b", "c": "d", "e": "f", "g": "h"},
    ]

    for payload in error_payloads:
        resp = await client.post(
            "/api/v1/auth/register",
            json=payload if isinstance(payload, dict) else None,
            headers={"Content-Type": "application/json"} if not isinstance(payload, str) else {"Content-Type": "text/plain"},
            content=json.dumps(payload) if isinstance(payload, dict) else str(payload) if not isinstance(payload, type(None)) else b"",
            timeout=TIMEOUT,
        )
        body = resp.text.lower()
        # Check for stack traces in response
        if any(pat in body for pat in ["traceback", "file \"", "line ", "stacktrace", "at "]):
            findings.append(Finding(
                category="Information Disclosure",
                name="Verbose Error Messages",
                severity=SEV_HIGH,
                description=f"Error response contains stack trace or verbose error details",
                affected_endpoint="/api/v1/auth/register",
                payload=str(payload)[:50],
                status_code=resp.status_code,
                evidence=resp.text[:300],
                remediation="Configure global exception handler to return generic error messages. Log full details server-side.",
            ))

    # Check CORS configuration
    resp = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
        },
        timeout=TIMEOUT,
    )
    cors_origin = resp.headers.get("access-control-allow-origin", "")
    if cors_origin == "*" or "evil.com" in cors_origin:
        findings.append(Finding(
            category="Information Disclosure",
            name="CORS Misconfiguration",
            severity=SEV_MEDIUM,
            description=f"CORS allows arbitrary origins: {cors_origin}",
            affected_endpoint="/api/v1/auth/login",
            status_code=resp.status_code,
            evidence=f"Origin: {cors_origin}",
            remediation="Restrict CORS to trusted origins. Do not use wildcard for credentialed requests.",
        ))

    # Server version disclosure
    server_header = resp.headers.get("server", "")
    if server_header and any(
        pat in server_header.lower() for pat in ["uvicorn", "fastapi", "python", "nginx/", "apache"]
    ):
        findings.append(Finding(
            category="Information Disclosure",
            name="Server Version Disclosure",
            severity=SEV_LOW,
            description=f"Server header reveals technology: {server_header}",
            affected_endpoint="/",
            status_code=resp.status_code,
            evidence=f"Server: {server_header}",
            remediation="Configure server to remove or obfuscate version info in Server header.",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 7. SSRF & INTERNAL NETWORK PROBING
# ═════════════════════════════════════════════════════════════════════════

async def _test_ssrf_probing(client: httpx.AsyncClient, auth_token: str) -> List[Finding]:
    """Test Server-Side Request Forgery via various input points."""
    findings = []
    headers = {"Authorization": f"Bearer {auth_token}"}

    ssrf_payloads = [
        {"url": "http://169.254.169.254/latest/meta-data/"},  # AWS metadata
        {"url": "http://metadata.google.internal/"},           # GCP metadata
        {"url": "http://127.0.0.1:5432"},                      # Local PostgreSQL
        {"url": "http://127.0.0.1:6379"},                      # Local Redis
        {"url": "http://127.0.0.1:8000/health"},               # Self
        {"url": "file:///etc/passwd"},                          # File protocol
        {"url": "http://localhost:5432"},                       # Local DB
        {"url": "dict://127.0.0.1:6379/info"},                  # Dict protocol for Redis
        {"url": "gopher://127.0.0.1:6379/_INFO"},               # Gopher protocol
        {"url": "http://[::1]:8000/health"},                    # IPv6 localhost
        {"url": "http://0.0.0.0:8000/health"},                 # Zero address
        {"url": "http://10.0.0.1/"},                            # Private subnet
        {"url": "http://192.168.1.1/"},                         # Private subnet
    ]

    for payload in ssrf_payloads:
        # Try injecting in various endpoints
        endpoints_payloads = [
            ("POST", "/api/v1/ingest/", {"source": "webhook", "events": [{"url": payload["url"]}]}),
            ("POST", "/api/v1/ai/ask", {"query": f"Check status of {payload['url']}"}),
        ]

        for method, endpoint, body in endpoints_payloads:
            try:
                resp = await client.request(
                    method, endpoint, json=body, headers=headers, timeout=TIMEOUT
                )
                # Check for clues that SSRF worked
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(pat in body_lower for pat in ["meta-data", "ami-id", "root", "docker"]):
                        findings.append(Finding(
                            category="SSRF",
                            name=f"SSRF to {payload['url'][:30]}",
                            severity=SEV_CRITICAL,
                            description=f"SSRF attempt to {payload['url']} returned data indicating success",
                            affected_endpoint=endpoint,
                            payload=payload["url"],
                            status_code=200,
                            evidence=resp.text[:300],
                            remediation="Block access to private/internal IP ranges. Validate and restrict outbound URLs.",
                        ))
            except Exception as e:
                findings.append(Finding(
                    category="SSRF",
                    name=f"SSRF Connection Issue",
                    severity=SEV_INFO,
                    description=f"SSRF probe caused exception: {e}",
                    affected_endpoint=endpoint,
                    payload=payload["url"][:50],
                    evidence=str(e)[:200],
                    remediation="Investigate — exception may indicate server-side request was attempted.",
                ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# 8. RATE LIMIT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════

async def _test_rate_limit_analysis(client: httpx.AsyncClient) -> List[Finding]:
    """Analyze rate limiting behavior in detail."""
    findings = []

    # Find the exact rate limit threshold
    start = time.time()
    request_times = []
    for i in range(100):
        t = time.time()
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": f"ratelimit_user_{i}", "password": "test"},
            timeout=TIMEOUT,
        )
        request_times.append(time.time() - t)

        if resp.status_code == 429:
            rate_limit_window = time.time() - start
            retry_after = resp.headers.get("retry-after", "unknown")
            findings.append(Finding(
                category="Rate Limiting",
                name="Rate Limit Threshold Identified",
                severity=SEV_INFO,
                description=f"Rate limiting triggered after {i+1} requests in {rate_limit_window:.1f}s. Retry-After: {retry_after}",
                affected_endpoint="/api/v1/auth/login",
                status_code=429,
                evidence=f"Requests before limit: {i+1}, Window: {rate_limit_window:.1f}s, Retry-After: {retry_after}",
                remediation=f"Current threshold: {i+1} req/window. Adjust based on expected traffic patterns.",
            ))

            # Check if rate limit is IP-based (bypassable via X-Forwarded-For)
            resp2 = await client.post(
                "/api/v1/auth/login",
                json={"username": "test_bypass", "password": "test"},
                headers={"X-Forwarded-For": "10.0.0.1"},
                timeout=TIMEOUT,
            )
            if resp2.status_code != 429:
                findings.append(Finding(
                    category="Rate Limiting",
                    name="Rate Limit Bypass via X-Forwarded-For",
                    severity=SEV_HIGH,
                    description="Rate limit can be bypassed by changing X-Forwarded-For header",
                    affected_endpoint="/api/v1/auth/login",
                    payload="X-Forwarded-For: 10.0.0.1",
                    status_code=resp2.status_code,
                    evidence="Request with spoofed X-Forwarded-For was not rate limited",
                    remediation="Use actual client IP (not header-based) for rate limiting. Or track header consistently.",
                ))
            break

    # Test if different endpoints share rate limits
    resp1 = await client.get("/api/v1/pipeline/status", timeout=TIMEOUT)
    resp2 = await client.get("/api/v1/search?q=test", timeout=TIMEOUT)

    if resp1.status_code == 429 or resp2.status_code == 429:
        findings.append(Finding(
            category="Rate Limiting",
            name="Global Rate Limit",
            severity=SEV_LOW,
            description="Rate limiting appears to be global across endpoints (get and post endpoints share limit)",
            affected_endpoint="/api/v1/pipeline/status",
            status_code=resp1.status_code,
            evidence=f"GET /api/v1/pipeline/status: {resp1.status_code}, GET /api/v1/search: {resp2.status_code}",
            remediation="Consider per-endpoint rate limits rather than global limits.",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════
# MAIN EXECUTOR
# ═════════════════════════════════════════════════════════════════════════

async def authenticate(register: bool = True) -> Tuple[Optional[str], Optional[str]]:
    """Get an authentication token for testing — tries login then register."""
    async with httpx.AsyncClient(base_url=TARGET, timeout=TIMEOUT) as client:
        # Try login with default creds
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        if login_resp.status_code == 200:
            data = login_resp.json()
            log.info("[OK] Authenticated as admin")
            return data.get("access_token"), data.get("refresh_token")

        # Try registration
        if register:
            test_user = f"pentest_{_random_string(6)}"
            reg_resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": test_user,
                    "email": f"{test_user}@cybernova.pentest",
                    "password": "Pentest123!",
                },
            )
            if reg_resp.status_code in (200, 201):
                data = reg_resp.json()
                log.info("[OK] Registered test user: %s", test_user)
                return data.get("access_token"), data.get("refresh_token")

        log.warning("[!] Authentication failed — running unauthenticated tests only")
        return None, None


async def run_all_attacks() -> Dict[str, Any]:
    """Execute all real-world attacker scenarios."""
    log.info("=" * 70)
    log.info("  CYBERNOVA — REAL-WORLD ATTACKER SIMULATION")
    log.info("  Target: %s", TARGET)
    log.info("  Time:   %s", datetime.now(timezone.utc).isoformat())
    log.info("=" * 70)

    auth_token, refresh_token = await authenticate()

    all_findings: List[Finding] = []
    attack_phases: List[Tuple[str, Any]] = []

    authenticated_scenarios = [
        ("IDOR / Tenant Hopping", _test_idor_tenant_hopping),
        ("Pagination Abuse", _test_pagination_abuse),
        ("SSRF Probing", _test_ssrf_probing),
    ]

    unauthenticated_scenarios = [
        ("JWT alg=none Attack", _test_jwt_alg_none),
        ("JWT KID Injection", _test_jwt_kid_injection),
        ("Password Spraying", _test_password_spraying),
        ("NoSQL Injection", _test_nosql_injection),
        ("SSTI Injection", _test_ssti_injection),
        ("CRLF Injection", _test_crlf_injection),
        ("WAF Bypass Techniques", _test_waf_bypass),
        ("Information Disclosure", _test_information_disclosure),
        ("Rate Limit Analysis", _test_rate_limit_analysis),
        ("Mass Assignment", _test_mass_assignment),
        ("Race Condition", _test_race_condition),
    ]

    # Run unauthenticated scenarios
    for name, test_fn in unauthenticated_scenarios:
        log.info("\n─── [UNAUTH] %s ───", name)
        async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
            try:
                findings = await test_fn(client)
                all_findings.extend(findings)
                for f in findings:
                    log.info("  %s [%s] %s", f"✅ FOUND" if f.severity in (SEV_CRITICAL, SEV_HIGH) else "ℹ️  INFO", f.severity, f.name)
                if not findings:
                    log.info("  ✅ No vulnerabilities found")
            except Exception as e:
                log.error("  💥 Scenario failed: %s", e)

    # Run authenticated scenarios
    if auth_token:
        for name, test_fn in authenticated_scenarios:
            log.info("\n─── [AUTH] %s ───", name)
            async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
                try:
                    findings = await test_fn(client, auth_token)
                    all_findings.extend(findings)
                    for f in findings:
                        log.info("  %s [%s] %s", "✅ FOUND" if f.severity in (SEV_CRITICAL, SEV_HIGH) else "ℹ️  INFO", f.severity, f.name)
                    if not findings:
                        log.info("  ✅ No vulnerabilities found")
                except Exception as e:
                    log.error("  💥 Scenario failed: %s", e)
    else:
        log.info("\n─── [AUTH] Skipping authenticated scenarios (no token) ───")

    # Compile results
    vuln_count = sum(1 for f in all_findings if f.severity in (SEV_CRITICAL, SEV_HIGH))
    info_count = sum(1 for f in all_findings if f.severity in (SEV_MEDIUM, SEV_LOW, SEV_INFO))

    log.info("\n" + "=" * 70)
    log.info("  PENETRATION TEST RESULTS")
    log.info("=" * 70)
    log.info("  Total scenarios run:    %d", len(unauthenticated_scenarios) + len(authenticated_scenarios))
    log.info("  Vulnerabilities found:  %d", vuln_count)
    log.info("  Info / low findings:    %d", info_count)
    log.info("  Total findings:         %d", len(all_findings))

    if vuln_count > 0:
        log.info("\n  ── HIGH/CRITICAL VULNERABILITIES ──")
        for f in all_findings:
            if f.severity in (SEV_CRITICAL, SEV_HIGH):
                log.info("  [%s] %s", f.severity, f.name)
                log.info("        Target: %s", f.affected_endpoint)
                log.info("        Desc:   %s", f.description)
                log.info("        Fix:    %s", f.remediation)
                log.info("")

    if info_count > 0:
        log.info("\n  ── INFORMATIONAL FINDINGS ──")
        for f in all_findings:
            if f.severity not in (SEV_CRITICAL, SEV_HIGH):
                log.info("  [%s] %s", f.severity, f.name)
                log.info("        Target: %s", f.affected_endpoint)
                log.info("")

    if vuln_count == 0 and info_count == 0:
        log.info("\n  ✅ No issues found — CyberNova appears well-defended!")
    elif vuln_count == 0 and info_count > 0:
        log.info("\n  ✅ No high/critical vulnerabilities found!")
        log.info("     %d informational/low-severity observations noted.", info_count)

    log.info("=" * 70)

    return {
        "vulnerabilities": vuln_count,
        "informational": info_count,
        "total": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
        "severity_breakdown": {
            "CRITICAL": sum(1 for f in all_findings if f.severity == SEV_CRITICAL),
            "HIGH": sum(1 for f in all_findings if f.severity == SEV_HIGH),
            "MEDIUM": sum(1 for f in all_findings if f.severity == SEV_MEDIUM),
            "LOW": sum(1 for f in all_findings if f.severity == SEV_LOW),
            "INFO": sum(1 for f in all_findings if f.severity == SEV_INFO),
        },
        "attack_coverage": {
            "authentication": ["JWT alg=none", "JWT KID injection", "password spraying"],
            "authorization": ["IDOR", "tenant hopping", "forced browsing"],
            "injection": ["NoSQL", "SSTI", "CRLF"],
            "waf_bypass": ["SQLi bypass", "XSS bypass"],
            "info_disclosure": ["security headers", "debug endpoints", "verbose errors", "CORS", "server version"],
            "api_abuse": ["pagination", "mass assignment", "race conditions"],
            "ssrf": ["internal network probing", "cloud metadata"],
            "rate_limiting": ["threshold analysis", "header bypass"],
        },
    }


async def main():
    results = await run_all_attacks()
    # Exit 0 if no CRITICAL or HIGH vulnerabilities, 1 otherwise
    sys.exit(0 if results["vulnerabilities"] == 0 else 1)


# ── Pytest Tests ────────────────────────────────────────────────────────

import pytest


def _server_reachable(timeout: float = 2.0) -> bool:
    """Return True if a CyberNova server is listening at TARGET."""
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(TARGET)
    host = parts.hostname or "localhost"
    port = parts.port or 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# These tests are live penetration tests that require a running CyberNova
# server (e.g. the docker-compose stack). In CI jobs with no server, they
# are skipped instead of failing on connection errors.
NEEDS_LIVE_SERVER = pytest.mark.skipif(
    not _server_reachable(),
    reason=f"Requires a running CyberNova server at {TARGET} (live integration test)",
)


@NEEDS_LIVE_SERVER
@pytest.mark.asyncio
async def test_real_world_authentication_attacks():
    """JWT attacks, password spraying, race conditions."""
    findings = []
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        findings.extend(await _test_jwt_alg_none(client))
        findings.extend(await _test_jwt_kid_injection(client))
        findings.extend(await _test_password_spraying(client))
        findings.extend(await _test_race_condition(client))
    critical = [f for f in findings if f.severity in (SEV_CRITICAL, SEV_HIGH)]
    assert len(critical) == 0, f"Found {len(critical)} critical/high auth vulnerabilities: {[f.name for f in critical]}"


@NEEDS_LIVE_SERVER
@pytest.mark.asyncio
async def test_real_world_injection_attacks():
    """NoSQLi, SSTI, CRLF injection."""
    findings = []
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        findings.extend(await _test_nosql_injection(client))
        findings.extend(await _test_ssti_injection(client))
        findings.extend(await _test_crlf_injection(client))
    critical = [f for f in findings if f.severity in (SEV_CRITICAL, SEV_HIGH)]
    assert len(critical) == 0, f"Found {len(critical)} critical/high injection vulnerabilities: {[f.name for f in critical]}"


@NEEDS_LIVE_SERVER
@pytest.mark.asyncio
async def test_real_world_waf_bypass():
    """WAF bypass techniques."""
    findings = []
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        findings.extend(await _test_waf_bypass(client))
    critical = [f for f in findings if f.severity in (SEV_CRITICAL, SEV_HIGH)]
    assert len(critical) == 0, f"Found {len(critical)} critical/high WAF bypass issues: {[f.name for f in critical]}"


@NEEDS_LIVE_SERVER
@pytest.mark.asyncio
async def test_real_world_info_disclosure():
    """Information disclosure checks."""
    findings = []
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        findings.extend(await _test_information_disclosure(client))
    high = [f for f in findings if f.severity == SEV_HIGH]
    assert len(high) == 0, f"Found {len(high)} high severity info disclosure issues: {[f.name for f in high]}"


@pytest.mark.asyncio
async def test_real_world_rate_limiting():
    """Rate limit analysis — requires running server at localhost:8000."""
    findings = []
    try:
        async with httpx.AsyncClient(base_url=TARGET, verify=False, timeout=TIMEOUT) as client:
            # Quick connectivity check — skip if server is not running
            try:
                await client.get("/", timeout=5.0)
            except (httpx.ConnectError, httpx.ReadTimeout):
                pytest.skip("Server not running at %s — rate limit test requires live server" % TARGET)
            findings.extend(await _test_rate_limit_analysis(client))
    except httpx.ReadTimeout:
        pytest.skip("Server timed out — rate limit test requires live server")
    high = [f for f in findings if f.severity == SEV_HIGH]
    assert len(high) == 0, f"Found {len(high)} high severity rate limiting issues: {[f.name for f in high]}"


@NEEDS_LIVE_SERVER
@pytest.mark.asyncio
async def test_real_world_mass_assignment():
    """Mass assignment protection."""
    findings = []
    async with httpx.AsyncClient(base_url=TARGET, verify=False) as client:
        findings.extend(await _test_mass_assignment(client))
    critical = [f for f in findings if f.severity in (SEV_CRITICAL, SEV_HIGH)]
    assert len(critical) == 0, f"Found {len(critical)} critical/high mass assignment issues: {[f.name for f in critical]}"


if __name__ == "__main__":
    asyncio.run(main())
