"""
CyberNova — WAF Middleware
Inspects all HTTP requests for malicious patterns and blocks them.
Two layers: (1) hardcoded fast pre-check, (2) WAF engine analysis.
"""
from __future__ import annotations

import logging
import re
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from cybernova.protection.waf import waf_engine

log = logging.getLogger("cybernova.protection.waf_middleware")

MAX_BODY_BYTES = 1_048_576

SKIP_PREFIXES = frozenset({
    "/api/rag/",
    "/api/v1/ingest/",  # Security events contain attack payloads — that's the data to analyze
    "/api/v1/auth/",   # Auth endpoints — browser Origin/Referer headers contain localhost URLs, causing SSRF false positives
})

# Paths where we skip body inspection only (still check query params and headers)
SKIP_BODY_PREFIXES = frozenset({
    "/api/v1/ingest/",
    "/api/v1/pipeline/ingest",
    "/api/v1/ai/",
})
SKIP_PATHS = frozenset({
    "/", "/health", "/ready", "/metrics",
    "/docs", "/redoc", "/openapi.json",
})

# ── Hardcoded attack detection patterns (defense-in-depth) ──

# SQL trailing comment: admin'--, ' OR '1'='1 #
SQLI_TRAILING_RE = re.compile(
    r"['\"](?:\s*--|\s*#|\s*/\*|--\s|#\s)",
    re.I,
)

# XSS: <script>, <iframe>, javascript:, onerror=, alert(
XSS_RE = re.compile(
    r"<(?:script|iframe|svg[\s/>]|img|body)[\s/>]|"
    r"(?:javascript|vbscript|data:text/html)\s*:|"
    r"on\w+\s*=|"
    r"(?:alert|prompt|confirm)\s*\(|"
    r"String\.fromCharCode|eval\s*\(",
    re.I,
)

# Path traversal: ../..\, %2e%2e%2f, /etc/passwd
PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\){2,}|"
    r"%2e%2e%2f|%2e%2e%5c|"
    r"\.{3,}[/\\]|"
    r"\.\.[/\\]\.\.[/\\]|"
    r"/etc/(?:passwd|shadow|hosts|crontab|ssh)|"
    r"/windows/win\.ini|"
    r"/boot\.ini",
    re.I,
)

# Command injection: ; id, | whoami, && ls, `cmd`, $(cmd)
CMD_INJECTION_RE = re.compile(
    r"(?:;|\||&&)\s*(?:id|whoami|ls|cat|sh|bash|cmd|powershell|dir|type|ps|echo|rm|mv|cp|chmod|chown|nc|nmap|curl|wget|python|perl|ruby|php|node|kill|find|grep|sort|more|less|head|tail|tee|xargs|sudo|su|passwd|ifconfig|ipconfig|netstat|route|iptables|systemctl|service|docker|kubectl|minikube)\b|"
    r"`[^`]+`|"
    r"\$\([^)]+\)",
    re.I,
)

# SQL tautology: ' OR 1=1, ' OR '1'='1
SQL_TAUTOLOGY_RE = re.compile(
    r"'\s*(?:OR|AND)\s+[\"']?\w+[\"']?\s*[=<>]",
    re.I,
)

# SSTI / Template Injection: {{ expr }}, ${ expr }, #{ expr }, <%= expr %>, class.forName
SSTI_RE = re.compile(
    r"\{\{\s*[\w.'\"\[\]]+\s*\}\}|"
    r"\$\{[\w.'\"\[\]]+\}|"
    r"#\{[\w.()]+\}|"
    r"<%[=\s]|"
    r"\{%\s*[\w.]+\s*%\}|"
    r"class\s*\.\s*forName|"
    r"Runtime\.getRuntime|"
    r"ProcessBuilder",
    re.I,
)

# Simple keyword check (fast path)
MALICIOUS_KEYWORDS = frozenset({
    # SQLi
    "'--", "';--", "'#", "'/*", "union select", "drop table",
    # XSS
    "<script", "<iframe", "javascript:", "onerror=", "onload=",
    # Path traversal
    "../", "..\\", "%2e%2e", "/etc/passwd",
    # Command injection
    "; id", ";id", "| id", "|id", "&& id", "`ls", "$(",
    # NoSQL
    "$gt", "$ne", "$where", "$regex",
    # SSTI
    "{{", "${", "#{", "<%",
})


def _contains_attack(value: str) -> str | None:
    """Check a single string for any attack pattern. Returns category or None."""
    if not value:
        return None
    
    lower = value.lower()
    
    # Fast keyword check
    for kw in MALICIOUS_KEYWORDS:
        if kw in lower:
            if kw in ("'--", "';--", "'#", "'/*"):
                return "sqli_trailing_comment"
            if kw in ("union select", "drop table"):
                return "sqli"
            if kw in ("<script", "<iframe", "javascript:", "onerror=", "onload="):
                return "xss"
            if kw in ("../", "..\\", "%2e%2e", "/etc/passwd"):
                return "path_traversal"
            if kw in ("; id", ";id", "| id", "|id", "&& id", "`ls", "$("):
                return "cmd_injection"
            if kw in ("$gt", "$ne", "$where", "$regex"):
                return "nosql_injection"
            return "malicious"

    # Regex checks
    if SQLI_TRAILING_RE.search(value):
        return "sqli_trailing_comment"
    if SQL_TAUTOLOGY_RE.search(value):
        return "sqli_tautology"
    if XSS_RE.search(value):
        return "xss"
    if PATH_TRAVERSAL_RE.search(value):
        return "path_traversal"
    if CMD_INJECTION_RE.search(value):
        return "cmd_injection"
    if SSTI_RE.search(value):
        return "template_injection"

    return None


def _check_all_attack_sources(path: str, query_params: dict, body: str | None) -> str | None:
    """Check path, query params, and body for attacks."""
    # Check path
    result = _contains_attack(path)
    if result:
        return result
    
    # Check query params
    for key, value in query_params.items():
        result = _contains_attack(value)
        if result:
            return result
        result = _contains_attack(f"{key}={value}")
        if result:
            return result
    
    # Check body
    if body:
        result = _contains_attack(body)
        if result:
            return result
    
    return None


def register_waf_middleware(app: FastAPI) -> None:
    log.info("WAF middleware registration starting...")

    @app.middleware("http")
    async def waf_inspection(request: Request, call_next: Callable) -> Response:
        path = request.url.path
        log.debug("WAF intercepted: %s %s", request.method, path)

        if path in SKIP_PATHS or any(path.startswith(p) for p in SKIP_PREFIXES):
            return await call_next(request)

        method = request.method
        query_params = dict(request.query_params)
        source_ip = request.client.host if request.client else ""

        if query_params:
            log.debug("WAF query params: %s", query_params)

        # Read body for POST/PUT/PATCH/DELETE
        # But skip body inspection for ingest/event endpoints — they receive
        # security event payloads that NATURALLY contain attack patterns
        # (SQLi payloads, XSS strings, etc.). Those are the data to analyze!
        skip_body = any(path.startswith(p) for p in SKIP_BODY_PREFIXES)
        body = None
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                raw = await request.body()
                # Enforce body size limit — but exempt ingest endpoints which
                # legitimately receive large security event payloads.
                if not skip_body and len(raw) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds maximum size of {MAX_BODY_BYTES} bytes"},
                    )
                if raw and not skip_body:
                    body = raw.decode("utf-8", errors="replace")
                    log.debug("WAF body: %s...", body[:200])
            except Exception as e:
                log.debug("WAF body read error: %s", e)
                body = None

        # Layer 1: Fast pre-check (only path and query params for ingest endpoints)
        pre_check = _check_all_attack_sources(path, query_params, body)

        if pre_check:
            log.warning(
                "WAF BLOCKED (pre-check): %s %s from %s — %s",
                method, path, source_ip, pre_check,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked by Web Application Firewall",
                    "reason": "malicious_request",
                    "finding_count": 1,
                    "max_risk_score": 99.0,
                    "pre_check_category": pre_check,
                },
                headers={
                    "X-WAF-Blocked": "true",
                    "X-WAF-Risk-Score": "99.0",
                    "X-WAF-PreCheck": pre_check,
                },
            )

        # Layer 2: WAF engine analysis
        exec_headers = {}
        try:
            result = waf_engine.analyze_request(
                method=method,
                path=path,
                query_params=query_params,
                body=body,
                headers=dict(request.headers),
                source_ip=source_ip,
            )

            if result["attack_detected"]:
                log.warning(
                    "WAF: %s %s from %s — %d findings (blocked=%s, risk=%.1f)",
                    method, path, source_ip,
                    result["finding_count"],
                    result["blocked"],
                    result["max_risk_score"],
                )

            if result["blocked"]:
                log.warning("WAF BLOCKED (engine) %s %s — risk=%.1f", method, path, result["max_risk_score"])
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Request blocked by Web Application Firewall",
                        "reason": "malicious_request",
                        "finding_count": result["finding_count"],
                        "max_risk_score": result["max_risk_score"],
                    },
                    headers={
                        "X-WAF-Blocked": "true",
                        "X-WAF-Risk-Score": str(result["max_risk_score"]),
                    },
                )

            # Set inspection headers for observability even when not blocked
            if result["attack_detected"]:
                exec_headers["X-WAF-Inspected"] = "true"
                exec_headers["X-WAF-Findings"] = str(result["finding_count"])
                exec_headers["X-WAF-Risk-Score"] = str(result["max_risk_score"])
        except Exception as e:
            log.error("WAF engine error: %s", e)

        log.debug("WAF ALLOWED %s %s", method, path)
        response = await call_next(request)
        if exec_headers:
            for key, val in exec_headers.items():
                response.headers[key] = val
        return response

    log.info("WAF middleware registration complete")
