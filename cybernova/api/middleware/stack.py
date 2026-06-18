"""
CyberNova — Middleware Stack
CORS, security headers, tracing, error handling, rate limiting, CSRF.
"""
from __future__ import annotations

import time
import uuid
import logging
import secrets
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from cybernova.config.settings import get_settings
from cybernova.core.exceptions import CyberNovaError, CSRFProtectionError
from cybernova.api.middleware.rate_limiter import register_api_key_rate_limiter

log = logging.getLogger("cybernova.middleware")


def register_middleware(app: FastAPI) -> None:
    settings = get_settings()

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Trace-ID", "X-Correlation-ID"],
        max_age=86400,
        expose_headers=["X-Trace-ID", "X-Correlation-ID", "X-Processing-Time-Ms"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Rate limiting is handled by PlanRateLimitMiddleware (registered in main.py)
    # Per-API-key rate limiting middleware
    register_api_key_rate_limiter(app)

    # Request body size enforcement
    max_body = settings.max_request_size

    # Exempt paths that legitimately receive large payloads
    _SIZE_EXEMPT_PREFIXES = ("/api/v1/ingest", "/api/rag/", "/ws")

    @app.middleware("http")
    async def request_size_guard(request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if any(path.startswith(p) for p in _SIZE_EXEMPT_PREFIXES):
            return await call_next(request)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > max_body:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds maximum size of {max_body} bytes"},
                    )
            except (ValueError, OverflowError):
                pass  # malformed Content-Length — let the request proceed; WAF will catch it
        return await call_next(request)

    # Distributed tracing + request lifecycle logging
    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable) -> Response:
        trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            log.exception("%s %s -> 500 (%.1fms) [UNHANDLED]", request.method, request.url.path, elapsed_ms)
            raise
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Processing-Time-Ms"] = str(elapsed_ms)
        if response.status_code >= 500:
            log.error("%s %s -> %d (%.1fms)", request.method, request.url.path, response.status_code, elapsed_ms)
        elif response.status_code >= 400:
            log.warning("%s %s -> %d (%.1fms)", request.method, request.url.path, response.status_code, elapsed_ms)
        else:
            log.info("%s %s -> %d (%.1fms)", request.method, request.url.path, response.status_code, elapsed_ms)
        return response

    # CSRF protection for state-changing methods
    @app.middleware("http")
    async def csrf_protection(request: Request, call_next: Callable) -> Response:
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            content_type = request.headers.get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                csrf_token = request.headers.get("X-CSRF-Token", "")
                cookie_token = request.cookies.get("csrf_token", "")
                if not csrf_token or not cookie_token or not secrets.compare_digest(csrf_token, cookie_token):
                    log.warning("CSRF validation failed for %s %s", request.method, request.url.path)
                    raise CSRFProtectionError()
        response: Response = await call_next(request)
        if request.method == "GET":
            token = secrets.token_hex(32)
            response.set_cookie(
                key="csrf_token",
                value=token,
                httponly=True,
                samesite="strict",
                secure=settings.is_production,
                max_age=3600,
            )
        return response

    # Security headers
    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        if request.url.path.startswith("/api/") or request.url.path in ("/", "/health", "/ready", "/metrics"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Error handlers
    @app.exception_handler(CyberNovaError)
    async def cybernova_error_handler(request: Request, exc: CyberNovaError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, **(exc.extra or {})},
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        trace_id = request.headers.get("X-Trace-ID", "unknown")
        log.error("Unhandled exception [%s]: %s %s — %s", trace_id, request.method, request.url.path, str(exc))
        detail = "System fault. Action logged."
        if settings.environment == "development":
            detail = str(exc)
        return JSONResponse(status_code=500, content={"detail": detail, "trace_id": trace_id})
