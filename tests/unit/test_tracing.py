from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.monitoring.tracing import (
    _get_client_ip,
    close_tracing,
    get_tracer,
    is_tracing_enabled,
    setup_tracing,
    trace_db_call,
)


def test_setup_tracing_noop_when_sdk_missing():
    with patch("cybernova.monitoring.tracing._OTEL_SDK_AVAILABLE", False):
        setup_tracing()
        tracer = get_tracer()
        assert tracer is not None
        assert is_tracing_enabled() is False


def test_get_tracer_returns_tracer():
    tracer = get_tracer()
    assert tracer is not None


def test_close_tracing_does_not_raise():
    close_tracing()


def test_setup_tracing_sdk_not_available_uses_noop():
    with patch("cybernova.monitoring.tracing._OTEL_SDK_AVAILABLE", False):
        setup_tracing(service_name="test", otlp_endpoint="http://test:4318")
        assert is_tracing_enabled() is False
        assert get_tracer() is not None


def test_trace_db_call_creates_span():
    async def run():
        async with trace_db_call("SELECT", "SELECT 1", "postgresql") as span:
            return span

    import asyncio
    result_span = asyncio.run(run())
    assert result_span is not None


def test_middleware_creates_http_span():
    from cybernova.monitoring.tracing import TraceMiddleware

    mock_app = AsyncMock()
    middleware = TraceMiddleware(mock_app)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "scheme": "http",
        "headers": [(b"host", b"example.com"), (b"user-agent", b"test-agent")],
        "client": ["10.0.0.1", 54321],
    }
    receive = MagicMock()
    send = AsyncMock()

    async def run():
        await middleware(scope, receive, send)

    import asyncio
    asyncio.run(run())

    mock_app.assert_awaited_once()


def test_middleware_skips_non_http():
    from cybernova.monitoring.tracing import TraceMiddleware

    mock_app = AsyncMock()
    middleware = TraceMiddleware(mock_app)

    scope = {"type": "websocket", "path": "/ws"}
    receive = MagicMock()
    send = AsyncMock()

    async def run():
        await middleware(scope, receive, send)

    import asyncio
    asyncio.run(run())

    mock_app.assert_awaited_once()


def test_trace_db_call_attributes():
    span_attrs = {}

    async def run():
        async with trace_db_call("INSERT", "INSERT INTO users", "postgresql") as span:
            span_attrs.update(dict(span.attributes))

    import asyncio
    asyncio.run(run())
    assert span_attrs.get("db.system") == "postgresql"
    assert span_attrs.get("db.operation") == "INSERT"
    assert span_attrs.get("db.statement") == "INSERT INTO users"


def test_otel_settings_in_settings():
    from cybernova.config.settings import get_settings
    settings = get_settings()
    assert hasattr(settings, "otel_endpoint")
    assert hasattr(settings, "otel_service_name")
    assert hasattr(settings, "otel_enabled")
    assert settings.otel_endpoint == "http://localhost:4318/v1/traces"
    assert settings.otel_service_name == "cybernova"


def test_get_client_ip_from_scope():
    headers = {}
    scope = {"client": ["192.168.1.1", 1234]}
    ip = _get_client_ip(scope, headers)
    assert ip == "192.168.1.1"


def test_get_client_ip_from_forwarded():
    headers = {b"x-forwarded-for": b"10.0.0.1, 10.0.0.2"}
    scope = {"client": None}
    ip = _get_client_ip(scope, headers)
    assert ip == "10.0.0.1"


def test_get_client_ip_empty():
    headers = {}
    scope = {"client": None}
    ip = _get_client_ip(scope, headers)
    assert ip == ""


def test_pipeline_wrapper_imports():
    from cybernova.pipeline.unified_pipeline import unified_pipeline
    assert unified_pipeline is not None


def test_trace_middleware_imports():
    from cybernova.monitoring.tracing import TraceMiddleware
    assert TraceMiddleware is not None
