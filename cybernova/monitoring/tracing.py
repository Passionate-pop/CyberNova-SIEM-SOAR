from __future__ import annotations

import logging
from contextlib import asynccontextmanager, nullcontext
from typing import Any, AsyncGenerator

try:
    from opentelemetry import trace
    from opentelemetry.propagate import extract, inject
    _OTEL_API_AVAILABLE = True
except ImportError:
    _OTEL_API_AVAILABLE = False
    trace = None
    def extract(_):
        return {}
    def inject(_):
        return None

try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    _OTEL_SDK_AVAILABLE = True
except ImportError:
    _OTEL_SDK_AVAILABLE = False


class _NoopSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def end(self) -> None:
        # No-op span — no telemetry backend to report to
        pass


class _NoopTracer:
    def start_as_current_span(self, name: str, **kwargs: Any) -> Any:
        span = _NoopSpan()
        attrs = kwargs.get("attributes") or {}
        for k, v in attrs.items():
            span.set_attribute(k, v)
        return nullcontext(span)

    def start_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        return _NoopSpan()


log = logging.getLogger("cybernova.monitoring.tracing")

_TRACER: Any = None
_TRACER_PROVIDER: Any = None
_OTEL_ENABLED = False


def _noop_tracer() -> _NoopTracer:
    return _NoopTracer()


def setup_tracing(
    service_name: str = "cybernova",
    service_version: str = "0.0.0",
    environment: str = "development",
    otlp_endpoint: str = "http://localhost:4318/v1/traces",
) -> None:
    global _TRACER, _TRACER_PROVIDER, _OTEL_ENABLED

    if not _OTEL_SDK_AVAILABLE:
        _TRACER = _noop_tracer()
        log.info("OpenTelemetry SDK not installed — tracing disabled (no-op)")
        return

    # Skip OTLP exporter if endpoint is localhost (no collector in dev)
    if 'localhost' in otlp_endpoint or '127.0.0.1' in otlp_endpoint:
        _TRACER = _noop_tracer()
        log.info("OpenTelemetry tracing disabled — no OTLP collector at %s", otlp_endpoint)
        return

    resource = Resource.create({
        "service.name": service_name,
        "service.version": service_version,
        "deployment.environment": environment,
    })

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider
    _TRACER = trace.get_tracer(service_name, service_version)
    _OTEL_ENABLED = True

    log.info("OpenTelemetry tracing initialized (endpoint=%s)", otlp_endpoint)


def get_tracer() -> Any:
    global _TRACER
    if _TRACER is not None:
        return _TRACER
    _TRACER = _noop_tracer()
    return _TRACER


def close_tracing() -> None:
    if _TRACER_PROVIDER is not None:
        _TRACER_PROVIDER.shutdown()
        log.info("OpenTelemetry tracer shut down")


def is_tracing_enabled() -> bool:
    return _OTEL_ENABLED


# ── HTTP Request Tracing ──────────────────────────────────────


class TraceMiddleware:
    """ASGI middleware that creates an OpenTelemetry span per HTTP request.

    Captures method, path, status code, client IP, and propagates
    trace context via W3C Trace-Context headers.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        tracer = get_tracer()
        headers = dict(scope.get("headers", []))
        ctx = extract(headers) if _OTEL_API_AVAILABLE else None
        method = scope.get("method", "GET")
        path = scope.get("path", "/")

        span_kind_cls = getattr(trace, "SpanKind", None)
        span_kind = span_kind_cls.SERVER if span_kind_cls else None
        with tracer.start_as_current_span(
            f"{method} {path}",
            context=ctx,
            kind=span_kind,
            attributes={
                "http.method": method,
                "http.target": path,
                "http.host": _decode_header(headers, b"host"),
                "http.scheme": scope.get("scheme", "http"),
                "http.user_agent": _decode_header(headers, b"user-agent"),
                "http.client_ip": _get_client_ip(scope, headers),
            },
        ) as span:
            async def send_wrapper(message):
                if message.get("type") == "http.response.start":
                    status_code = message.get("status", 0)
                    span.set_attribute("http.status_code", status_code)
                    if _OTEL_API_AVAILABLE:
                        outgoing = dict(message.get("headers", []))
                        inject(outgoing)
                        message["headers"] = list(outgoing.items())
                await send(message)

            await self.app(scope, receive, send_wrapper)


def _decode_header(headers: dict, key: bytes) -> str:
    val = headers.get(key)
    if isinstance(val, bytes):
        return val.decode(errors="replace")
    return ""


def _get_client_ip(scope: dict, headers: dict) -> str:
    client = scope.get("client")
    if client:
        return client[0]
    for header_name in (b"x-forwarded-for", b"x-real-ip"):
        value = headers.get(header_name)
        if value:
            return value.decode().split(",")[0].strip()
    return ""


# ── DB Call Tracing ───────────────────────────────────────────


@asynccontextmanager
async def trace_db_call(
    operation: str = "",
    statement: str = "",
    system: str = "postgresql",
) -> AsyncGenerator[Any, None]:
    """Context manager for tracing database operations.

    Usage:
        async with trace_db_call("SELECT", "SELECT 1", "postgresql"):
            await db.execute(...)
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(
        f"db.{operation}" if operation else "db.call",
        attributes={
            "db.system": system,
            "db.operation": operation,
            "db.statement": statement,
        },
    ) as span:
        yield span
