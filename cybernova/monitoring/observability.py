"""
CyberNova — Structured Logging + Observability
Structured JSON logging with tenant correlation, request tracing.
"""
from __future__ import annotations

import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from contextvars import ContextVar

import json

_tenant_id: ContextVar[str] = ContextVar("tenant_id", default="default")
_trace_id: ContextVar[str] = ContextVar("trace_id", default="")
_request_id: ContextVar[str] = ContextVar("request_id", default="")


class StructuredFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "tenant_id": _tenant_id.get(),
            "trace_id": _trace_id.get() or str(uuid.uuid4())[:8],
            "request_id": _request_id.get(),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)

        return json.dumps(log_entry)


class StructuredLogger:
    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    def _make_extra(self, **kwargs: Any) -> Dict[str, Any]:
        return {"extra_fields": kwargs}

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log.info(msg, extra=self._make_extra(**kwargs))

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log.warning(msg, extra=self._make_extra(**kwargs))

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log.error(msg, extra=self._make_extra(**kwargs))

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log.critical(msg, extra=self._make_extra(**kwargs))

    def audit(self, msg: str, user_id: Optional[str] = None, **kwargs: Any) -> None:
        self._log.info(
            msg,
            extra=self._make_extra(
                event_type="audit",
                user_id=user_id,
                **kwargs,
            ),
        )


def setup_structured_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    for logger_name in ["cybernova", "uvicorn", "fastapi"]:
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        logger.handlers.clear()
        logger.addHandler(handler)


class RequestContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            request_id = headers.get(b"x-request-id", b"").decode() or str(uuid.uuid4())[:8]
            _request_id.set(request_id)

            scope.get("path", "")
            scope.get("method", "")

            async def send_wrapper(message):
                if message.get("type") == "http.response.start":
                    headers = dict(message.get("headers", []))
                    headers[b"x-request-id"] = request_id.encode()
                    message["headers"] = list(headers.items())
                await send(message)

            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)


class MetricsCollector:
    def __init__(self) -> None:
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, list] = {}

    def inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._make_key(name, labels)
        self._gauges[key] = value

    def histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-1000:]

    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_all(self) -> Dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: {"count": len(v), "sum": sum(v), "avg": sum(v) / len(v) if v else 0}
                for k, v in self._histograms.items()
            },
        }

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus exposition format.

        Counters use _total suffix per convention. Gauges are exported as-is.
        Labels (name{k=v}) are rendered as ``name{k="v"}`` for Prometheus.
        """
        lines: list[str] = []
        for key, value in self._counters.items():
            metric_name, labels = self._split_metric_key(key)
            if labels:
                lines.append(f"{metric_name}_total{{{labels}}} {value}")
            else:
                lines.append(f"{metric_name}_total {value}")
        for key, value in self._gauges.items():
            metric_name, labels = self._split_metric_key(key)
            if labels:
                lines.append(f"{metric_name}{{{labels}}} {value}")
            else:
                lines.append(f"{metric_name} {value}")
        return "\n".join(lines)

    @staticmethod
    def _split_metric_key(key: str) -> tuple[str, str]:
        """Split ``metric_name{k1=v1,k2=v2}`` into ``(name, labels_str)``.

        Returns ``(key, '')`` when no ``{`` is present.
        """
        if "{" not in key:
            return key, ""
        name, raw = key.split("{", 1)
        # raw ends with '}' — strip it, then format each pair as k="v"
        raw = raw.rstrip("}")
        parts = [f'{k}="{v}"' for k, v in (p.split("=", 1) for p in raw.split(",") if "=" in p)]
        return name, ",".join(parts)


metrics = MetricsCollector()


class Timer:
    def __init__(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        self.name = name
        self.labels = labels or {}
        self._start = time.perf_counter()

    def stop(self) -> float:
        duration = time.perf_counter() - self._start
        metrics.histogram(f"{self.name}_duration_seconds", duration, self.labels)
        metrics.inc(f"{self.name}_total", 1, self.labels)
        return duration
