from __future__ import annotations

import logging
import sys
import uuid
import json
from datetime import datetime, timezone
from typing import Optional
from contextvars import ContextVar

from cybernova.config.settings import get_settings

_tenant_id: ContextVar[str] = ContextVar("tenant_id", default="default")
_trace_id: ContextVar[str] = ContextVar("trace_id", default=str(uuid.uuid4())[:8])
_request_id: ContextVar[str] = ContextVar("request_id", default="")


class StructuredFormatter(logging.Formatter):
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
            "trace_id": _trace_id.get(),
            "request_id": _request_id.get(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "_extra"):
            log_entry.update(record._extra)
        return json.dumps(log_entry)


def setup_logging(name: Optional[str] = None) -> logging.Logger:
    settings = get_settings()
    logger = logging.getLogger(name or "cybernova")
    logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    if logger.hasHandlers():
        logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if settings.is_production:
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    logger.addHandler(handler)
    logger.propagate = False
    return logger


logger = setup_logging()
