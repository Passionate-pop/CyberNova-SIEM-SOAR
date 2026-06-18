from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from cybernova.core.logging.logger import _tenant_id, _trace_id, _request_id


class CyberNovaJsonFormatter(logging.Formatter):
    """JSON formatter for ELK/Loki ingestion.

    Standardized fields: timestamp, level, module, tenant_id, request_id, event_id.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") +
                         f"{datetime.now(timezone.utc).microsecond:06d}" + "Z",
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
            "tenant_id": _tenant_id.get(),
            "trace_id": _trace_id.get(),
            "request_id": _request_id.get(),
            "event_id": str(uuid.uuid4()),
        }

        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        extra = getattr(record, "_extra", None)
        if extra:
            entry.update(extra)

        return json.dumps(entry, default=str, ensure_ascii=False)


def setup_json_logging() -> logging.Logger:
    """Configure root logger with JSON formatting. Call once at startup."""
    from cybernova.config.settings import get_settings

    settings = get_settings()
    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CyberNovaJsonFormatter())
    root.addHandler(handler)
    return root
