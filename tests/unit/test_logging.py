from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from cybernova.config.logging import CyberNovaJsonFormatter, setup_json_logging
from cybernova.core.logging.logger import _tenant_id, _trace_id, _request_id

TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _parse_log(record: logging.LogRecord) -> dict:
    return json.loads(CyberNovaJsonFormatter().format(record))


def test_json_output_is_valid_json():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", (), None)
    parsed = _parse_log(record)
    assert isinstance(parsed, dict)


def test_standardized_fields_present():
    record = logging.LogRecord("test", logging.WARNING, __file__, 5, "warn msg", (), None)
    parsed = _parse_log(record)
    for field in ("timestamp", "level", "logger", "module", "message",
                  "tenant_id", "trace_id", "request_id", "event_id"):
        assert field in parsed, f"missing field: {field}"


def test_timestamp_format():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "x", (), None)
    parsed = _parse_log(record)
    assert TIMESTAMP_RE.match(parsed["timestamp"]), f"bad timestamp: {parsed['timestamp']}"
    ts = datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))
    assert ts.tzinfo is not None


def test_event_id_is_uuid():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "x", (), None)
    parsed = _parse_log(record)
    assert UUID_RE.match(parsed["event_id"]), f"bad uuid: {parsed['event_id']}"


def test_event_id_unique_per_call():
    r1 = _parse_log(logging.LogRecord("t", logging.INFO, __file__, 1, "a", (), None))
    r2 = _parse_log(logging.LogRecord("t", logging.INFO, __file__, 1, "b", (), None))
    assert r1["event_id"] != r2["event_id"]


def test_level_and_message_correct():
    record = logging.LogRecord("test", logging.ERROR, __file__, 42, "fail", (), None)
    parsed = _parse_log(record)
    assert parsed["level"] == "ERROR"
    assert parsed["message"] == "fail"
    assert parsed["line"] == 42


@pytest.mark.parametrize("level,expected", [
    (logging.DEBUG, "DEBUG"),
    (logging.INFO, "INFO"),
    (logging.WARNING, "WARNING"),
    (logging.ERROR, "ERROR"),
    (logging.CRITICAL, "CRITICAL"),
])
def test_all_levels(level, expected):
    record = logging.LogRecord("test", level, __file__, 1, "msg", (), None)
    parsed = _parse_log(record)
    assert parsed["level"] == expected


def test_exception_includes_traceback():
    import sys
    try:
        raise ValueError("bad")
    except ValueError:
        exc_info = sys.exc_info()
    record = logging.LogRecord("test", logging.ERROR, __file__, 1,
                               "exc", (), exc_info=exc_info)
    parsed = _parse_log(record)
    assert "exception" in parsed
    assert "ValueError" in parsed["exception"]
    assert "bad" in parsed["exception"]


def test_extra_fields_via_extra():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "x", (), None)
    record._extra = {"user_id": 42, "action": "login"}
    parsed = _parse_log(record)
    assert parsed["user_id"] == 42
    assert parsed["action"] == "login"


def test_context_vars_propagate():
    _tenant_id.set("tenant-abc")
    _trace_id.set("trace-xyz")
    _request_id.set("req-123")

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "ctx", (), None)
    parsed = _parse_log(record)

    assert parsed["tenant_id"] == "tenant-abc"
    assert parsed["trace_id"] == "trace-xyz"
    assert parsed["request_id"] == "req-123"


def test_setup_json_logging_returns_root_logger():
    logger = setup_json_logging()
    assert logger is logging.getLogger()


def test_setup_json_logging_sets_json_handler():
    logger = setup_json_logging()
    handlers = logger.handlers
    assert len(handlers) >= 1
    assert isinstance(handlers[0].formatter, CyberNovaJsonFormatter)


def test_json_output_no_newlines_in_message():
    record = logging.LogRecord("test", logging.INFO, __file__, 1,
                               "line1\nline2\r\nline3", (), None)
    output = CyberNovaJsonFormatter().format(record)
    # The JSON string should have escaped newlines, not actual newlines
    parsed = json.loads(output)
    assert parsed["message"] == "line1\nline2\r\nline3"


def test_function_and_module_recorded():
    record = logging.LogRecord("test", logging.INFO, __file__, 10,
                               "in func", (), None, func="inner_func")
    parsed = _parse_log(record)
    assert parsed["function"] == "inner_func"


def test_unicode_handling():
    record = logging.LogRecord("test", logging.INFO, __file__, 1,
                               "héllo wörld 🌍", (), None)
    parsed = _parse_log(record)
    assert parsed["message"] == "héllo wörld 🌍"
