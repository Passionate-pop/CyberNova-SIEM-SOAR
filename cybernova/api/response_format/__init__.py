"""
CyberNova — Standardized API Response Format
Consistent response envelope for all API endpoints.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi.responses import JSONResponse


def success_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = 200,
    meta: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    body = {
        "status": "success",
        "message": message,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if meta:
        body["meta"] = meta
    return JSONResponse(status_code=status_code, content=body)


def error_response(
    detail: str = "An error occurred",
    status_code: int = 400,
    errors: Optional[list] = None,
) -> JSONResponse:
    body = {
        "status": "error",
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if errors:
        body["errors"] = errors
    return JSONResponse(status_code=status_code, content=body)
