from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("cybernova.api_versioning")

SUPPORTED_VERSIONS = {"1", "2"}
DEFAULT_VERSION = "2"


class APIVersionMiddleware(BaseHTTPMiddleware):
    """
    Enforces API versioning via Accept-Version header.
    - Requests without a version header get the default (v2).
    - Requests with an unsupported version get a 400.
    - Sets X-API-Version response header.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        version = request.headers.get("Accept-Version", DEFAULT_VERSION)
        if version not in SUPPORTED_VERSIONS:
            return Response(
                content=f'{{"error":"Unsupported API version: {version}","supported_versions":["1","2"]}}',
                status_code=400,
                media_type="application/json",
                headers={"X-API-Version": version},
            )

        response = await call_next(request)
        response.headers["X-API-Version"] = version
        response.headers["X-API-Deprecated"] = "true" if version == "1" else "false"
        response.headers["X-API-Sunset"] = "2027-01-01" if version == "1" else ""
        return response
