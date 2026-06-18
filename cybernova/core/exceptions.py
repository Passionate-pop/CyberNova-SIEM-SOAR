"""
CyberNova — Custom Exceptions
Structured error classes mapped to HTTP status codes.
"""
from __future__ import annotations
from typing import Any, Optional


class CyberNovaError(Exception):
    status_code: int = 500
    detail: str = "Internal server error"

    def __init__(self, detail: Optional[str] = None, **kwargs: Any) -> None:
        self.detail = detail or self.__class__.detail
        self.extra = kwargs
        super().__init__(self.detail)


class NotFoundError(CyberNovaError):
    status_code = 404
    detail = "Resource not found"


class ValidationError(CyberNovaError):
    status_code = 422
    detail = "Validation error"


class AuthenticationError(CyberNovaError):
    status_code = 401
    detail = "Could not validate credentials"


class AuthorizationError(CyberNovaError):
    status_code = 403
    detail = "Insufficient permissions"


class RateLimitError(CyberNovaError):
    status_code = 429
    detail = "Rate limit exceeded"


class DatabaseError(CyberNovaError):
    status_code = 503
    detail = "Database service unavailable"


class ExternalServiceError(CyberNovaError):
    status_code = 502
    detail = "External service error"


class CSRFProtectionError(CyberNovaError):
    status_code = 403
    detail = "CSRF validation failed"


class TenantError(CyberNovaError):
    status_code = 403
    detail = "Missing or invalid tenant context"
