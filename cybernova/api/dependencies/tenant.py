"""
CyberNova — Tenant Isolation Dependency
Extracts tenant_id from JWT and injects it into every service call.
Rejects any request missing tenant context.
"""
from __future__ import annotations

import logging
from fastapi import Depends
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.core.exceptions import TenantError

log = logging.getLogger("cybernova.api.tenant")


async def get_tenant_id(user: CurrentUser = Depends(get_current_user)) -> str:
    """Extract and validate tenant_id from authenticated user.
    Inject this dependency into any route that needs tenant context.
    """
    if not user.tenant_id:
        log.critical("Request without tenant context from user=%s", user.username)
        raise TenantError("Missing tenant context")
    return user.tenant_id
