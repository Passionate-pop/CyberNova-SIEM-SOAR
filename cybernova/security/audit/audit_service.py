"""
CyberNova — Audit Logging Service
Records security-relevant actions for compliance and forensics.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import AuditLog
from cybernova.core.utils.helpers import new_id, utcnow

log = logging.getLogger("cybernova.security.audit")


class AuditService:
    """Records audit events into the audit_logs table."""

    async def record(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        entry = AuditLog(
            id=new_id(),
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            timestamp=utcnow(),
        )
        db.add(entry)
        try:
            async with db.begin_nested():
                await db.flush()
            log.info("AUDIT: %s by user=%s tenant=%s on %s/%s",
                     action, user_id, tenant_id, resource_type, resource_id)
        except IntegrityError:
            log.warning(
                "AUDIT skipped (FK constraint): tenant=%s not found for action=%s user=%s",
                tenant_id, action, user_id,
            )


audit_service = AuditService()
