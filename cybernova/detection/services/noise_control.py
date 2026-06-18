"""
CyberNova — Noise Control: Whitelist & Suppression
Checks before generating alerts.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    WhitelistEntry, AlertSuppression, Alert,
)

log = logging.getLogger("cybernova.detection.noise")


async def is_whitelisted(
    db: AsyncSession,
    tenant_id: str,
    entity: str,
    entity_type: str = "ip",
) -> bool:
    """Check if entity is permanently whitelisted."""
    result = await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.tenant_id == tenant_id,
            WhitelistEntry.entity == entity,
            WhitelistEntry.entity_type == entity_type,
        )
    )
    return result.scalar_one_or_none() is not None


async def is_suppressed(
    db: AsyncSession,
    tenant_id: str,
    entity: str,
    rule_id: str = None,
) -> bool:
    """Check if entity is temporarily suppressed (snoozed)."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AlertSuppression).where(
            AlertSuppression.tenant_id == tenant_id,
            AlertSuppression.entity == entity,
            (AlertSuppression.expires_at.is_(None) | (AlertSuppression.expires_at > now)),
        )
    )
    suppression = result.scalar_one_or_none()
    if not suppression:
        return False
    if rule_id and suppression.rule_id and suppression.rule_id != rule_id:
        return False
    return True


async def should_suppress_alert(
    db: AsyncSession,
    tenant_id: str,
    alert: Alert,
) -> bool:
    """Check whitelist or suppression before creating alert."""
    entity = alert.extra_data.get("source_ip") if alert.extra_data else None
    if not entity:
        return False
    if await is_whitelisted(db, tenant_id, entity, "ip"):
        log.info("Alert suppressed: IP %s is whitelisted", entity)
        return True
    if await is_suppressed(db, tenant_id, entity, alert.rule_name):
        log.info("Alert suppressed: IP %s is snoozed", entity)
        return True
    return False
