"""
CyberNova — Organization Management Router
POST /api/v1/organizations/generate-key  — Generate org key for staff invitations
GET  /api/v1/organizations/keys           — List org keys
GET  /api/v1/organizations/settings       — Get org settings
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import OrganizationKey, Tenant, Device, User as UserModel
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.core.utils.helpers import generate_org_key, hash_org_key

log = logging.getLogger("cybernova.organizations")
router = APIRouter(prefix="/api/v1/organizations", tags=["Organizations"])


@router.post("/generate-key", summary="Generate organization key")
async def generate_org_key_endpoint(
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Generate a new organization key for staff invitations."""
    name = body.get("name", "default")
    raw_key = generate_org_key()
    key_hash = hash_org_key(raw_key)

    org_key = OrganizationKey(
        tenant_id=tenant_id,
        key_hash=key_hash,
        name=name,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        is_active=True,
    )
    db.add(org_key)
    await db.commit()

    log.info("Org key generated for tenant %s by %s", tenant_id, user.username)
    return {
        "org_key": raw_key,
        "name": name,
        "expires_at": org_key.expires_at.isoformat(),
    }


@router.get("/keys", summary="List organization keys")
async def list_org_keys(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """List all organization keys for the current tenant."""
    result = await db.execute(
        select(OrganizationKey).where(
            OrganizationKey.tenant_id == tenant_id
        ).order_by(OrganizationKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        {
            "id": k.id,
            "name": k.name,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat() if k.created_at else "",
        }
        for k in keys
    ]


@router.get("/settings", summary="Get organization settings")
async def get_org_settings(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get organization settings for the current tenant."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Count devices and users
    device_count = (await db.execute(
        select(func.count()).select_from(Device).where(Device.tenant_id == tenant_id)
    )).scalar() or 0

    user_count = (await db.execute(
        select(func.count()).select_from(UserModel).where(UserModel.tenant_id == tenant_id)
    )).scalar() or 0

    return {
        "tenant_id": tenant.id,
        "name": tenant.name or "",
        "domain": getattr(tenant, "domain", "") or "",
        "plan": getattr(tenant, "plan", "free") or "free",
        "device_count": device_count,
        "user_count": user_count,
    }
