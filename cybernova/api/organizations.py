"""
CyberNova — Organization Router
Admin endpoints for managing org keys
"""
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import OrganizationKey, Tenant, Device, User
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.audit.service import audit_service
from cybernova.core.utils.helpers import generate_org_key, hash_org_key

router = APIRouter(prefix="/api/v1/organizations", tags=["Organizations"])


class GenerateOrgKeyRequest(BaseModel):
    name: str = Field(default="default")


class OrgKeyResponse(BaseModel):
    org_key: str
    name: str
    expires_at: str


class OrgSettingsResponse(BaseModel):
    tenant_id: str
    name: str
    domain: str = ""
    plan: str
    device_count: int
    user_count: int


@router.post("/generate-key", summary="Generate new org key", response_model=OrgKeyResponse)
async def create_org_key(
    payload: GenerateOrgKeyRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user)
):
    """Generate a new organization key."""
    
    org_key = generate_org_key()  # from helpers
    key_hash = hash_org_key(org_key)
    
    new_key = OrganizationKey(
        tenant_id=user.tenant_id,
        key_hash=key_hash,
        name=payload.name,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    )
    
    db.add(new_key)
    await db.commit()
    
    await audit_service.log(
        db=db,
        action="org_key_created",
        tenant_id=user.tenant_id,
        user_id=user.id,
        resource_type="organization_key",
        details={"name": payload.name},
    )
    
    return OrgKeyResponse(
        org_key=org_key,
        name=payload.name,
        expires_at=new_key.expires_at.isoformat()
    )


@router.get("/settings", summary="Get organization settings", response_model=OrgSettingsResponse)
async def get_org_settings(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user)
):
    """Get organization settings."""
    
    from sqlalchemy import select, func
    
    tenant_id = user.tenant_id
    
    stmt = select(Tenant).where(Tenant.id == tenant_id)
    result = await db.execute(stmt)
    tenant = result.scalar_one_or_none()
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    device_count_stmt = select(func.count()).select_from(Device).where(Device.tenant_id == tenant_id)
    device_result = await db.execute(device_count_stmt)
    device_count = device_result.scalar()
    
    user_count_stmt = select(func.count()).select_from(User).where(User.tenant_id == tenant_id)
    user_result = await db.execute(user_count_stmt)
    user_count = user_result.scalar()
    
    return OrgSettingsResponse(
        tenant_id=tenant.id,
        name=tenant.name,
        domain=tenant.domain or "",
        plan=tenant.plan,
        device_count=device_count,
        user_count=user_count,
    )


@router.get("/keys", summary="List org keys")
async def list_org_keys(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user)
):
    """List organization keys."""
    
    from sqlalchemy import select
    
    stmt = select(OrganizationKey).where(
        OrganizationKey.tenant_id == user.tenant_id,
        OrganizationKey.is_active
    )
    result = await db.execute(stmt)
    keys = result.scalars().all()
    
    return [
        {
            "id": k.id,
            "name": k.name,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat(),
        }
        for k in keys
    ]