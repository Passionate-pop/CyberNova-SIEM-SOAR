"""
CyberNova — Policy Admin Router
Manage security policies via API.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin, require_settings_view, require_settings_update
from cybernova.policy_engine.engine import policy_manager

router = APIRouter(prefix="/api/v1/admin/policies", tags=["Admin Policies"])


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    conditions: dict
    actions: List[str]
    cooldown_seconds: int = 300


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool
    conditions: dict
    actions: List[str]
    cooldown_seconds: int
    created_at: str


class PolicyToggle(BaseModel):
    enabled: bool


@router.get("", response_model=List[PolicyResponse], summary="List policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_settings_view),
):
    """List all policies for the tenant."""
    
    policies = await policy_manager.get_policies(user.tenant_id, db)
    
    return [
        PolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description or "",
            enabled=p.enabled,
            conditions=p.conditions,
            actions=p.actions,
            cooldown_seconds=p.cooldown_seconds,
            created_at=p.created_at.isoformat(),
        )
        for p in policies
    ]


@router.post("", response_model=PolicyResponse, summary="Create policy")
async def create_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """Create a new policy."""
    
    policy = await policy_manager.create_policy(
        tenant_id=user.tenant_id,
        name=payload.name,
        description=payload.description,
        conditions=payload.conditions,
        actions=payload.actions,
        created_by=user.id,
        cooldown_seconds=payload.cooldown_seconds,
        db=db
    )
    
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description or "",
        enabled=policy.enabled,
        conditions=policy.conditions,
        actions=policy.actions,
        cooldown_seconds=policy.cooldown_seconds,
        created_at=policy.created_at.isoformat(),
    )


@router.post("/{policy_id}/toggle", summary="Toggle policy")
async def toggle_policy(
    policy_id: str,
    payload: PolicyToggle,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_settings_update),
):
    """Enable or disable a policy."""
    
    policy = await policy_manager.toggle_policy(
        policy_id, user.tenant_id, payload.enabled, db
    )
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    return {"status": "ok", "enabled": policy.enabled}


@router.get("/defaults", summary="Create default policies")
async def create_default_policies(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
):
    """Create default policies for the tenant."""
    
    policies = await policy_manager.get_default_policies(user.tenant_id, db)
    
    return {"created": len(policies)}