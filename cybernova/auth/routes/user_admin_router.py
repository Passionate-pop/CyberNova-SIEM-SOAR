"""
CyberNova — User & Role Management Admin API
CRUD for users, role management with RBAC enforcement.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import User as UserModel
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import (
    require_users_view, require_users_create, require_users_update, require_users_delete,
    require_admin,
)
from cybernova.auth.rbac import list_roles, Role, ROLE_PERMISSIONS, Permission
from cybernova.audit.service import audit_service
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.auth.user_admin")
router = APIRouter(prefix="/api/v1/admin/users", tags=["User Admin"])


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    roles: List[str] = ["viewer"]


class UpdateUserRequest(BaseModel):
    email: Optional[str] = None
    is_active: Optional[bool] = None


class UpdateRolesRequest(BaseModel):
    roles: List[str]


class UpdateRolePermissionsRequest(BaseModel):
    permissions: List[str]


@router.get("/", summary="List users")
async def list_users(
    tenant_filter: Optional[str] = Query(None, alias="tenant_id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_view),
    current_tenant_id: str = Depends(get_tenant_id),
):
    query = select(UserModel).where(UserModel.tenant_id == current_tenant_id)
    if tenant_filter:
        query = query.where(UserModel.tenant_id == tenant_filter)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(UserModel.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    users = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "roles": u.roles or [],
                "is_active": u.is_active,
                "is_disabled": u.is_disabled,
                "tenant_id": u.tenant_id,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "updated_at": u.updated_at.isoformat() if u.updated_at else None,
            }
            for u in users
        ],
    }


@router.get("/{user_id}", summary="Get user detail")
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_view),
    current_tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.tenant_id == current_tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": target.id,
        "username": target.username,
        "email": target.email,
        "roles": target.roles or [],
        "is_active": target.is_active,
        "is_disabled": target.is_disabled,
        "tenant_id": target.tenant_id,
        "created_at": target.created_at.isoformat() if target.created_at else None,
        "updated_at": target.updated_at.isoformat() if target.updated_at else None,
    }


@router.post("/", summary="Create user", status_code=201)
async def create_user(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_create),
    current_tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.security.hasher import hash_password

    existing = await db.execute(
        select(UserModel).where(
            UserModel.tenant_id == current_tenant_id,
            UserModel.email == body.email,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists")

    user_model = UserModel(
        id=new_id(),
        tenant_id=current_tenant_id,
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        roles=body.roles,
        is_active=True,
    )
    db.add(user_model)
    await db.flush()

    await audit_service.log(
        db=db,
        action="user_created",
        tenant_id=current_tenant_id,
        user_id=user.id,
        resource_type="user",
        resource_id=user_model.id,
        details={"username": body.username, "email": body.email, "roles": body.roles},
    )
    await db.commit()

    return {
        "id": user_model.id,
        "username": user_model.username,
        "email": user_model.email,
        "roles": user_model.roles,
        "is_active": user_model.is_active,
    }


@router.put("/{user_id}", summary="Update user")
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_update),
    current_tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.tenant_id == current_tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if body.email is not None:
        target.email = body.email
    if body.is_active is not None:
        target.is_active = body.is_active

    await db.flush()
    await audit_service.log(
        db=db,
        action="user_updated",
        tenant_id=current_tenant_id,
        user_id=user.id,
        resource_type="user",
        resource_id=user_id,
        details={"email": body.email, "is_active": body.is_active},
    )
    await db.commit()

    return {"status": "updated", "user_id": user_id}


@router.put("/{user_id}/roles", summary="Update user roles")
async def update_user_roles(
    user_id: str,
    body: UpdateRolesRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_update),
    current_tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.tenant_id == current_tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    valid_roles = {r.value for r in Role}
    for r in body.roles:
        if r not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role: {r}")

    target.roles = body.roles
    await db.flush()
    await audit_service.log(
        db=db,
        action="user_roles_updated",
        tenant_id=current_tenant_id,
        user_id=user.id,
        resource_type="user",
        resource_id=user_id,
        details={"roles": body.roles},
    )
    await db.commit()

    return {"status": "updated", "user_id": user_id, "roles": body.roles}


@router.delete("/{user_id}", summary="Delete user")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_users_delete),
    current_tenant_id: str = Depends(get_tenant_id),
):
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.tenant_id == current_tenant_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(target)
    await db.flush()
    await audit_service.log(
        db=db,
        action="user_deleted",
        tenant_id=current_tenant_id,
        user_id=user.id,
        resource_type="user",
        resource_id=user_id,
        details={"username": target.username, "email": target.email},
    )
    await db.commit()

    return {"status": "deleted", "user_id": user_id}


@router.get("/roles", summary="List all roles with permissions")
async def get_roles(
    user: CurrentUser = Depends(get_current_user),
):
    return {"roles": list_roles()}


@router.post("/roles/{role}/permissions", summary="Update permissions for a role")
async def update_role_permissions(
    role: str,
    body: UpdateRolePermissionsRequest,
    user: CurrentUser = Depends(require_admin),
):
    try:
        role_enum = Role(role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {role}")

    valid_permissions = {p.value for p in Permission}
    for p in body.permissions:
        if p not in valid_permissions:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {p}")

    ROLE_PERMISSIONS[role_enum] = {Permission(p) for p in body.permissions}
    log.info("Permissions updated for role %s by %s", role, user.username)

    return {
        "status": "updated",
        "role": role,
        "permissions": body.permissions,
    }
