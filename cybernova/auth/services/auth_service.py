"""
CyberNova — Auth Service
Registration, login, tenant provisioning.
With account lockout protection after failed attempts.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from cybernova.database.postgres.models import User, Tenant, OrganizationKey
from cybernova.security.encryption.jwt_handler import (
    hash_password, verify_password, create_tokens, TokenResponse,
)
from cybernova.core.utils.helpers import new_id, utcnow, generate_org_key, hash_org_key

log = logging.getLogger("cybernova.auth.service")

# ── Account Lockout (Redis-backed, survives restarts) ────────────────────────
# Falls back to in-memory dict when Redis is unavailable.
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 900  # 15 minutes
_LOCKOUT_PREFIX = "cybernova:lockout:"

# In-memory fallback (only used when Redis is down)
_failed_attempts_local: dict = {}


async def _get_redis_lockout():
    """Get Redis client for lockout tracking, or None if unavailable."""
    try:
        from cybernova.database.redis import get_redis
        return await get_redis()
    except Exception:
        return None


async def _check_lockout(username: str) -> tuple[int, float]:
    """Return (attempts, lockout_time) for a username.
    Uses Redis when available, falls back to in-memory dict.
    """
    redis = await _get_redis_lockout()
    if redis:
        try:
            key = f"{_LOCKOUT_PREFIX}{username}"
            data = await redis.hgetall(key)
            if data:
                attempts = int(data.get("attempts", 0))
                lockout_time = float(data.get("lockout_time", 0))
                return attempts, lockout_time
            return 0, 0.0
        except Exception as e:
            log.debug("[LOCKOUT] Redis read failed for %s: %s", username, e)

    # In-memory fallback
    if username in _failed_attempts_local:
        return _failed_attempts_local[username]
    return 0, 0.0


async def _record_failed_attempt(username: str) -> int:
    """Increment failed login attempts atomically. Returns new attempt count."""
    redis = await _get_redis_lockout()
    if redis:
        try:
            key = f"{_LOCKOUT_PREFIX}{username}"
            # Atomic increment — no race condition
            attempts = await redis.hincrby(key, "attempts", 1)
            await redis.expire(key, LOCKOUT_DURATION * 2)  # TTL = 2x lockout
            # Set lockout_time only when crossing threshold (once)
            if attempts >= LOCKOUT_THRESHOLD:
                existing = await redis.hget(key, "lockout_time")
                if not existing or float(existing) == 0:
                    await redis.hset(key, "lockout_time", str(time.time()))
            return attempts
        except Exception as e:
            log.debug("[LOCKOUT] Redis write failed for %s: %s", username, e)

    # In-memory fallback
    attempts, lockout_time = await _check_lockout(username)
    attempts += 1
    lt = time.time() if attempts >= LOCKOUT_THRESHOLD else 0
    _failed_attempts_local[username] = (attempts, lt)
    return attempts


async def _clear_lockout(username: str) -> None:
    """Clear failed login attempts on successful login."""
    redis = await _get_redis_lockout()
    if redis:
        try:
            await redis.delete(f"{_LOCKOUT_PREFIX}{username}")
        except Exception:
            pass
    _failed_attempts_local.pop(username, None)


class AuthService:

    async def register(
        self, db: AsyncSession, username: str, email: str,
        password: str, tenant_name: str = "default", roles: list = None,  # nosec
        org_key: str = "", company_size: str = "",
    ) -> TokenResponse:
        """Register a new user, provisioning a tenant if needed.
        
        Args:
            org_key: If provided, links user to existing org instead of creating new tenant.
            company_size: Company size for org billing (only for admin creating new org).
        """
        existing = await db.execute(
            select(User).where((User.username == username) | (User.email == email))
        )
        if existing.scalars().first():
            from fastapi import HTTPException, status
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="Username or email already registered")

        tenant = None
        is_new_org = False
        generated_org_key = ""

        if org_key:
            # Staff joining existing org via org_key
            key_hash = hash_org_key(org_key)
            key_result = await db.execute(
                select(OrganizationKey).where(OrganizationKey.key_hash == key_hash)
            )
            key_obj = key_result.scalar_one_or_none()
            if key_obj:
                tenant_result = await db.execute(
                    select(Tenant).where(Tenant.id == key_obj.tenant_id)
                )
                tenant = tenant_result.scalar_one_or_none()

        if not tenant:
            tenant_result = await db.execute(
                select(Tenant).where(Tenant.name == tenant_name)
            )
            tenant = tenant_result.scalars().first()

        if not tenant:
            # New tenant — auto-generate org key for admin
            tenant = Tenant(
                id=new_id(), name=tenant_name, plan="free",
                company_size=company_size, is_active=True, created_at=utcnow(),
            )
            db.add(tenant)
            await db.flush()
            is_new_org = True

        try:
            user = User(
                id=new_id(), tenant_id=tenant.id, username=username,
                email=email, hashed_password=hash_password(password),
                roles=roles or ["viewer"], is_active=True, created_at=utcnow(),
            )
            db.add(user)
            await db.flush()

            # Auto-generate org key for new orgs (admin registration)
            if is_new_org and ("admin" in (roles or [])):
                generated_org_key = generate_org_key()
                key_hash = hash_org_key(generated_org_key)
                org_key_obj = OrganizationKey(
                    tenant_id=tenant.id,
                    key_hash=key_hash,
                    name="default",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                )
                db.add(org_key_obj)
                await db.flush()
        except IntegrityError:
            await db.rollback()
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already registered"
            )

        # Determine user's purpose and org_type for JWT
        is_admin = "admin" in (roles or [])
        purpose = "organization" if (org_key or is_new_org) else "individual"
        org_type = "boss" if (is_admin and purpose == "organization") else ("staff" if purpose == "organization" else "")

        access_token, refresh_token = create_tokens({
            "user_id": user.id, "tenant_id": tenant.id,
            "username": user.username, "email": user.email,
            "roles": user.roles,
            "purpose": purpose,
            "org_type": org_type,
            "org_name": tenant.name,
            "company_size": tenant.company_size or "",
        })
        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token,
            token_type="bearer", expires_in=30 * 60,  # nosec
            org_key=generated_org_key,
            purpose=purpose,
            org_type=org_type,
            org_name=tenant.name,
            company_size=tenant.company_size or "",
        )

    async def login(
        self, db: AsyncSession, username: str, password: str,  # nosec
        ip: str = "", org_key: str = "",
    ) -> TokenResponse:
        from fastapi import HTTPException, status
        
        # Check for account lockout (Redis-backed)
        attempts, lockout_time = await _check_lockout(username)
        if attempts >= LOCKOUT_THRESHOLD:
            lockout_remaining = LOCKOUT_DURATION - (time.time() - lockout_time)
            if lockout_remaining > 0:
                log.warning("LOGIN BLOCKED: %s locked until %ds", username, lockout_remaining)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account locked. Try again in {int(lockout_remaining/60)} minutes"
                )
            else:
                # Lockout expired — clear it
                await _clear_lockout(username)
        
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if not user or not verify_password(password, user.hashed_password):
            # Track failed attempt (Redis-backed, atomic HINCRBY)
            current_attempts = await _record_failed_attempt(username)
            log.warning("LOGIN FAILED: %s from %s (attempt %d)", username, ip, current_attempts)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid username or password")
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Account is disabled")

        # If org_key provided during login, validate it and ensure it matches user's tenant
        if org_key:
            key_hash = hash_org_key(org_key)
            key_result = await db.execute(
                select(OrganizationKey).where(
                    OrganizationKey.key_hash == key_hash,
                    OrganizationKey.is_active,
                )
            )
            key_obj = key_result.scalar_one_or_none()
            if not key_obj:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid organization key"
                )
            if key_obj.tenant_id != user.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Organization key does not match your account's organization"
                )
        
        # Clear failed attempts on successful login (Redis-backed)
        await _clear_lockout(username)

        # Determine org context for JWT
        tenant_result = await db.execute(
            select(Tenant).where(Tenant.id == user.tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()

        # Determine purpose and org_type
        is_admin = "admin" in (user.roles or [])
        if tenant and tenant.name != "default" and tenant.name != "personal":
            purpose = "organization"
            org_type = "boss" if is_admin else "staff"
        else:
            purpose = "individual"
            org_type = ""
        
        access_token, refresh_token = create_tokens({
            "user_id": user.id, "tenant_id": user.tenant_id,
            "username": user.username, "email": user.email,
            "roles": user.roles,
            "purpose": purpose,
            "org_type": org_type,
            "org_name": tenant.name if tenant else "",
            "company_size": tenant.company_size if tenant else "",
        })
        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token,
            token_type="bearer", expires_in=30 * 60,  # nosec
            purpose=purpose,
            org_type=org_type,
            org_name=tenant.name if tenant else "",
            company_size=tenant.company_size if tenant else "",
        )


auth_service = AuthService()
