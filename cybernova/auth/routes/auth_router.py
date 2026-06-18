"""
CyberNova — Auth Router
POST /api/v1/auth/register
POST /api/v1/auth/login
"""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.auth.schemas import LoginRequest, RegisterRequest
from cybernova.auth.services.auth_service import auth_service
from cybernova.security.rate_limit.limiter import get_limiter
from cybernova.audit.service import audit_service

log = logging.getLogger("cybernova.auth.router")

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
limiter = get_limiter()


from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser


@router.get("/me", summary="Get current user profile")
async def get_me(user: CurrentUser = Depends(get_current_user)):
    """Return the current authenticated user's profile from the JWT."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "roles": user.roles,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "purpose": user.purpose,
        "org_type": user.org_type,
        "org_name": user.org_name,
        "company_size": user.company_size,
    }


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.post("/register", summary="Register user")
@limiter.limit("10/minute")
async def register(request: Request, payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await auth_service.register(
        db, payload.username, payload.email, payload.password,
        tenant_name=payload.tenant_name, roles=payload.roles,
        org_key=payload.org_key, company_size=payload.company_size,
    )
    
    from cybernova.security.encryption.jwt_handler import decode_access_token
    token_data = decode_access_token(result.access_token)
    await audit_service.log(
        db=db,
        action="user_created",
        tenant_id=token_data.get("tenant_id", "default"),
        user_id=token_data.get("user_id"),
        resource_type="user",
        resource_id=token_data.get("user_id"),
        details={"username": payload.username, "email": payload.email},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    
    return result


@router.post("/login", summary="Login")
@limiter.limit("20/minute")
async def login(request: Request, payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    from fastapi import HTTPException, status
    from sqlalchemy.exc import OperationalError
    ip = get_client_ip(request)
    
    try:
        result = await auth_service.login(db, payload.username, payload.password, ip=ip, org_key=payload.org_key)
    except (OperationalError, ConnectionRefusedError, OSError) as exc:
        # DB unavailable — still return 401, never 500. Track as brute force attempt.
        log.warning("LOGIN FAILED (DB down): %s from %s — %s", payload.username, ip, exc)
        try:
            from cybernova.protection.brute_force_mesh import brute_force_mesh
            brute_force_mesh.record_failure(ip, payload.username)
        except Exception as bf_err:
            log.warning("Brute force mesh record_failure failed (non-critical): %s", bf_err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    except HTTPException:
        # Auth service already raised proper HTTP error (401/429/403) — track in brute force mesh
        try:
            from cybernova.protection.brute_force_mesh import brute_force_mesh
            brute_force_mesh.record_failure(ip, payload.username)
        except Exception as bf_err:
            log.warning("Brute force mesh record_failure failed (non-critical): %s", bf_err)
        # Still attempt audit silently
        try:
            await audit_service.log(
                db=db,
                action="login_failed",
                tenant_id="default",
                resource_type="user",
                details={"username": payload.username},
                ip_address=ip,
            )
            await db.commit()
        except Exception:
            await db.rollback()
        raise
    except Exception as exc:
        # Any other unexpected error — return 401, never 500
        log.error("LOGIN ERROR (unexpected): %s from %s — %s", payload.username, ip, exc)
        try:
            from cybernova.protection.brute_force_mesh import brute_force_mesh
            brute_force_mesh.record_failure(ip, payload.username)
        except Exception as bf_err:
            log.warning("Brute force mesh record_failure failed (non-critical): %s", bf_err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    from cybernova.security.encryption.jwt_handler import decode_access_token
    token_data = decode_access_token(result.access_token)
    
    # Track successful login: clear any brute force counter
    try:
        from cybernova.protection.brute_force_mesh import brute_force_mesh
        brute_force_mesh.record_success(ip, payload.username)
    except Exception as bf_err:
        log.warning("Brute force mesh record_success failed (non-critical): %s", bf_err)
    
    # Audit successful login — must never break the auth flow
    try:
        await audit_service.log(
            db=db,
            action="login",
            tenant_id=token_data.get("tenant_id", "default"),
            user_id=token_data.get("user_id"),
            resource_type="user",
            resource_id=token_data.get("user_id"),
            details={"username": payload.username},
            ip_address=ip,
        )
        await db.commit()
    except Exception as audit_err:
        log.warning("Failed to audit login success (non-blocking): %s", audit_err)
        await db.rollback()
    
    return result


@router.post("/refresh", summary="Refresh access token")
@limiter.limit("5/minute")
async def refresh(request: Request, payload: dict):
    """Refresh access token using refresh token"""
    from fastapi import HTTPException, status
    from cybernova.security.encryption.jwt_handler import refresh_access_token
    
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing refresh_token")
    
    new_tokens = refresh_access_token(refresh_token)
    if not new_tokens:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token")
    
    return {
        "access_token": new_tokens[0],
        "refresh_token": new_tokens[1],
        "token_type": "bearer",  # nosec
    }
