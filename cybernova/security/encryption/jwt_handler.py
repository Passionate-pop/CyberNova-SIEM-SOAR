"""
CyberNova — JWT & Password Security
Token creation, validation, password hashing, HMAC verification.
"""

import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
from fastapi import Depends, Request, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import JWTError, jwt
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cybernova.config.settings import get_settings
from cybernova.core.exceptions import AuthenticationError, AuthorizationError
from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import APIKey, Tenant

log = logging.getLogger("cybernova.security.jwt")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Pydantic Models ──────────────────────────────────────────────────────────

class TokenData(BaseModel):
    user_id: str
    username: str
    tenant_id: str
    roles: List[str] = []
    model_config = ConfigDict(extra="forbid")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    org_key: str = ""
    purpose: str = ""
    org_type: str = ""
    org_name: str = ""
    company_size: str = ""
    model_config = ConfigDict(extra="forbid")


class CurrentUser(BaseModel):
    id: str
    tenant_id: str
    username: str
    email: str = ""
    roles: List[str] = []
    is_active: bool = True
    purpose: str = ""
    org_type: str = ""
    org_name: str = ""
    company_size: str = ""
    
    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles
    
    @property
    def is_analyst(self) -> bool:
        return "analyst" in self.roles
    
    @property
    def role(self) -> str:
        if self.is_admin:
            return "admin"
        if self.is_analyst:
            return "analyst"
        return "viewer"
    
    model_config = ConfigDict(extra="forbid")


# ── Password Hashing ────────────────────────────────────────────────────────

# Workaround: passlib 1.7.x is incompatible with bcrypt >= 4.1.
# Use bcrypt directly for hashing and verification.
_BCRYPT_ROUNDS = 12

def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception as exc:
        log.warning("Password verification failed: %s", exc)
        return False


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


# ── HMAC Verification ───────────────────────────────────────────────────────

def verify_hmac_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


# ── JWT Tokens ───────────────────────────────────────────────────────────────

def create_tokens(data: dict) -> tuple[str, str]:
    settings = get_settings()
    now = datetime.now(timezone.utc)

    access_payload = data.copy()
    access_payload.update({
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "nbf": now, "iat": now,
        "iss": "cybernova-auth", "aud": "cybernova-api", "type": "access",
    })
    access_token = jwt.encode(access_payload, settings.secret_key, algorithm="HS256")

    # Refresh token carries ALL user claims so token refresh preserves purpose/roles/org context
    refresh_payload = {
        "user_id": data.get("user_id"),
        "tenant_id": data.get("tenant_id"),
        "username": data.get("username", ""),
        "email": data.get("email", ""),
        "roles": data.get("roles", ["viewer"]),
        "purpose": data.get("purpose", "individual"),
        "org_type": data.get("org_type", ""),
        "org_name": data.get("org_name", ""),
        "company_size": data.get("company_size", ""),
    }
    refresh_payload.update({
        "exp": now + timedelta(days=7),
        "nbf": now, "iat": now,
        "iss": "cybernova-auth", "aud": "cybernova-api", "type": "refresh",
    })
    refresh_token = jwt.encode(refresh_payload, settings.secret_key, algorithm="HS256")

    log.info("Tokens issued for user=%s tenant=%s", data.get("user_id"), data.get("tenant_id"))
    return access_token, refresh_token


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(
        token, settings.secret_key, algorithms=["HS256"],
        audience="cybernova-api", issuer="cybernova-auth",
    )

def decode_refresh_token(token: str) -> dict:
    """Decode refresh token"""
    settings = get_settings()
    return jwt.decode(
        token, settings.secret_key, algorithms=["HS256"],
        audience="cybernova-api", issuer="cybernova-auth",
    )

def refresh_access_token(refresh_token: str) -> tuple[str, str] | None:
    """Generate new access token from refresh token"""
    try:
        payload = decode_refresh_token(refresh_token)
        if payload.get("type") != "refresh":
            return None
        
        # Build new token data preserving ALL user claims from the original access token
        # (the refresh token only stores user_id + tenant_id; we must look up the rest from DB)
        token_data = {
            "user_id": payload.get("user_id"),
            "tenant_id": payload.get("tenant_id"),
            "username": payload.get("username", ""),
            "roles": payload.get("roles", ["viewer"]),
            "purpose": payload.get("purpose", "individual"),
            "org_type": payload.get("org_type", ""),
            "org_name": payload.get("org_name", ""),
            "company_size": payload.get("company_size", ""),
        }
        return create_tokens(token_data)
    except Exception as e:
        log.error("Token refresh failed: %s", e)
        return None


# ── FastAPI Dependencies ────────────────────────────────────────────────────

async def verify_api_key(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> Optional[APIKey]:
    if not api_key:
        return None
    hashed = hash_api_key(api_key)
    stmt = select(APIKey).where(APIKey.key_hash == hashed, APIKey.is_active)
    result = await db.execute(stmt)
    key_obj = result.scalars().first()
    if key_obj:
        tenant_stmt = select(Tenant).where(Tenant.id == key_obj.tenant_id, Tenant.is_active)
        tenant_res = await db.execute(tenant_stmt)
        if tenant_res.scalars().first():
            key_obj.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            return key_obj
    log.warning("Invalid API key attempt")
    return None


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    api_key_obj: Optional[APIKey] = Depends(verify_api_key),
) -> CurrentUser:
    if api_key_obj:
        return CurrentUser(
            id=f"api_key_{api_key_obj.id}",
            tenant_id=api_key_obj.tenant_id,
            username=f"api_client_{api_key_obj.name}",
            roles=["ingest_client"],
        )
    if not token:
        raise AuthenticationError("Missing authentication token")
    try:
        payload = decode_access_token(token)
        if payload.get("type") != "access":
            raise JWTError("Invalid token type")
        user_id = payload.get("user_id")
        username = payload.get("username")
        tenant_id = payload.get("tenant_id")
        if not user_id or not username or not tenant_id:
            raise AuthenticationError()

        raw_roles = payload.get("roles", [])
        from cybernova.auth.rbac import VALID_ROLES
        roles = list(set(r for r in raw_roles if isinstance(r, str) and r in VALID_ROLES))
        if not roles:
            log.warning("JWT has no valid roles for user=%s — defaulting to viewer", user_id)
            roles = ["viewer"]

        return CurrentUser(
            id=user_id, tenant_id=tenant_id, username=username,
            email=payload.get("email", ""),
            roles=roles,
            is_active=payload.get("is_active", True),
            purpose=payload.get("purpose", ""),
            org_type=payload.get("org_type", ""),
            org_name=payload.get("org_name", ""),
            company_size=payload.get("company_size", ""),
        )
    except JWTError as exc:
        log.warning("JWT validation failed: %s from %s", exc, request.client.host if request.client else "unknown")
        raise AuthenticationError()


def require_roles(*required_roles: str):
    """Validate user roles against canonical RBAC engine."""
    from cybernova.auth.rbac import VALID_ROLES

    validated = []
    for r in required_roles:
        if r not in VALID_ROLES:
            log.warning("require_roles: invalid role '%s' — skipping", r)
            continue
        validated.append(r)
    if not validated:
        log.critical("require_roles: no valid roles provided")
        raise ValueError("No valid roles specified in require_roles()")

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not any(r in user.roles for r in validated):
            log.critical("RBAC blocked: user=%s required=%s", user.username, validated)
            raise AuthorizationError("Insufficient permissions")
        return user
    return _check


require_admin = require_roles("admin")
require_analyst = require_roles("admin", "analyst")
