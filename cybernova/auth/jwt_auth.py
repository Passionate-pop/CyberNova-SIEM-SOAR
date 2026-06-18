"""
DEPRECATED: This module contains legacy JWT auth code that duplicates
security/encryption/jwt_handler.py. All new code should import from
security.encryption.jwt_handler instead.

This module is kept only for backward compatibility with tests and
legacy code paths that haven't been migrated yet.
"""
import os
import logging
from typing import Optional
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from cybernova.auth.rbac import (
    Permission,
    has_permission as rbac_has_permission,
    get_role_permissions,
    has_all_permissions,
    VALID_ROLES as RBAC_VALID_ROLES,
)

log = logging.getLogger("cybernova.auth")

# --- JWT_SECRET resolution ---

_WEAK_JWT_DEFAULTS = frozenset({
    "",
    "cybernova-secret-key-change-in-production",
    "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING",
})


def _resolve_jwt_secret() -> str:
    """Resolve JWT_SECRET at load time. Crashes in production if missing/weak."""
    # Production: crash if missing or too short. Dev: ephemeral fallback with loud warning.
    # Check JWT_SECRET first, then SECRET_KEY (pydantic Settings alias from .env)
    secret = os.environ.get("JWT_SECRET") or os.environ.get("SECRET_KEY")
    environment = os.environ.get("ENVIRONMENT", "development")
    is_production = environment == "production"

    if not secret:
        if is_production:
            raise RuntimeError(
                "JWT_SECRET environment variable is REQUIRED in production. "
                "Without it, JWT token validation is impossible and the application "
                "cannot operate securely. "
                "Generate a secure key:  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Development only: generate ephemeral key for convenience
        import secrets as _secrets
        ephemeral = _secrets.token_hex(32)
        log.warning(
            "[AUTH] JWT_SECRET not set — generated ephemeral key. "
            "This is acceptable for development ONLY. "
            "All sessions/tokens will be invalidated on next restart. "
            "Set JWT_SECRET in your .env file for persistent authentication."
        )
        return ephemeral

    # reject known weak defaults (commonly used in tutorials, targeted by attackers)
    if secret in _WEAK_JWT_DEFAULTS:
        if is_production:
            raise RuntimeError(
                "JWT_SECRET is set to a known weak default value. "
                "This is a CRITICAL security vulnerability — attackers can forge "
                "arbitrary JWT tokens. "
                "Generate a new secret:  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        log.warning(
            "[AUTH] JWT_SECRET is set to a known default '%s...' — "
            "this is INSECURE even for development. Update your .env file.",
            secret[:8],
        )

    # short secrets are vulnerable to brute-force
    if len(secret) < 32:
        if is_production:
            raise RuntimeError(
                f"JWT_SECRET is too short ({len(secret)} characters). "
                "HMAC-SHA256 keys must be at least 32 characters (256 bits) "
                "to prevent brute-force attacks. "
                f"Generate a new secret:  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        log.warning(
            "[AUTH] JWT_SECRET is only %d characters — minimum 32 recommended. "
            "Short secrets weaken HMAC-SHA256 protection.", len(secret)
        )

    return secret


SECRET_KEY = _resolve_jwt_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours


def is_valid_role(role: str) -> bool:
    """Check role is in RBAC registry, not hardcoded."""
    return role in RBAC_VALID_ROLES


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    from passlib.hash import bcrypt
    try:
        return bcrypt.verify(plain, hashed)
    except Exception as e:
        log.error("Password verification error: %s", e)
        return False


async def authenticate_user_from_db(username: str, password: str) -> Optional[dict]:
    """Authenticate user against DB. Returns dict with sub, role, roles list."""
    from cybernova.database.postgres.session import async_session_factory
    from cybernova.database.postgres.models import User
    from sqlalchemy import select
    from passlib.hash import bcrypt

    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalars().first()
        if not user:
            return None
        if not bcrypt.verify(password, user.hashed_password):
            return None

        # User model uses JSON 'roles' list — extract primary role for
        # backwards compatibility with code expecting a single 'role' string
        user_roles = user.roles if isinstance(user.roles, list) else ["viewer"]
        primary_role = user_roles[0] if user_roles else "viewer"

        return {
            "sub": user.username,
            "role": primary_role,
            "roles": user_roles,
        }


def create_token(username: str, role: str) -> str:
    """Create token for authenticated user."""
    return create_access_token({"sub": username, "role": role})


def decode_token(token: str) -> dict:
    """Decode and verify token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Validate role at decode boundary
        role = payload.get("role", "")
        if role and not is_valid_role(role):
            log.warning("[AUTH] Invalid role from JWT: %s", role)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
    """Get current authenticated user from token."""
    token = credentials.credentials
    return decode_token(token)


def require_role(required_role: str):
    """FastAPI dependency: require a role via RBAC permission validation.

    No hardcoded admin bypass — all checks go through the Permission enum.
    admin passes because admin owns every permission, not because of string comparison.
    """
    from cybernova.auth.rbac import Role as RBACRole, VALID_ROLES as RBAC_ROLES_SET

    if required_role not in RBAC_ROLES_SET:
        raise ValueError(
            f"require_role(): unknown role '{required_role}'. "
            f"Valid roles: {sorted(RBAC_ROLES_SET)}"
        )

    # Resolve all permissions required for this role at definition time (not per-request)
    try:
        role_enum = RBACRole(required_role)
        _required = get_role_permissions(role_enum.value)
    except (ValueError, KeyError) as exc:
        raise ValueError(f"require_role(): failed to resolve permissions for '{required_role}': {exc}")

    if not _required:
        raise ValueError(f"require_role(): role '{required_role}' has no defined permissions — check ROLE_PERMISSIONS in rbac.py")

    required_permissions = list(_required)

    def _checker(user: dict = Depends(get_current_user)):
        user_roles_raw = user.get("role", "")
        user_roles: list = [user_roles_raw] if isinstance(user_roles_raw, str) else (user_roles_raw or [])

        # No hardcoded admin bypass — all checks go through RBAC Permission system
        if not has_all_permissions(user_roles, required_permissions):
            log.warning(
                "[AUTH] require_role denied: user=%s required_role=%s user_roles=%s",
                user.get("sub", "unknown"), required_role, user_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Role '{required_role}' required.",
            )
        return user

    return _checker


def require_permission(permission: str):
    """Require a specific permission. Validates against Permission enum at def time."""
    # fail-fast validation — catch typos at import, not runtime
    # Validate permission string at definition time — fail fast, not at runtime
    try:
        perm_enum = Permission(permission)
    except ValueError:
        valid_perms = [p.value for p in Permission]
        raise ValueError(
            f"require_permission(): unknown permission '{permission}'. "
            f"Valid permissions: {sorted(valid_perms)}"
        )

    def _checker(user: dict = Depends(get_current_user)):
        user_role = user.get("role", "")
        user_roles = user.get("roles", [user_role]) if user.get("roles") else [user_role]
        if not rbac_has_permission(user_roles, perm_enum):
            log.warning(
                "[AUTH] Permission denied: user=%s permission=%s user_roles=%s",
                user.get("sub", "unknown"), permission, user_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required: '{permission}'.",
            )
        return user

    return _checker


# --- Security dependency for FastAPI ---
security = HTTPBearer(auto_error=False)


async def get_optional_user(request: Request):
    """Get user if authenticated, None otherwise."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        return decode_token(token)
    except HTTPException:
        return None


# --- Health check (no auth) ---
def is_authenticated(user: Optional[dict]) -> bool:
    """Check if request is authenticated."""
    return user is not None