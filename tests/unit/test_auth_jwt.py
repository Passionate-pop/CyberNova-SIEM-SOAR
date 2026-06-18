"""Comprehensive unit tests for auth/jwt_auth.py — targeting 80%+ line coverage."""

import os
from datetime import timedelta, timezone
from unittest.mock import patch, MagicMock

import jwt
import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from cybernova.auth.jwt_auth import (
    _resolve_jwt_secret, is_valid_role, create_access_token,
    verify_password, create_token, decode_token,
    get_current_user, require_role, require_permission,
    get_optional_user, is_authenticated,
    SECRET_KEY, ALGORITHM,
)


class TestResolveJwtSecret:
    def test_production_with_secret(self):
        with patch.dict(os.environ, {"JWT_SECRET": "a" * 32, "ENVIRONMENT": "production"}, clear=True):
            secret = _resolve_jwt_secret()
            assert len(secret) >= 32

    def test_production_no_secret_raises(self):
        with patch.dict(os.environ, {"JWT_SECRET": "", "ENVIRONMENT": "production"}, clear=True):
            with pytest.raises(RuntimeError, match="JWT_SECRET environment variable is REQUIRED"):
                _resolve_jwt_secret()

    def test_production_weak_default_raises(self):
        with patch.dict(os.environ, {"JWT_SECRET": "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING", "ENVIRONMENT": "production"}, clear=True):
            with pytest.raises(RuntimeError, match="known weak default"):
                _resolve_jwt_secret()

    def test_production_too_short_raises(self):
        with patch.dict(os.environ, {"JWT_SECRET": "short", "ENVIRONMENT": "production"}, clear=True):
            with pytest.raises(RuntimeError, match="too short"):
                _resolve_jwt_secret()

    def test_development_ephemeral(self):
        with patch.dict(os.environ, {"JWT_SECRET": "", "ENVIRONMENT": "development"}, clear=True):
            secret = _resolve_jwt_secret()
            assert len(secret) == 64

    def test_development_weak_default_warns(self):
        with patch.dict(os.environ, {"JWT_SECRET": "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING", "ENVIRONMENT": "development"}, clear=True):
            secret = _resolve_jwt_secret()
            assert secret == "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING"

    def test_development_short_warns(self):
        with patch.dict(os.environ, {"JWT_SECRET": "short", "ENVIRONMENT": "development"}, clear=True):
            secret = _resolve_jwt_secret()
            assert secret == "short"


class TestIsValidRole:
    def test_valid_role(self):
        assert is_valid_role("admin") is True
        assert is_valid_role("viewer") is True
        assert is_valid_role("analyst") is True

    def test_invalid_role(self):
        assert is_valid_role("superadmin") is False
        assert is_valid_role("") is False


class TestCreateAccessToken:
    def test_creates_valid_token(self):
        token = create_access_token({"sub": "testuser", "role": "admin"})
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"

    def test_custom_expiry(self):
        token = create_access_token({"sub": "u"}, expires_delta=timedelta(hours=1))
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "u"


class TestVerifyPassword:
    def test_correct_password(self):
        from passlib.hash import bcrypt
        hashed = bcrypt.hash("my_password")
        assert verify_password("my_password", hashed) is True

    def test_wrong_password(self):
        from passlib.hash import bcrypt
        hashed = bcrypt.hash("my_password")
        assert verify_password("wrong", hashed) is False

    def test_invalid_hash(self):
        assert verify_password("pwd", "not_a_hash") is False


class TestCreateToken:
    def test_creates_token(self):
        token = create_token("user1", "analyst")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "user1"
        assert payload["role"] == "analyst"


class TestDecodeToken:
    def test_valid_token(self):
        token = create_access_token({"sub": "u", "role": "viewer"})
        payload = decode_token(token)
        assert payload["sub"] == "u"

    def test_expired_token(self):
        token = create_access_token(
            {"sub": "u", "role": "viewer"},
            expires_delta=timedelta(seconds=-1),
        )
        with pytest.raises(HTTPException) as exc:
            decode_token(token)
        assert exc.value.status_code == 401

    def test_invalid_token(self):
        with pytest.raises(HTTPException) as exc:
            decode_token("not.a.token")
        assert exc.value.status_code == 401

    def test_invalid_role_in_token_logs_warning(self):
        payload = {"sub": "u", "role": "superadmin", "exp": 9999999999}
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        result = decode_token(token)
        assert result["role"] == "superadmin"


class TestGetCurrentUser:
    def test_returns_decoded_payload(self):
        token = create_token("u", "admin")
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        user = get_current_user(creds)
        assert user["sub"] == "u"


class TestRequireRole:
    def test_unknown_role_raises(self):
        with pytest.raises(ValueError, match="unknown role"):
            require_role("nonexistent")

    def test_sufficient_permissions(self):
        checker = require_role("viewer")
        user = {"role": "admin", "sub": "admin-u"}
        result = checker(user)
        assert result["sub"] == "admin-u"

    def test_insufficient_permissions(self):
        checker = require_role("admin")
        user = {"role": "viewer", "sub": "viewer-u"}
        with pytest.raises(HTTPException) as exc:
            checker(user)
        assert exc.value.status_code == 403

    def test_roles_list_format(self):
        checker = require_role("admin")
        user = {"role": "admin", "roles": ["admin"], "sub": "u"}
        result = checker(user)
        assert result["sub"] == "u"


class TestRequirePermission:
    def test_unknown_permission_raises(self):
        with pytest.raises(ValueError, match="unknown permission"):
            require_permission("does:not:exist")

    def test_has_permission(self):
        checker = require_permission("alerts:view")
        result = checker({"role": "admin", "sub": "u"})
        assert result["sub"] == "u"

    def test_lacks_permission(self):
        checker = require_permission("alerts:delete")
        with pytest.raises(HTTPException) as exc:
            checker({"role": "viewer", "sub": "v"})
        assert exc.value.status_code == 403


class TestGetOptionalUser:
    @pytest.mark.asyncio
    async def test_no_auth_header(self):
        request = MagicMock(spec=Request)
        request.headers = {}
        result = await get_optional_user(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_header_format(self):
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Basic xyz"}
        result = await get_optional_user(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_valid_token(self):
        token = create_token("u", "analyst")
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": f"Bearer {token}"}
        result = await get_optional_user(request)
        assert result["sub"] == "u"

    @pytest.mark.asyncio
    async def test_expired_token_returns_none(self):
        payload = {"sub": "u", "role": "admin", "exp": 0}
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": f"Bearer {token}"}
        result = await get_optional_user(request)
        assert result is None


class TestIsAuthenticated:
    def test_authenticated(self):
        assert is_authenticated({"sub": "u"}) is True

    def test_not_authenticated(self):
        assert is_authenticated(None) is False
