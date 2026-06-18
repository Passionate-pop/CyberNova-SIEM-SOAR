"""Tests for authentication and RBAC."""
from __future__ import annotations
import pytest
from pydantic import ValidationError
from cybernova.auth.jwt_auth import create_access_token, decode_token, is_valid_role
from cybernova.auth.rbac import Role, Permission, has_permission, get_role_permissions
from cybernova.auth.schemas import RegisterRequest


def test_create_and_decode_token():
    token = create_access_token({"sub": "admin", "role": "admin"})
    assert token is not None
    payload = decode_token(token)
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"


def test_valid_roles():
    assert is_valid_role("admin") is True
    assert is_valid_role("analyst") is True
    assert is_valid_role("viewer") is True
    assert is_valid_role("fake_role") is False


def test_rbac_admin_has_all_permissions():
    perms = get_role_permissions("admin")
    assert Permission.ALERTS_VIEW in perms
    assert Permission.USERS_DELETE in perms
    assert Permission.SETTINGS_UPDATE in perms
    assert Permission.DATA_EXPORT in perms


def test_rbac_viewer_limited():
    perms = get_role_permissions("viewer")
    assert Permission.ALERTS_VIEW in perms
    assert Permission.INCIDENTS_VIEW in perms
    assert Permission.USERS_DELETE not in perms
    assert Permission.SETTINGS_UPDATE not in perms


def test_rbac_has_permission():
    assert has_permission(["admin"], Permission.ALERTS_DELETE) is True
    assert has_permission(["viewer"], Permission.ALERTS_DELETE) is False
    assert has_permission(["analyst"], Permission.ALERTS_UPDATE) is True
    assert has_permission(["viewer"], Permission.AUTOMATION_TRIGGER) is False


def test_multiple_roles_resolution():
    assert has_permission(["viewer", "admin"], Permission.USERS_DELETE) is True
    assert has_permission(["viewer", "analyst"], Permission.INCIDENTS_UPDATE) is True


def test_register_password_too_short():
    with pytest.raises(ValidationError, match="at least 8 characters"):
        RegisterRequest(username="test", email="t@t.com", password="Ab1!")


def test_register_password_no_uppercase():
    with pytest.raises(ValidationError, match="uppercase"):
        RegisterRequest(username="test", email="t@t.com", password="abcdefgh1!")


def test_register_password_no_special():
    with pytest.raises(ValidationError, match="special character"):
        RegisterRequest(username="test", email="t@t.com", password="Abcdefgh1")


def test_register_password_valid():
    req = RegisterRequest(username="test", email="t@t.com", password="Abcdefgh1!")
    assert req.password == "Abcdefgh1!"
