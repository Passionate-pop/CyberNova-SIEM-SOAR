"""Unit tests for auth/services/auth_service.py — targeting 80%+ coverage."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.auth.services.auth_service import AuthService, _failed_attempts_local, LOCKOUT_THRESHOLD, _check_lockout, _clear_lockout, _record_failed_attempt


@pytest.fixture
def db():
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def service():
    return AuthService()


@pytest.mark.asyncio
async def test_login_success(service, db):
    from passlib.hash import bcrypt
    db.execute = AsyncMock()
    mock_user = MagicMock()
    mock_user.username = "testuser"
    mock_user.hashed_password = bcrypt.hash("correct")
    mock_user.is_active = True
    mock_user.tenant_id = "t1"
    mock_user.roles = ["analyst"]
    mock_user.name = "test_org"
    mock_user.company_size = "small"
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = result_mock

    from cybernova.security.encryption.jwt_handler import create_tokens
    with patch("cybernova.auth.services.auth_service.create_tokens") as mock_ct:
        mock_ct.return_value = ("access", "refresh")
        resp = await service.login(db, "testuser", "correct")
    assert resp.access_token == "access"
    assert resp.token_type == "bearer"


@pytest.mark.asyncio
async def test_login_failure(service, db):
    db.execute = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    db.execute.return_value = result_mock

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await service.login(db, "nobody", "wrong")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_login_inactive_user(service, db):
    from passlib.hash import bcrypt
    db.execute = AsyncMock()
    mock_user = MagicMock()
    mock_user.username = "disabled_user"
    mock_user.hashed_password = bcrypt.hash("pwd")
    mock_user.is_active = False
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = result_mock

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await service.login(db, "disabled_user", "pwd")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_login_lockout(service, db):
    with patch("cybernova.auth.services.auth_service._check_lockout", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = (LOCKOUT_THRESHOLD, time.time())
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await service.login(db, "locked_user", "any")
        assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_login_lockout_expired(service, db):
    from passlib.hash import bcrypt
    mock_user = MagicMock()
    mock_user.username = "expired_user"
    mock_user.hashed_password = bcrypt.hash("pwd")
    mock_user.is_active = True
    mock_user.tenant_id = "t1"
    mock_user.roles = ["viewer"]
    mock_user.name = "test_org"
    mock_user.company_size = "small"
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = mock_user

    with patch("cybernova.auth.services.auth_service._check_lockout", new_callable=AsyncMock) as mock_check, \
         patch("cybernova.auth.services.auth_service._clear_lockout", new_callable=AsyncMock) as mock_clear, \
         patch("cybernova.auth.services.auth_service.create_tokens") as mock_ct:
        # Lockout expired — attempts >= threshold but lockout_time is old
        mock_check.return_value = (LOCKOUT_THRESHOLD, time.time() - 1000)
        mock_ct.return_value = ("a", "b")
        db.execute.return_value = result_mock
        resp = await service.login(db, "expired_user", "pwd")
    assert resp.access_token == "a"
    # _clear_lockout called twice: once for expired lockout check, once for successful login
    assert mock_clear.call_count == 2


@pytest.mark.asyncio
async def test_register_existing_user_raises(service, db):
    existing_mock = MagicMock()
    existing_mock.scalar_one_or_none.return_value = MagicMock()
    db.execute.return_value = existing_mock
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await service.register(db, "existing", "e@m.com", "P@ss1234")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_register_creates_user(service, db):
    db.execute = AsyncMock()
    
    # Mock the first call (existing user check) returns None
    none_result = MagicMock()
    none_result.scalar_one_or_none.return_value = None
    # Configure scalars().first() to return None (tenant lookup)
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = None
    scalars_mock.all.return_value = []
    none_result.scalars.return_value = scalars_mock
    
    db.execute.return_value = none_result

    with patch("cybernova.auth.services.auth_service.create_tokens") as mock_ct:
        mock_ct.return_value = ("access", "refresh")
        resp = await service.register(db, "newuser", "new@m.com", "Str0ng!Pass")
    assert resp.access_token == "access"
    assert db.add.called


@pytest.mark.asyncio
async def test_register_with_org_key(service, db):
    """Test that staff joining via org_key links to the correct tenant."""
    # The register() method makes several db.execute calls:
    # 1. Check existing user (must return None)
    # 2. Lookup org_key by hash (must return a key object with tenant_id)
    # 3. Lookup tenant by that tenant_id (must return a tenant)
    # 4. Flush new user (may trigger IntegrityError check)
    # 5. Create tokens

    # First call: existing user check → returns None
    none_result = MagicMock()
    none_result.scalar_one_or_none.return_value = None
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = None
    none_result.scalars.return_value = scalars_mock

    # Second call: org key lookup → returns a valid key object
    org_key_result = MagicMock()
    org_key_obj = MagicMock()
    org_key_obj.tenant_id = "org_tenant_id"
    org_key_result.scalar_one_or_none.return_value = org_key_obj

    # Third call: tenant lookup → returns a tenant
    tenant_result = MagicMock()
    tenant_obj = MagicMock()
    tenant_obj.id = "org_tenant_id"
    tenant_obj.name = "test_org"
    tenant_obj.company_size = "small"
    tenant_result.scalar_one_or_none.return_value = tenant_obj

    db.execute.side_effect = [none_result, org_key_result, tenant_result]

    with patch("cybernova.auth.services.auth_service.create_tokens") as mock_ct:
        mock_ct.return_value = ("access", "refresh")
        resp = await service.register(db, "orguser", "org@m.com", "Str0ng!Pass", org_key="valid-org-key")
    assert resp.access_token == "access"
