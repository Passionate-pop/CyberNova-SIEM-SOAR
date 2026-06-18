"""Comprehensive unit tests for auth/rbac.py — targeting 80%+ line coverage."""

import time
from unittest.mock import patch

import pytest

from cybernova.auth.rbac import (
    Permission, Role, ROLE_PERMISSIONS, VALID_ROLES,
    normalize_permissions, get_primary_role, get_role_permissions,
    has_permission, has_any_permission, has_all_permissions,
    filter_by_permission, list_roles, PermissionDeniedTracker,
    ROLE_PRIORITY,
)


class TestNormalizePermissions:
    def test_non_list_returns_empty(self):
        assert normalize_permissions("not a list") == []
        assert normalize_permissions(None) == []
        assert normalize_permissions(42) == []

    def test_filters_non_strings(self):
        result = normalize_permissions(["alerts:view", 42, None, "rules:view", True])
        assert result == ["alerts:view", "rules:view"]

    def test_deduplicates_preserving_order(self):
        result = normalize_permissions(["a", "b", "a", "c", "b"])
        assert result == ["a", "b", "c"]

    def test_empty_list_returns_empty(self):
        assert normalize_permissions([]) == []


class TestGetPrimaryRole:
    def test_admin_is_highest(self):
        assert get_primary_role(["viewer", "admin", "analyst"]) == "admin"

    def test_soc_manager_second(self):
        assert get_primary_role(["viewer", "soc_manager", "analyst"]) == "soc_manager"

    def test_engineer_third(self):
        assert get_primary_role(["viewer", "engineer"]) == "engineer"

    def test_analyst_fourth(self):
        assert get_primary_role(["viewer", "analyst"]) == "analyst"

    def test_viewer_fallback(self):
        assert get_primary_role(["viewer"]) == "viewer"

    def test_unknown_role_falls_back_to_viewer(self):
        assert get_primary_role(["nonexistent"]) == "viewer"

    def test_empty_list_falls_back_to_viewer(self):
        assert get_primary_role([]) == "viewer"


class TestGetRolePermissions:
    def test_admin_has_permissions(self):
        perms = get_role_permissions("admin")
        assert Permission.ALERTS_DELETE in perms
        assert Permission.USERS_CREATE in perms

    def test_viewer_limited(self):
        perms = get_role_permissions("viewer")
        assert Permission.ALERTS_VIEW in perms
        assert Permission.ALERTS_DELETE not in perms

    def test_invalid_role_returns_empty(self):
        assert get_role_permissions("bogus_role") == set()


class TestHasPermission:
    def test_admin_has_delete(self):
        assert has_permission(["admin"], Permission.ALERTS_DELETE) is True

    def test_viewer_lacks_delete(self):
        assert has_permission(["viewer"], Permission.ALERTS_DELETE) is False

    def test_multiple_roles_union(self):
        assert has_permission(["viewer", "admin"], Permission.ALERTS_DELETE) is True

    def test_empty_roles(self):
        assert has_permission([], Permission.ALERTS_VIEW) is False

    def test_invalid_role_does_not_crash(self):
        assert has_permission(["bogus"], Permission.ALERTS_VIEW) is False


class TestHasAnyPermission:
    def test_true_when_any_matches(self):
        result = has_any_permission(
            ["analyst"], [Permission.ALERTS_DELETE, Permission.ALERTS_VIEW]
        )
        assert result is True

    def test_false_when_none_match(self):
        result = has_any_permission(
            ["viewer"], [Permission.ALERTS_DELETE, Permission.USERS_CREATE]
        )
        assert result is False

    def test_empty_permissions_list(self):
        assert has_any_permission(["admin"], []) is False


class TestHasAllPermissions:
    def test_true_when_all_match(self):
        a = Permission.ALERTS_VIEW
        i = Permission.INCIDENTS_VIEW
        assert has_all_permissions(["admin"], [a, i]) is True

    def test_false_when_any_missing(self):
        a = Permission.ALERTS_VIEW
        d = Permission.ALERTS_DELETE
        assert has_all_permissions(["viewer"], [a, d]) is False

    def test_empty_permissions_list(self):
        assert has_all_permissions(["viewer"], []) is True


class TestFilterByPermission:
    def test_admin_returns_all(self):
        items = [{"id": 1}, {"id": 2}]
        result = filter_by_permission(
            ["admin"], items, lambda x: x["id"] > 1
        )
        assert len(result) == 2

    def test_non_admin_filters(self):
        items = [{"id": 1}, {"id": 2}]
        result = filter_by_permission(
            ["viewer"], items, lambda x: x["id"] > 1
        )
        assert len(result) == 1
        assert result[0]["id"] == 2


class TestListRoles:
    def test_returns_all_roles(self):
        roles = list_roles()
        assert len(roles) == len(Role)
        role_values = {r["role"] for r in roles}
        for r in Role:
            assert r.value in role_values

    def test_each_role_has_description_and_permissions(self):
        for entry in list_roles():
            assert "description" in entry
            assert "permissions" in entry
            assert isinstance(entry["permissions"], list)


class TestPermissionDeniedTracker:
    def test_record_returns_count(self):
        tracker = PermissionDeniedTracker(window_seconds=60, threshold=5)
        assert tracker.record("1.2.3.4") == 1
        assert tracker.record("1.2.3.4") == 2

    def test_is_abusing_below_threshold(self):
        tracker = PermissionDeniedTracker(window_seconds=60, threshold=3)
        tracker.record("1.2.3.4")
        tracker.record("1.2.3.4")
        assert tracker.is_abusing("1.2.3.4") is False

    def test_is_abusing_at_threshold(self):
        tracker = PermissionDeniedTracker(window_seconds=60, threshold=3)
        for _ in range(3):
            tracker.record("1.2.3.4")
        assert tracker.is_abusing("1.2.3.4") is True

    def test_expired_records_do_not_count(self):
        tracker = PermissionDeniedTracker(window_seconds=0.1, threshold=2)
        tracker.record("1.2.3.4")
        time.sleep(0.15)
        assert tracker.is_abusing("1.2.3.4") is False

    def test_get_stats_returns_counts(self):
        tracker = PermissionDeniedTracker(window_seconds=60, threshold=5)
        tracker.record("1.2.3.4")
        tracker.record("5.6.7.8")
        tracker.record("5.6.7.8")
        stats = tracker.get_stats()
        assert stats["1.2.3.4"] == 1
        assert stats["5.6.7.8"] == 2

    def test_multiple_ips_isolated(self):
        tracker = PermissionDeniedTracker(window_seconds=60, threshold=3)
        tracker.record("a")
        tracker.record("b")
        tracker.record("b")
        assert tracker.is_abusing("a") is False
        assert tracker.is_abusing("b") is False
        tracker.record("b")
        assert tracker.is_abusing("b") is True
        assert tracker.is_abusing("a") is False
