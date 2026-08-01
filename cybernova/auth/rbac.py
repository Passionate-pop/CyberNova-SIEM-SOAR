"""
CyberNova — RBAC (Role-Based Access Control)
Enterprise-grade permission system with roles, permissions, and resource-level access.
"""
from __future__ import annotations

import time
from collections import defaultdict
from enum import Enum
from threading import Lock
from typing import Dict, List, Set


class Permission(str, Enum):
    ALERTS_VIEW = "alerts:view"
    ALERTS_UPDATE = "alerts:update"
    ALERTS_DELETE = "alerts:delete"
    
    INCIDENTS_VIEW = "incidents:view"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_DELETE = "incidents:delete"
    
    RULES_VIEW = "rules:view"
    RULES_CREATE = "rules:create"
    RULES_UPDATE = "rules:update"
    RULES_DELETE = "rules:delete"
    
    DEVICES_VIEW = "devices:view"
    DEVICES_MANAGE = "devices:manage"
    
    USERS_VIEW = "users:view"
    USERS_CREATE = "users:create"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    
    SETTINGS_VIEW = "settings:view"
    SETTINGS_UPDATE = "settings:update"
    
    AUDIT_VIEW = "audit:view"
    
    PIPELINE_VIEW = "pipeline:view"
    PIPELINE_MANAGE = "pipeline:manage"
    
    AUTOMATION_VIEW = "automation:view"
    AUTOMATION_TRIGGER = "automation:trigger"
    
    THREAT_INTEL_VIEW = "threat_intel:view"
    THREAT_INTEL_MANAGE = "threat_intel:manage"
    
    ANALYTICS_VIEW = "analytics:view"
    
    DATA_EXPORT = "data:export"
    DATA_DELETE = "data:delete"

    DASHBOARD_VIEW = "dashboard:view"
    TESTING_VIEW = "testing:view"
    TESTING_EXECUTE = "testing:execute"
    ANOMALY_VIEW = "anomaly:view"
    ISOLATION_VIEW = "isolation:view"
    ISOLATION_MANAGE = "isolation:manage"
    RETENTION_VIEW = "retention:view"
    RETENTION_MANAGE = "retention:manage"
    AGENT_VIEW = "agent:view"
    AGENT_MANAGE = "agent:manage"
    INTEGRATIONS_VIEW = "integrations:view"
    INTEGRATIONS_MANAGE = "integrations:manage"
    TENANT_VIEW = "tenant:view"
    TENANT_MANAGE = "tenant:manage"
    BILLING_VIEW = "billing:view"
    NOTIFICATIONS_VIEW = "notifications:view"
    NOTIFICATIONS_MANAGE = "notifications:manage"

    CLOUD_INGEST = "cloud:ingest"
    CLOUD_VIEW = "cloud:view"

    CSPM_SCAN = "cspm:scan"
    CSPM_VIEW = "cspm:view"

    WORM_WRITE = "worm:write"
    WORM_VIEW = "worm:view"
    WORM_VERIFY = "worm:verify"

    RESIDENCY_VIEW = "residency:view"
    RESIDENCY_ADMIN = "residency:admin"

    ABAC_VIEW = "abac:view"
    ABAC_MANAGE = "abac:manage"

    RAG_VIEW = "rag:view"
    RAG_MANAGE = "rag:manage"


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SOC_MANAGER = "soc_manager"
    ENGINEER = "engineer"


ROLE_PRIORITY: List[str] = ["admin", "soc_manager", "engineer", "analyst", "viewer"]

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.ALERTS_VIEW, Permission.ALERTS_UPDATE, Permission.ALERTS_DELETE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_UPDATE, Permission.INCIDENTS_DELETE,
        Permission.RULES_VIEW, Permission.RULES_CREATE, Permission.RULES_UPDATE, Permission.RULES_DELETE,
        Permission.DEVICES_VIEW, Permission.DEVICES_MANAGE,
        Permission.USERS_VIEW, Permission.USERS_CREATE, Permission.USERS_UPDATE, Permission.USERS_DELETE,
        Permission.SETTINGS_VIEW, Permission.SETTINGS_UPDATE,
        Permission.AUDIT_VIEW,
        Permission.PIPELINE_VIEW, Permission.PIPELINE_MANAGE,
        Permission.AUTOMATION_VIEW, Permission.AUTOMATION_TRIGGER,
        Permission.THREAT_INTEL_VIEW, Permission.THREAT_INTEL_MANAGE,
        Permission.ANALYTICS_VIEW,
        Permission.DATA_EXPORT, Permission.DATA_DELETE,
        Permission.DASHBOARD_VIEW, Permission.TESTING_VIEW, Permission.TESTING_EXECUTE,
        Permission.ANOMALY_VIEW, Permission.ISOLATION_VIEW, Permission.ISOLATION_MANAGE,
        Permission.RETENTION_VIEW, Permission.RETENTION_MANAGE,
        Permission.AGENT_VIEW, Permission.AGENT_MANAGE,
        Permission.INTEGRATIONS_VIEW, Permission.INTEGRATIONS_MANAGE,
        Permission.TENANT_VIEW, Permission.TENANT_MANAGE,
        Permission.BILLING_VIEW,
        Permission.NOTIFICATIONS_VIEW, Permission.NOTIFICATIONS_MANAGE,

        Permission.CLOUD_INGEST, Permission.CLOUD_VIEW,
        Permission.CSPM_SCAN, Permission.CSPM_VIEW,
        Permission.WORM_WRITE, Permission.WORM_VIEW, Permission.WORM_VERIFY,
        Permission.RESIDENCY_VIEW, Permission.RESIDENCY_ADMIN,
        Permission.ABAC_VIEW, Permission.ABAC_MANAGE,
        Permission.RAG_VIEW, Permission.RAG_MANAGE,
    },
    Role.SOC_MANAGER: {
        Permission.ALERTS_VIEW, Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_UPDATE,
        Permission.RULES_VIEW,
        Permission.DEVICES_VIEW,
        Permission.USERS_VIEW,
        Permission.SETTINGS_VIEW,
        Permission.AUDIT_VIEW,
        Permission.PIPELINE_VIEW,
        Permission.AUTOMATION_VIEW, Permission.AUTOMATION_TRIGGER,
        Permission.THREAT_INTEL_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.DATA_EXPORT,
        Permission.DASHBOARD_VIEW, Permission.ANOMALY_VIEW,
        Permission.ISOLATION_VIEW, Permission.TESTING_VIEW,
        Permission.RETENTION_VIEW, Permission.AGENT_VIEW,
        Permission.NOTIFICATIONS_VIEW, Permission.INTEGRATIONS_VIEW,

        Permission.CLOUD_VIEW,
        Permission.CSPM_VIEW,
        Permission.WORM_VIEW,
        Permission.RESIDENCY_VIEW,
        Permission.ABAC_VIEW,
        Permission.RAG_VIEW,
    },
    Role.ANALYST: {
        Permission.ALERTS_VIEW, Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_UPDATE,
        Permission.RULES_VIEW,
        Permission.DEVICES_VIEW,
        Permission.PIPELINE_VIEW,
        Permission.AUTOMATION_VIEW,
        Permission.THREAT_INTEL_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.DASHBOARD_VIEW, Permission.ANOMALY_VIEW,
        Permission.ISOLATION_VIEW, Permission.TESTING_VIEW,
        Permission.RETENTION_VIEW, Permission.NOTIFICATIONS_VIEW,

        Permission.CLOUD_VIEW,
        Permission.CSPM_VIEW,
        Permission.WORM_VIEW,
        Permission.RESIDENCY_VIEW,
        Permission.RAG_VIEW,
    },
    Role.ENGINEER: {
        Permission.ALERTS_VIEW,
        Permission.INCIDENTS_VIEW,
        Permission.RULES_VIEW, Permission.RULES_CREATE, Permission.RULES_UPDATE,
        Permission.DEVICES_VIEW, Permission.DEVICES_MANAGE,
        Permission.SETTINGS_VIEW, Permission.SETTINGS_UPDATE,
        Permission.PIPELINE_VIEW, Permission.PIPELINE_MANAGE,
        Permission.AUTOMATION_VIEW, Permission.AUTOMATION_TRIGGER,
        Permission.THREAT_INTEL_VIEW, Permission.THREAT_INTEL_MANAGE,
        Permission.DASHBOARD_VIEW, Permission.ANOMALY_VIEW,
        Permission.ISOLATION_VIEW, Permission.ISOLATION_MANAGE,
        Permission.TESTING_VIEW, Permission.TESTING_EXECUTE,
        Permission.RETENTION_VIEW, Permission.RETENTION_MANAGE,
        Permission.AGENT_VIEW, Permission.AGENT_MANAGE,
        Permission.INTEGRATIONS_VIEW, Permission.INTEGRATIONS_MANAGE,

        Permission.CLOUD_INGEST, Permission.CLOUD_VIEW,
        Permission.CSPM_SCAN, Permission.CSPM_VIEW,
        Permission.WORM_VIEW,
        Permission.RESIDENCY_VIEW,
        Permission.RAG_VIEW,
    },
    Role.VIEWER: {
        # View permissions — individuals & org staff get full read access
        Permission.ALERTS_VIEW,
        Permission.INCIDENTS_VIEW,
        Permission.RULES_VIEW,
        Permission.DEVICES_VIEW,
        Permission.DASHBOARD_VIEW, Permission.ANOMALY_VIEW,
        Permission.PIPELINE_VIEW,
        Permission.THREAT_INTEL_VIEW,
        Permission.SETTINGS_VIEW,
        Permission.AUDIT_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.AUTOMATION_VIEW,
        Permission.AGENT_VIEW,
        Permission.ISOLATION_VIEW,
        Permission.RETENTION_VIEW,
        Permission.INTEGRATIONS_VIEW,
        Permission.NOTIFICATIONS_VIEW,
        Permission.TENANT_VIEW,
        Permission.BILLING_VIEW,
        Permission.TESTING_VIEW,
        Permission.RESIDENCY_VIEW,
        Permission.ABAC_VIEW,
        Permission.RAG_VIEW,
        Permission.CLOUD_VIEW,
        Permission.CSPM_VIEW,
        Permission.WORM_VIEW,
        # Org staff need read access to users and devices
        Permission.USERS_VIEW,
    },
}


VALID_ROLES: Set[str] = {r.value for r in Role}


def normalize_permissions(perms: object) -> List[str]:
    """Sanitize permissions at JWT/DB boundary. Removes non-strings, deduplicates."""
    if not isinstance(perms, list):
        return []
    return list(dict.fromkeys(p for p in perms if isinstance(p, str)))


def get_primary_role(roles: List[str]) -> str:
    """Return the highest-priority role from a user's role list."""
    for r in ROLE_PRIORITY:
        if r in roles:
            return r
    return Role.VIEWER.value


def get_role_permissions(role: str) -> Set[Permission]:
    """Get all permissions for a role."""
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except (ValueError, KeyError):
        return set()


def has_permission(user_roles: List[str], permission: Permission) -> bool:
    """Check if any of the user's roles has the specified permission."""
    for role in user_roles:
        perms = get_role_permissions(role)
        if permission in perms:
            return True
    return False


def has_any_permission(user_roles: List[str], permissions: List[Permission]) -> bool:
    """Check if user has any of the specified permissions."""
    for perm in permissions:
        if has_permission(user_roles, perm):
            return True
    return False


def has_all_permissions(user_roles: List[str], permissions: List[Permission]) -> bool:
    """Check if user has all of the specified permissions."""
    for perm in permissions:
        if not has_permission(user_roles, perm):
            return False
    return True


def filter_by_permission(user_roles: List[str], items: List[Dict], permission_check: callable) -> List[Dict]:
    """Filter items based on permission check function."""
    if has_permission(user_roles, Permission.ALERTS_DELETE):
        return items
    return [item for item in items if permission_check(item)]


ROLE_DESCRIPTIONS = {
    Role.ADMIN: "Full system access - can manage all resources",
    Role.SOC_MANAGER: "Manage SOC operations - view all, update alerts/incidents",
    Role.ANALYST: "Investigate alerts and incidents - view and update",
    Role.ENGINEER: "System configuration and automation - manage rules and devices",
    Role.VIEWER: "Read-only access to dashboards and alerts",
}


def list_roles() -> List[Dict]:
    """List all available roles with their permissions."""
    return [
        {
            "role": r.value,
            "description": ROLE_DESCRIPTIONS[r],
            "permissions": [p.value for p in perms],
        }
        for r, perms in ROLE_PERMISSIONS.items()
    ]


class RBACEngine:
    """Central RBAC engine — wraps permission checks and role management."""

    def __init__(self) -> None:
        self._permissions = {p.value for p in Permission}
        self._roles = {r.value for r in Role}

    def has_permission(self, user_roles: List[str], permission: Permission) -> bool:
        return has_permission(user_roles, permission)

    def has_any(self, user_roles: List[str], permissions: List[Permission]) -> bool:
        return has_any_permission(user_roles, permissions)

    def has_all(self, user_roles: List[str], permissions: List[Permission]) -> bool:
        return has_all_permissions(user_roles, permissions)

    def role_permissions(self, role: str) -> Set[Permission]:
        return get_role_permissions(role)

    def primary_role(self, roles: List[str]) -> str:
        return get_primary_role(roles)

    def list_roles(self) -> List[Dict]:
        return list_roles()


rbac = RBACEngine()


class PermissionDeniedTracker:
    """Thread-safe counter for permission denials by IP. Used for rate-limiting abuse detection."""

    def __init__(self, window_seconds: int = 60, threshold: int = 20):
        self._window = window_seconds
        self._threshold = threshold
        self._lock = Lock()
        self._counts: Dict[str, list] = defaultdict(list)

    def record(self, ip: str) -> int:
        """Record a denial for an IP. Returns current count in window."""
        now = time.time()
        with self._lock:
            self._counts[ip] = [t for t in self._counts[ip] if now - t < self._window]
            self._counts[ip].append(now)
            return len(self._counts[ip])

    def is_abusing(self, ip: str) -> bool:
        """Check if IP has exceeded denial threshold in window."""
        now = time.time()
        with self._lock:
            self._counts[ip] = [t for t in self._counts[ip] if now - t < self._window]
            return len(self._counts[ip]) >= self._threshold

    def get_stats(self) -> Dict[str, int]:
        """Return current denial counts per IP (for monitoring)."""
        now = time.time()
        with self._lock:
            return {ip: len([t for t in ts if now - t < self._window]) for ip, ts in self._counts.items()}


denied_tracker = PermissionDeniedTracker()
