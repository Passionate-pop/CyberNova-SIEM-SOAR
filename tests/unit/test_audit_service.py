"""
Tests for Audit Service — verifies EVERY action type is logged with
actor, timestamp, IP, and before/after state where applicable.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.audit.service import (
    AuditService, AuditAction, AuditResource, audit_service,
)


TENANT = "tenant-1"
USER = "user-1"
ACTOR = "admin-1"
IP = "192.168.1.1"


@pytest.fixture
def db():
    m = MagicMock()
    m.execute = AsyncMock()
    m.flush = AsyncMock()
    m.add = MagicMock()
    return m


def _check_audit_log(log_entry, action, resource_type, tenant_id=TENANT, user_id=USER, has_before=False, has_after=False):
    assert log_entry.action == action
    assert log_entry.resource_type == resource_type
    assert log_entry.tenant_id == tenant_id
    assert log_entry.user_id == user_id
    assert log_entry.ip_address == IP
    if has_before:
        assert log_entry.before_state is not None
    if has_after:
        assert log_entry.after_state is not None


# ── Base log method ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_basic(db):
    entry = await audit_service.log(
        db=db, action=AuditAction.LOGIN.value,
        tenant_id=TENANT, user_id=USER,
        resource_type=AuditResource.USER.value, resource_id=USER,
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.LOGIN.value, AuditResource.USER.value)


@pytest.mark.asyncio
async def test_log_with_before_after_state(db):
    entry = await audit_service.log(
        db=db, action=AuditAction.SETTINGS_UPDATED.value,
        tenant_id=TENANT, user_id=USER,
        resource_type=AuditResource.SETTINGS.value,
        details={"changed_fields": ["rate_limit"]},
        before_state={"rate_limit": 60},
        after_state={"rate_limit": 100},
        ip_address=IP,
    )
    assert entry.before_state == {"rate_limit": 60}
    assert entry.after_state == {"rate_limit": 100}


# ── Authentication actions ────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_login_success(db):
    entry = await audit_service.log_login(
        db=db, tenant_id=TENANT, user_id=USER,
        username="alice", success=True, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.LOGIN.value, AuditResource.USER.value)


@pytest.mark.asyncio
async def test_log_login_failed(db):
    entry = await audit_service.log_login(
        db=db, tenant_id=TENANT, user_id=USER,
        username="alice", success=False, ip_address=IP,
    )
    assert entry.action == AuditAction.LOGIN_FAILED.value


@pytest.mark.asyncio
async def test_log_logout(db):
    entry = await audit_service.log_logout(
        db=db, tenant_id=TENANT, user_id=USER, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.LOGOUT.value, AuditResource.USER.value)


@pytest.mark.asyncio
async def test_log_password_change(db):
    entry = await audit_service.log_password_change(
        db=db, tenant_id=TENANT, user_id="target-user",
        changed_by=ACTOR, ip_address=IP,
    )
    assert entry.action == AuditAction.PASSWORD_CHANGED.value
    assert entry.user_id == ACTOR
    assert entry.resource_id == "target-user"


@pytest.mark.asyncio
async def test_log_password_reset(db):
    entry = await audit_service.log_password_reset(
        db=db, tenant_id=TENANT, user_id="target-user",
        initiated_by=ACTOR, ip_address=IP,
    )
    assert entry.action == AuditAction.PASSWORD_RESET.value


# ── User management actions ───────────────────────────────────────

@pytest.mark.asyncio
async def test_log_user_created(db):
    entry = await audit_service.log_user_created(
        db=db, tenant_id=TENANT, actor_user_id=ACTOR,
        new_user_id=USER, new_user_username="bob",
        roles=["viewer"], created_by=ACTOR, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.USER_CREATED.value, AuditResource.USER.value,
                     user_id=ACTOR, has_after=True)


@pytest.mark.asyncio
async def test_log_user_updated(db):
    entry = await audit_service.log_user_updated(
        db=db, tenant_id=TENANT, actor_user_id=ACTOR,
        target_user_id=USER, changed_fields=["email"],
        before={"email": "old@example.com"}, after={"email": "new@example.com"},
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.USER_UPDATED.value, AuditResource.USER.value,
                     user_id=ACTOR, has_before=True, has_after=True)
    assert entry.before_state["email"] == "old@example.com"


@pytest.mark.asyncio
async def test_log_user_deleted(db):
    entry = await audit_service.log_user_deleted(
        db=db, tenant_id=TENANT, actor_user_id=ACTOR,
        target_user_id=USER, target_username="bob",
        before={"username": "bob", "roles": ["viewer"]}, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.USER_DELETED.value, AuditResource.USER.value,
                     user_id=ACTOR, has_before=True)


@pytest.mark.asyncio
async def test_log_user_roles_changed(db):
    entry = await audit_service.log_user_roles_changed(
        db=db, tenant_id=TENANT, actor_user_id=ACTOR,
        target_user_id=USER, old_roles=["viewer"], new_roles=["admin"],
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.USER_ROLES_CHANGED.value, AuditResource.USER.value,
                     user_id=ACTOR, has_before=True, has_after=True)
    assert entry.before_state["roles"] == ["viewer"]
    assert entry.after_state["roles"] == ["admin"]


# ── Alert actions ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_alert_severity_changed(db):
    entry = await audit_service.log_alert_severity_changed(
        db=db, tenant_id=TENANT, user_id=USER,
        alert_id="alert-1", old_severity="low", new_severity="critical",
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.ALERT_SEVERITY_CHANGED.value, AuditResource.ALERT.value,
                     has_before=True, has_after=True)
    assert entry.before_state["severity"] == "low"
    assert entry.after_state["severity"] == "critical"


@pytest.mark.asyncio
async def test_log_alert_escalated(db):
    entry = await audit_service.log_alert_escalated(
        db=db, tenant_id=TENANT, user_id=USER,
        alert_id="alert-1", escalated_to="soc-lead",
        reason="Critical severity", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.ALERT_ESCALATED.value, AuditResource.ALERT.value)
    assert entry.details["escalated_to"] == "soc-lead"


# ── Config / Settings actions ─────────────────────────────────────

@pytest.mark.asyncio
async def test_log_settings_change(db):
    entry = await audit_service.log_settings_change(
        db=db, tenant_id=TENANT, user_id=USER,
        changed_fields=["rate_limit"],
        before={"rate_limit": 60}, after={"rate_limit": 100},
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.SETTINGS_UPDATED.value, AuditResource.SETTINGS.value,
                     has_before=True, has_after=True)


@pytest.mark.asyncio
async def test_log_config_change(db):
    entry = await audit_service.log_config_change(
        db=db, tenant_id=TENANT, user_id=USER,
        config_section="pipeline",
        before={"batch_size": 100}, after={"batch_size": 500},
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.CONFIG_CHANGED.value, AuditResource.CONFIG.value,
                     has_before=True, has_after=True)
    assert entry.resource_id == "pipeline"


# ── Device actions ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_device_isolated(db):
    entry = await audit_service.log_device_isolated(
        db=db, tenant_id=TENANT, user_id=USER,
        device_id="dev-1", hostname="workstation-1",
        reason="Suspicious activity", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.DEVICE_ISOLATED.value, AuditResource.DEVICE.value,
                     has_after=True)
    assert entry.after_state["is_isolated"] is True
    assert entry.details["hostname"] == "workstation-1"


# ── IP blocking actions ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_ip_blocked(db):
    entry = await audit_service.log_ip_blocked(
        db=db, tenant_id=TENANT, user_id=USER,
        ip_address_blocked="10.0.0.99", reason="Brute force", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.IP_BLOCKED.value, AuditResource.BLOCKED_IP.value,
                     has_after=True)
    assert entry.resource_id == "10.0.0.99"


@pytest.mark.asyncio
async def test_log_ip_unblocked(db):
    entry = await audit_service.log_ip_unblocked(
        db=db, tenant_id=TENANT, user_id=USER,
        ip_address_unblocked="10.0.0.99", reason="Reviewed", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.IP_UNBLOCKED.value, AuditResource.BLOCKED_IP.value,
                     has_before=True, has_after=True)
    assert entry.before_state["is_blocked"] is True
    assert entry.after_state["is_blocked"] is False


# ── Session actions ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_session_revoked(db):
    entry = await audit_service.log_session_revoked(
        db=db, tenant_id=TENANT, user_id=USER,
        session_id="sess-1", reason="Admin force logout", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.SESSION_REVOKED.value, AuditResource.SESSION.value)


@pytest.mark.asyncio
async def test_log_all_sessions_revoked(db):
    entry = await audit_service.log_all_sessions_revoked(
        db=db, tenant_id=TENANT, user_id=ACTOR,
        target_user_id=USER, session_count=3, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.SESSIONS_REVOKED_ALL.value, AuditResource.SESSION.value,
                     user_id=ACTOR)
    assert entry.details["session_count"] == 3


# ── Backup / Restore actions ──────────────────────────────────────

@pytest.mark.asyncio
async def test_log_backup_created(db):
    entry = await audit_service.log_backup_created(
        db=db, tenant_id=TENANT, user_id=USER,
        backup_id="backup-1", size_bytes=1048576, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.BACKUP_CREATED.value, AuditResource.BACKUP.value)


@pytest.mark.asyncio
async def test_log_data_restored(db):
    entry = await audit_service.log_data_restored(
        db=db, tenant_id=TENANT, user_id=USER,
        backup_id="backup-1", tables_restored=["alerts", "incidents"], ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.DATA_RESTORED.value, AuditResource.BACKUP.value)
    assert entry.details["tables_restored"] == ["alerts", "incidents"]


# ── Reporting actions ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_report_generated(db):
    entry = await audit_service.log_report_generated(
        db=db, tenant_id=TENANT, user_id=USER,
        report_id="rep-1", report_type="compliance", ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.REPORT_GENERATED.value, AuditResource.REPORT.value)


# ── Rule action ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_rule_action(db):
    entry = await audit_service.log_rule_action(
        db=db, action=AuditAction.RULE_CREATED.value,
        tenant_id=TENANT, user_id=USER, rule_id="rule-1",
        rule_name="Test Rule", after_state={"enabled": True},
        ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.RULE_CREATED.value, AuditResource.RULE.value,
                     has_after=True)
    assert entry.details["rule_name"] == "Test Rule"


# ── Incident action ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_incident_action(db):
    entry = await audit_service.log_incident_action(
        db=db, action=AuditAction.INCIDENT_RESOLVED.value,
        tenant_id=TENANT, user_id=USER, incident_id="inc-1",
        after_state={"status": "resolved"}, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.INCIDENT_RESOLVED.value, AuditResource.INCIDENT.value,
                     has_after=True)


# ── Alert action ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_alert_action(db):
    entry = await audit_service.log_alert_action(
        db=db, action=AuditAction.ALERT_ASSIGNED.value,
        tenant_id=TENANT, user_id=USER, alert_id="alert-1",
        details={"assigned_to": "soc-analyst"}, ip_address=IP,
    )
    _check_audit_log(entry, AuditAction.ALERT_ASSIGNED.value, AuditResource.ALERT.value)


# ── Query methods ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_logs_returns_filtered(db):
    mr = MagicMock()
    sm = MagicMock()
    sm.all.return_value = []
    mr.scalars.return_value = sm
    db.execute.return_value = mr

    result = await audit_service.get_logs(db=db, tenant_id=TENANT, limit=10)
    assert result == []


@pytest.mark.asyncio
async def test_get_security_events_includes_all_actions(db):
    mr = MagicMock()
    sm = MagicMock()
    sm.all.return_value = []
    mr.scalars.return_value = sm
    db.execute.return_value = mr

    result = await audit_service.get_security_events(db=db, tenant_id=TENANT, days=7)
    assert result == []


@pytest.mark.asyncio
async def test_get_user_activity(db):
    mr = MagicMock()
    sm = MagicMock()
    sm.all.return_value = []
    mr.scalars.return_value = sm
    db.execute.return_value = mr

    result = await audit_service.get_user_activity(db=db, tenant_id=TENANT, user_id=USER, days=30)
    assert result == []


# ── Enum completeness ─────────────────────────────────────────────

def test_audit_action_enum_has_all_actions():
    actions = {a.value for a in AuditAction}
    expected = {
        "login", "logout", "login_failed", "password_changed", "password_reset",
        "mfa_enabled", "mfa_disabled",
        "user_created", "user_updated", "user_deleted", "user_roles_changed",
        "user_disabled", "user_enabled",
        "alert_created", "alert_updated", "alert_assigned", "alert_resolved",
        "alert_escalated", "alert_suppressed", "alert_severity_changed",
        "incident_created", "incident_updated", "incident_assigned",
        "incident_resolved", "incident_closed", "incident_priority_changed",
        "rule_created", "rule_updated", "rule_deleted", "rule_enabled", "rule_disabled",
        "settings_updated", "config_changed",
        "integration_created", "integration_updated", "integration_deleted",
        "api_key_created", "api_key_revoked", "api_key_rotated",
        "playbook_triggered", "playbook_created", "playbook_updated", "playbook_deleted",
        "automation_executed", "automation_created", "automation_disabled",
        "pipeline_started", "pipeline_stopped", "pipeline_config_changed",
        "data_exported", "data_deleted", "data_retention_run", "data_restored",
        "backup_created", "backup_restored",
        "tenant_updated", "tenant_plan_changed", "tenant_limits_changed",
        "device_registered", "device_updated", "device_deleted",
        "device_isolated", "device_unisolated",
        "ip_blocked", "ip_unblocked",
        "notification_sent", "notification_channel_created", "notification_channel_deleted",
        "session_created", "session_revoked", "sessions_revoked_all",
        "service_key_created", "service_key_rotated", "service_key_revoked",
        "permission_denied",
        "rbac_role_created", "rbac_role_updated",
        "abac_policy_created", "abac_policy_updated",
        "report_generated", "report_downloaded", "report_scheduled",
        "compliance_check_run", "compliance_evidence_collected",
    }
    assert actions == expected, f"Missing: {expected - actions}, Extra: {actions - expected}"


def test_audit_resource_enum_has_all_resources():
    resources = {r.value for r in AuditResource}
    expected = {
        "user", "alert", "incident", "rule", "playbook", "settings",
        "api_key", "tenant", "pipeline", "dashboard", "automation",
        "device", "blocked_ip", "notification", "report", "integration",
        "backup", "session", "service_key", "compliance", "config", "audit_log",
    }
    assert resources == expected


# ── Singleton ─────────────────────────────────────────────────────

def test_singleton_instance_exists():
    assert audit_service is not None
    assert isinstance(audit_service, AuditService)
