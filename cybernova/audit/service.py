"""
Audit logging. Tracks admin actions with actor, timestamp, IP, before/after state.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import AuditLog
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.audit")


class AuditAction(str, Enum):
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"  # nosec
    PASSWORD_RESET = "password_reset"  # nosec
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"

    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ROLES_CHANGED = "user_roles_changed"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"

    # Alert management
    ALERT_CREATED = "alert_created"
    ALERT_UPDATED = "alert_updated"
    ALERT_ASSIGNED = "alert_assigned"
    ALERT_RESOLVED = "alert_resolved"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_SUPPRESSED = "alert_suppressed"
    ALERT_SEVERITY_CHANGED = "alert_severity_changed"

    # Incident management
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_ASSIGNED = "incident_assigned"
    INCIDENT_RESOLVED = "incident_resolved"
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_PRIORITY_CHANGED = "incident_priority_changed"

    # Detection rules
    RULE_CREATED = "rule_created"
    RULE_UPDATED = "rule_updated"
    RULE_DELETED = "rule_deleted"
    RULE_ENABLED = "rule_enabled"
    RULE_DISABLED = "rule_disabled"

    # Configuration
    SETTINGS_UPDATED = "settings_updated"
    CONFIG_CHANGED = "config_changed"
    INTEGRATION_CREATED = "integration_created"
    INTEGRATION_UPDATED = "integration_updated"
    INTEGRATION_DELETED = "integration_deleted"

    # API keys
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_ROTATED = "api_key_rotated"

    # Playbooks / Automation
    PLAYBOOK_TRIGGERED = "playbook_triggered"
    PLAYBOOK_CREATED = "playbook_created"
    PLAYBOOK_UPDATED = "playbook_updated"
    PLAYBOOK_DELETED = "playbook_deleted"
    AUTOMATION_EXECUTED = "automation_executed"
    AUTOMATION_CREATED = "automation_created"
    AUTOMATION_DISABLED = "automation_disabled"

    # Pipeline
    PIPELINE_STARTED = "pipeline_started"
    PIPELINE_STOPPED = "pipeline_stopped"
    PIPELINE_CONFIG_CHANGED = "pipeline_config_changed"

    # Data
    DATA_EXPORTED = "data_exported"
    DATA_DELETED = "data_deleted"
    DATA_RETENTION_RUN = "data_retention_run"
    DATA_RESTORED = "data_restored"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"

    # Tenant
    TENANT_UPDATED = "tenant_updated"
    TENANT_PLAN_CHANGED = "tenant_plan_changed"
    TENANT_LIMITS_CHANGED = "tenant_limits_changed"

    # Devices / Network
    DEVICE_REGISTERED = "device_registered"
    DEVICE_UPDATED = "device_updated"
    DEVICE_DELETED = "device_deleted"
    DEVICE_ISOLATED = "device_isolated"
    DEVICE_UNISOLATED = "device_unisolated"
    IP_BLOCKED = "ip_blocked"
    IP_UNBLOCKED = "ip_unblocked"

    # Notifications
    NOTIFICATION_SENT = "notification_sent"
    NOTIFICATION_CHANNEL_CREATED = "notification_channel_created"
    NOTIFICATION_CHANNEL_DELETED = "notification_channel_deleted"

    # Session management
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSIONS_REVOKED_ALL = "sessions_revoked_all"

    # Service keys
    SERVICE_KEY_CREATED = "service_key_created"
    SERVICE_KEY_ROTATED = "service_key_rotated"
    SERVICE_KEY_REVOKED = "service_key_revoked"

    # Access control
    PERMISSION_DENIED = "permission_denied"
    RBAC_ROLE_CREATED = "rbac_role_created"
    RBAC_ROLE_UPDATED = "rbac_role_updated"
    ABAC_POLICY_CREATED = "abac_policy_created"
    ABAC_POLICY_UPDATED = "abac_policy_updated"

    # Reporting
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    REPORT_SCHEDULED = "report_scheduled"

    # Compliance
    COMPLIANCE_CHECK_RUN = "compliance_check_run"
    COMPLIANCE_EVIDENCE_COLLECTED = "compliance_evidence_collected"


class AuditResource(str, Enum):
    USER = "user"
    ALERT = "alert"
    INCIDENT = "incident"
    RULE = "rule"
    PLAYBOOK = "playbook"
    SETTINGS = "settings"
    API_KEY = "api_key"
    TENANT = "tenant"
    PIPELINE = "pipeline"
    DASHBOARD = "dashboard"
    AUTOMATION = "automation"
    DEVICE = "device"
    BLOCKED_IP = "blocked_ip"
    NOTIFICATION = "notification"
    REPORT = "report"
    INTEGRATION = "integration"
    BACKUP = "backup"
    SESSION = "session"
    SERVICE_KEY = "service_key"
    COMPLIANCE = "compliance"
    CONFIG = "config"
    AUDIT_LOG = "audit_log"


COMMON_SECURITY_ACTIONS = [
    AuditAction.LOGIN_FAILED.value,
    AuditAction.PASSWORD_CHANGED.value,
    AuditAction.PASSWORD_RESET.value,
    AuditAction.USER_DELETED.value,
    AuditAction.USER_DISABLED.value,
    AuditAction.USER_ROLES_CHANGED.value,
    AuditAction.API_KEY_CREATED.value,
    AuditAction.API_KEY_REVOKED.value,
    AuditAction.API_KEY_ROTATED.value,
    AuditAction.SESSION_REVOKED.value,
    AuditAction.SESSIONS_REVOKED_ALL.value,
    AuditAction.PERMISSION_DENIED.value,
    AuditAction.MFA_ENABLED.value,
    AuditAction.MFA_DISABLED.value,
    AuditAction.DEVICE_ISOLATED.value,
    AuditAction.IP_BLOCKED.value,
]


class AuditService:

    async def log(
        self,
        db: AsyncSession,
        action: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Log an audit event with optional before/after state."""
        audit = AuditLog(
            id=new_id(),
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            before_state=before_state,
            after_state=after_state,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit)
        await db.flush()
        log.debug("AUDIT: %s by %s on %s/%s (ip=%s)", action, user_id, resource_type, resource_id, ip_address)
        return audit

    # auth actions

    async def log_login(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.LOGIN.value if success else AuditAction.LOGIN_FAILED.value,
            tenant_id=tenant_id,
            user_id=user_id if success else None,
            resource_type=AuditResource.USER.value,
            resource_id=user_id if success else None,
            details={"username": username, "success": success},
            ip_address=ip_address,
        )

    async def log_logout(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.LOGOUT.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.USER.value,
            resource_id=user_id,
            ip_address=ip_address,
        )

    async def log_password_change(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        changed_by: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.PASSWORD_CHANGED.value,
            tenant_id=tenant_id,
            user_id=changed_by,
            resource_type=AuditResource.USER.value,
            resource_id=user_id,
            details={"target_user": user_id},
            ip_address=ip_address,
        )

    async def log_password_reset(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        initiated_by: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.PASSWORD_RESET.value,
            tenant_id=tenant_id,
            user_id=initiated_by,
            resource_type=AuditResource.USER.value,
            resource_id=user_id,
            details={"initiated_by": initiated_by},
            ip_address=ip_address,
        )

    # user management

    async def log_user_created(
        self,
        db: AsyncSession,
        tenant_id: str,
        actor_user_id: str,
        new_user_id: str,
        new_user_username: str,
        roles: List[str],
        created_by: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.USER_CREATED.value,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            resource_type=AuditResource.USER.value,
            resource_id=new_user_id,
            details={"username": new_user_username, "roles": roles, "created_by": created_by},
            after_state={"username": new_user_username, "roles": roles, "is_active": True},
            ip_address=ip_address,
        )

    async def log_user_updated(
        self,
        db: AsyncSession,
        tenant_id: str,
        actor_user_id: str,
        target_user_id: str,
        changed_fields: List[str],
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.USER_UPDATED.value,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            resource_type=AuditResource.USER.value,
            resource_id=target_user_id,
            details={"changed_fields": changed_fields},
            before_state=before,
            after_state=after,
            ip_address=ip_address,
        )

    async def log_user_deleted(
        self,
        db: AsyncSession,
        tenant_id: str,
        actor_user_id: str,
        target_user_id: str,
        target_username: str,
        before: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.USER_DELETED.value,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            resource_type=AuditResource.USER.value,
            resource_id=target_user_id,
            details={"username": target_username},
            before_state=before,
            ip_address=ip_address,
        )

    async def log_user_roles_changed(
        self,
        db: AsyncSession,
        tenant_id: str,
        actor_user_id: str,
        target_user_id: str,
        old_roles: List[str],
        new_roles: List[str],
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.USER_ROLES_CHANGED.value,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            resource_type=AuditResource.USER.value,
            resource_id=target_user_id,
            details={"old_roles": old_roles, "new_roles": new_roles},
            before_state={"roles": old_roles},
            after_state={"roles": new_roles},
            ip_address=ip_address,
        )

    # alert management

    async def log_alert_action(
        self,
        db: AsyncSession,
        action: str,
        tenant_id: str,
        user_id: str,
        alert_id: str,
        details: Optional[Dict[str, Any]] = None,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=action,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.ALERT.value,
            resource_id=alert_id,
            details=details,
            before_state=before_state,
            after_state=after_state,
            ip_address=ip_address,
        )

    async def log_alert_severity_changed(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        alert_id: str,
        old_severity: str,
        new_severity: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log_alert_action(
            db=db,
            action=AuditAction.ALERT_SEVERITY_CHANGED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            alert_id=alert_id,
            details={"old_severity": old_severity, "new_severity": new_severity},
            before_state={"severity": old_severity},
            after_state={"severity": new_severity},
            ip_address=ip_address,
        )

    async def log_alert_escalated(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        alert_id: str,
        escalated_to: str,
        reason: str = "",
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log_alert_action(
            db=db,
            action=AuditAction.ALERT_ESCALATED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            alert_id=alert_id,
            details={"escalated_to": escalated_to, "reason": reason},
            ip_address=ip_address,
        )

    # incident management

    async def log_incident_action(
        self,
        db: AsyncSession,
        action: str,
        tenant_id: str,
        user_id: str,
        incident_id: str,
        details: Optional[Dict[str, Any]] = None,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=action,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.INCIDENT.value,
            resource_id=incident_id,
            details=details,
            before_state=before_state,
            after_state=after_state,
            ip_address=ip_address,
        )

    # rule management

    async def log_rule_action(
        self,
        db: AsyncSession,
        action: str,
        tenant_id: str,
        user_id: str,
        rule_id: str,
        rule_name: str,
        details: Optional[Dict[str, Any]] = None,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=action,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.RULE.value,
            resource_id=rule_id,
            details={"rule_name": rule_name, **(details or {})},
            before_state=before_state,
            after_state=after_state,
            ip_address=ip_address,
        )

    # settings / config

    async def log_settings_change(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        changed_fields: List[str],
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.SETTINGS_UPDATED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.SETTINGS.value,
            details={"changed_fields": changed_fields},
            before_state=before,
            after_state=after,
            ip_address=ip_address,
        )

    async def log_config_change(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        config_section: str,
        before: Dict[str, Any],
        after: Dict[str, Any],
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.CONFIG_CHANGED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.CONFIG.value,
            resource_id=config_section,
            details={"config_section": config_section},
            before_state=before,
            after_state=after,
            ip_address=ip_address,
        )

    # device actions

    async def log_device_action(
        self,
        db: AsyncSession,
        action: str,
        tenant_id: str,
        user_id: str,
        device_id: str,
        device_hostname: str,
        details: Optional[Dict[str, Any]] = None,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=action,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.DEVICE.value,
            resource_id=device_id,
            details={"hostname": device_hostname, **(details or {})},
            before_state=before_state,
            after_state=after_state,
            ip_address=ip_address,
        )

    async def log_device_isolated(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        device_id: str,
        hostname: str,
        reason: str = "",
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log_device_action(
            db=db,
            action=AuditAction.DEVICE_ISOLATED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            device_id=device_id,
            device_hostname=hostname,
            details={"reason": reason},
            after_state={"is_isolated": True},
            ip_address=ip_address,
        )

    # ip blocking

    async def log_ip_blocked(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        ip_address_blocked: str,
        reason: str = "",
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.IP_BLOCKED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.BLOCKED_IP.value,
            resource_id=ip_address_blocked,
            details={"reason": reason},
            after_state={"is_blocked": True},
            ip_address=ip_address,
        )

    async def log_ip_unblocked(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        ip_address_unblocked: str,
        reason: str = "",
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.IP_UNBLOCKED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.BLOCKED_IP.value,
            resource_id=ip_address_unblocked,
            details={"reason": reason},
            before_state={"is_blocked": True},
            after_state={"is_blocked": False},
            ip_address=ip_address,
        )

    # session management

    async def log_session_revoked(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        session_id: str,
        reason: str = "",
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.SESSION_REVOKED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.SESSION.value,
            resource_id=session_id,
            details={"reason": reason},
            ip_address=ip_address,
        )

    async def log_all_sessions_revoked(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        target_user_id: str,
        session_count: int,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.SESSIONS_REVOKED_ALL.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.SESSION.value,
            resource_id=target_user_id,
            details={"target_user_id": target_user_id, "session_count": session_count},
            ip_address=ip_address,
        )

    # backup / restore

    async def log_backup_created(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        backup_id: str,
        size_bytes: int = 0,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.BACKUP_CREATED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.BACKUP.value,
            resource_id=backup_id,
            details={"size_bytes": size_bytes},
            ip_address=ip_address,
        )

    async def log_data_restored(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        backup_id: str,
        tables_restored: List[str],
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.DATA_RESTORED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.BACKUP.value,
            resource_id=backup_id,
            details={"tables_restored": tables_restored},
            ip_address=ip_address,
        )

    # reporting

    async def log_report_generated(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        report_id: str,
        report_type: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        return await self.log(
            db=db,
            action=AuditAction.REPORT_GENERATED.value,
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=AuditResource.REPORT.value,
            resource_id=report_id,
            details={"report_type": report_type},
            ip_address=ip_address,
        )

    # query

    async def get_logs(
        self,
        db: AsyncSession,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[AuditLog]:
        """Query audit logs with filters."""
        query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)

        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if action:
            query = query.where(AuditLog.action == action)
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        if start_date:
            query = query.where(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.where(AuditLog.timestamp <= end_date)

        query = query.order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)
        result = await db.execute(query)
        return list(result.scalars().all())

    async def get_user_activity(
        self,
        db: AsyncSession,
        tenant_id: str,
        user_id: str,
        days: int = 30,
    ) -> List[AuditLog]:
        """Get activity log for a specific user."""
        from datetime import timedelta
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        return await self.get_logs(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            start_date=start_date,
            limit=500,
        )

    async def get_security_events(
        self,
        db: AsyncSession,
        tenant_id: str,
        days: int = 7,
    ) -> List[AuditLog]:
        """Get security-related audit events."""
        from datetime import timedelta
        start_date = datetime.now(timezone.utc) - timedelta(days=days)

        query = select(AuditLog).where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action.in_(COMMON_SECURITY_ACTIONS),
            AuditLog.timestamp >= start_date,
        ).order_by(desc(AuditLog.timestamp))

        result = await db.execute(query)
        return list(result.scalars().all())


audit_service = AuditService()
