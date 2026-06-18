"""
CyberNova — RBAC Dependencies
FastAPI dependencies for permission checking.
"""


from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.auth.rbac import Permission, has_any_permission, denied_tracker
from cybernova.audit.service import audit_service, AuditAction, AuditResource
from cybernova.database.postgres.session import get_db


class RequirePermission:
    """Dependency that requires specific permissions."""
    
    def __init__(self, *permissions: Permission):
        self.permissions = list(permissions)
    
    async def __call__(
        self,
        request: Request,
        user: CurrentUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> CurrentUser:
        if not has_any_permission(user.roles, self.permissions):
            ip = request.client.host if request.client else "unknown"
            count = denied_tracker.record(ip)
            if denied_tracker.is_abusing(ip):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many permission denials — access temporarily blocked",
                )
            await audit_service.log(
                db=db,
                action=AuditAction.PERMISSION_DENIED.value,
                tenant_id=user.tenant_id,
                user_id=user.id,
                resource_type=AuditResource.USER.value,
                resource_id=user.id,
                details={
                    "required_permissions": [p.value for p in self.permissions],
                    "user_roles": user.roles,
                    "path": str(request.url.path),
                    "method": request.method,
                    "denial_count": count,
                },
                ip_address=ip,
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[p.value for p in self.permissions]}",
            )
        return user


class RequireAdmin:
    """Dependency that requires admin role."""
    
    async def __call__(
        self,
        request: Request,
        user: CurrentUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> CurrentUser:
        if "admin" not in user.roles:
            ip = request.client.host if request.client else "unknown"
            count = denied_tracker.record(ip)
            if denied_tracker.is_abusing(ip):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many permission denials — access temporarily blocked",
                )
            await audit_service.log(
                db=db,
                action=AuditAction.PERMISSION_DENIED.value,
                tenant_id=user.tenant_id,
                user_id=user.id,
                resource_type=AuditResource.USER.value,
                resource_id=user.id,
                details={
                    "required_role": "admin",
                    "user_roles": user.roles,
                    "path": str(request.url.path),
                    "method": request.method,
                    "denial_count": count,
                },
                ip_address=ip,
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )
        return user


require_alerts_view = RequirePermission(Permission.ALERTS_VIEW)
require_alerts_update = RequirePermission(Permission.ALERTS_UPDATE)
require_alerts_delete = RequirePermission(Permission.ALERTS_DELETE)

require_incidents_view = RequirePermission(Permission.INCIDENTS_VIEW)
require_incidents_update = RequirePermission(Permission.INCIDENTS_UPDATE)

require_rules_view = RequirePermission(Permission.RULES_VIEW)
require_rules_create = RequirePermission(Permission.RULES_CREATE)
require_rules_update = RequirePermission(Permission.RULES_UPDATE)
require_rules_delete = RequirePermission(Permission.RULES_DELETE)

require_users_view = RequirePermission(Permission.USERS_VIEW)
require_users_create = RequirePermission(Permission.USERS_CREATE)
require_users_update = RequirePermission(Permission.USERS_UPDATE)
require_users_delete = RequirePermission(Permission.USERS_DELETE)

require_devices_view = RequirePermission(Permission.DEVICES_VIEW)
require_devices_manage = RequirePermission(Permission.DEVICES_MANAGE)

require_settings_view = RequirePermission(Permission.SETTINGS_VIEW)
require_settings_update = RequirePermission(Permission.SETTINGS_UPDATE)

require_audit_view = RequirePermission(Permission.AUDIT_VIEW)
require_pipeline_view = RequirePermission(Permission.PIPELINE_VIEW)
require_pipeline_manage = RequirePermission(Permission.PIPELINE_MANAGE)

require_automation_view = RequirePermission(Permission.AUTOMATION_VIEW)
require_automation_trigger = RequirePermission(Permission.AUTOMATION_TRIGGER)

require_threat_intel_view = RequirePermission(Permission.THREAT_INTEL_VIEW)
require_threat_intel_manage = RequirePermission(Permission.THREAT_INTEL_MANAGE)

require_analytics_view = RequirePermission(Permission.ANALYTICS_VIEW)

require_data_export = RequirePermission(Permission.DATA_EXPORT)
require_data_delete = RequirePermission(Permission.DATA_DELETE)

require_dashboard_view = RequirePermission(Permission.DASHBOARD_VIEW)
require_testing_view = RequirePermission(Permission.TESTING_VIEW)
require_testing_execute = RequirePermission(Permission.TESTING_EXECUTE)
require_anomaly_view = RequirePermission(Permission.ANOMALY_VIEW)
require_isolation_view = RequirePermission(Permission.ISOLATION_VIEW)
require_isolation_manage = RequirePermission(Permission.ISOLATION_MANAGE)
require_retention_view = RequirePermission(Permission.RETENTION_VIEW)
require_retention_manage = RequirePermission(Permission.RETENTION_MANAGE)
require_agent_view = RequirePermission(Permission.AGENT_VIEW)
require_agent_manage = RequirePermission(Permission.AGENT_MANAGE)
require_integrations_view = RequirePermission(Permission.INTEGRATIONS_VIEW)
require_integrations_manage = RequirePermission(Permission.INTEGRATIONS_MANAGE)
require_tenant_view = RequirePermission(Permission.TENANT_VIEW)
require_tenant_manage = RequirePermission(Permission.TENANT_MANAGE)
require_notifications_view = RequirePermission(Permission.NOTIFICATIONS_VIEW)
require_notifications_manage = RequirePermission(Permission.NOTIFICATIONS_MANAGE)

require_cloud_ingest = RequirePermission(Permission.CLOUD_INGEST)
require_cloud_view = RequirePermission(Permission.CLOUD_VIEW)

require_cspm_scan = RequirePermission(Permission.CSPM_SCAN)
require_cspm_view = RequirePermission(Permission.CSPM_VIEW)

require_worm_write = RequirePermission(Permission.WORM_WRITE)
require_worm_view = RequirePermission(Permission.WORM_VIEW)
require_worm_verify = RequirePermission(Permission.WORM_VERIFY)

require_residency_view = RequirePermission(Permission.RESIDENCY_VIEW)
require_residency_admin = RequirePermission(Permission.RESIDENCY_ADMIN)

require_abac_view = RequirePermission(Permission.ABAC_VIEW)
require_abac_manage = RequirePermission(Permission.ABAC_MANAGE)

require_rag_view = RequirePermission(Permission.RAG_VIEW)
require_rag_manage = RequirePermission(Permission.RAG_MANAGE)

require_admin = RequireAdmin()
