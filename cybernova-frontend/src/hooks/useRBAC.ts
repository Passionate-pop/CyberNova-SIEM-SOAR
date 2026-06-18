import { useAuth } from './useAuth';
import { PERMISSIONS } from '../types';

type Permission = typeof PERMISSIONS[keyof typeof PERMISSIONS];

// Admin gets ALL known permissions
const ADMIN_PERMISSIONS: Permission[] = [
  PERMISSIONS.ALERTS_VIEW, PERMISSIONS.ALERTS_UPDATE, PERMISSIONS.ALERTS_DELETE,
  PERMISSIONS.INCIDENTS_VIEW, PERMISSIONS.INCIDENTS_UPDATE,
  PERMISSIONS.SETTINGS_VIEW, PERMISSIONS.SETTINGS_UPDATE,
  PERMISSIONS.USERS_VIEW, PERMISSIONS.USERS_MANAGE,
  PERMISSIONS.DEVICES_VIEW, PERMISSIONS.DEVICES_MANAGE,
  PERMISSIONS.POLICIES_VIEW, PERMISSIONS.POLICIES_CREATE, PERMISSIONS.POLICIES_UPDATE, PERMISSIONS.POLICIES_DELETE,
  PERMISSIONS.AUDIT_VIEW,
  PERMISSIONS.PIPELINE_VIEW, PERMISSIONS.PIPELINE_MANAGE,
  PERMISSIONS.RULES_VIEW, PERMISSIONS.RULES_CREATE,
  PERMISSIONS.RESPONSE_VIEW, PERMISSIONS.RESPONSE_TRIGGER,
  PERMISSIONS.BILLING_VIEW,
];

// Viewers: read-only access to alerts, incidents, rules, response
const VIEWER_PERMISSIONS: Permission[] = [
  PERMISSIONS.ALERTS_VIEW,
  PERMISSIONS.INCIDENTS_VIEW,
  PERMISSIONS.RULES_VIEW,
  PERMISSIONS.RESPONSE_VIEW,
];

// Analysts: full alert/incident lifecycle + investigation + response
const ANALYST_PERMISSIONS: Permission[] = [
  PERMISSIONS.ALERTS_VIEW, PERMISSIONS.ALERTS_UPDATE,
  PERMISSIONS.INCIDENTS_VIEW, PERMISSIONS.INCIDENTS_UPDATE,
  PERMISSIONS.DEVICES_VIEW,
  PERMISSIONS.POLICIES_VIEW, PERMISSIONS.POLICIES_CREATE,
  PERMISSIONS.AUDIT_VIEW,
  PERMISSIONS.PIPELINE_VIEW,
  PERMISSIONS.RULES_VIEW,
  PERMISSIONS.RESPONSE_VIEW, PERMISSIONS.RESPONSE_TRIGGER,
];

export function useRBAC() {
  const { user } = useAuth();
  
  const role = user?.role || 'viewer';
  const isAdmin = role === 'admin';
  const isAnalyst = role === 'analyst';
  const isViewer = role === 'viewer';
  const permissions = isAdmin
    ? ADMIN_PERMISSIONS
    : isAnalyst
      ? ANALYST_PERMISSIONS
      : VIEWER_PERMISSIONS;
  
  const can = (permission: Permission): boolean => {
    return permissions.includes(permission);
  };
  
  const canAny = (...perms: Permission[]): boolean => {
    return perms.some(p => permissions.includes(p));
  };
  
  return {
    role,
    permissions,
    can,
    canAny,
    isAdmin,
    isAnalyst,
    isViewer,
  };
}
