/**
 * Permission and role utility functions.
 * Separated from types.ts to keep type definitions clean.
 * This is the SINGLE source of truth for all permission logic.
 */
import { logAuthEvent } from './authTelemetry';
import type { User, UserRole } from '../types';
import { PERMISSIONS } from '../types';

// Role hierarchy (higher = more power)
export const ROLE_HIERARCHY: Record<UserRole, number> = {
  admin: 3,
  analyst: 2,
  viewer: 1,
};

/**
 * Check if a user has a specific permission.
 * This is the canonical implementation — all other checks should route through here.
 */
// All view/safe permissions — everyone (including individual/viewer) can access these
const VIEW_PERMISSIONS: string[] = [
  PERMISSIONS.ALERTS_VIEW,
  PERMISSIONS.INCIDENTS_VIEW,
  PERMISSIONS.RULES_VIEW,
  PERMISSIONS.DEVICES_VIEW,
  PERMISSIONS.DASHBOARD_VIEW,
  PERMISSIONS.SETTINGS_VIEW,
  PERMISSIONS.AUDIT_VIEW,
  PERMISSIONS.PIPELINE_VIEW,
  PERMISSIONS.AUTOMATION_VIEW,
  PERMISSIONS.THREAT_INTEL_VIEW,
  PERMISSIONS.ANALYTICS_VIEW,
  PERMISSIONS.TESTING_VIEW,
  PERMISSIONS.RESPONSE_VIEW,
  PERMISSIONS.POLICIES_VIEW,
  PERMISSIONS.NOTIFICATIONS_VIEW,
  PERMISSIONS.BILLING_VIEW,
  PERMISSIONS.ISOLATION_VIEW,
  PERMISSIONS.RETENTION_VIEW,
  PERMISSIONS.AGENT_VIEW,
  PERMISSIONS.INTEGRATIONS_VIEW,
  PERMISSIONS.TENANT_VIEW,
  PERMISSIONS.CLOUD_VIEW,
  PERMISSIONS.CSPM_VIEW,
  PERMISSIONS.WORM_VIEW,
  PERMISSIONS.RESIDENCY_VIEW,
  PERMISSIONS.ABAC_VIEW,
  PERMISSIONS.RAG_VIEW,
];

/**
 * Check if a user has a specific permission.
 * This is the canonical implementation — all other checks should route through here.
 */
export function hasPermission(user: User | null, permission: string): boolean {
  if (!user) {
    logAuthEvent({ type: 'permission_check', permission, allowed: false });
    return false;
  }

  let allowed = false;

  // Priority: explicit permissions from JWT/backend claims
  if (user.permissions && user.permissions.length > 0) {
    allowed = user.permissions.includes(permission);
  } else {
    // Fallback: role-based policy (for demo/local mode)
    if (user.role === 'admin') {
      allowed = true;
    } else if (user.role === 'analyst') {
      // Analysts get all view permissions plus specific write permissions
      allowed = VIEW_PERMISSIONS.includes(permission) || (
        permission !== PERMISSIONS.USERS_VIEW &&
        permission !== PERMISSIONS.USERS_MANAGE &&
        permission !== PERMISSIONS.SETTINGS_UPDATE &&
        permission !== PERMISSIONS.POLICIES_DELETE
      );
    } else if (user.role === 'viewer') {
      // Viewers / individual users get ALL view/safe permissions
      // (they should see all pages, just not perform write/admin actions)
      allowed = VIEW_PERMISSIONS.includes(permission);
    }
  }

  logAuthEvent({ type: 'permission_check', permission, allowed });
  return allowed;
}

// Get navigation items based on user context
export function getNavItemsForUser(user: User | null): { id: string; label: string; icon: string }[] {
  const purpose = user?.purpose || 'individual';

  if (purpose === 'individual') {
    // Individual users see ALL pages with read-only access
    return [
      { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' },
      { id: 'incidents', label: 'Incidents', icon: 'FileSearch' },
      { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle' },
      { id: 'monitoring', label: 'Live Monitor', icon: 'Activity' },
      { id: 'logs', label: 'Event Logs', icon: 'ScrollText' },
      { id: 'response', label: 'Response Center', icon: 'Shield' },
      { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
      { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
      { id: 'analytics', label: 'Analytics', icon: 'BarChart3' },
      { id: 'settings', label: 'Settings', icon: 'Settings' },
    ];
  }

  if (purpose === 'organization') {
    if (user?.role === 'admin') {
      return [
        { id: 'dashboard', label: 'Executive Dashboard', icon: 'LayoutDashboard' },
        { id: 'devices', label: 'Devices', icon: 'Monitor' },
        { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle' },
        { id: 'incidents', label: 'Incidents', icon: 'FileSearch' },
        { id: 'monitoring', label: 'Live Monitor', icon: 'Activity' },
        { id: 'logs', label: 'Event Logs', icon: 'ScrollText' },
        { id: 'response', label: 'Response Center', icon: 'Shield' },
        { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
        { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
        { id: 'users', label: 'Users', icon: 'Users' },
        { id: 'analytics', label: 'Analytics', icon: 'BarChart3' },
        { id: 'audit-logs', label: 'Audit Logs', icon: 'ScrollText' },
        { id: 'rate-limits', label: 'Rate Limits', icon: 'Activity' },
        { id: 'settings', label: 'Settings', icon: 'Settings' },
      ];
    }
    // Staff members see all relevant pages but with limited write actions
    return [
      { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' },
      { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle' },
      { id: 'incidents', label: 'Incidents', icon: 'FileSearch' },
      { id: 'monitoring', label: 'Live Monitor', icon: 'Activity' },
      { id: 'logs', label: 'Event Logs', icon: 'ScrollText' },
      { id: 'response', label: 'Response Center', icon: 'Shield' },
      { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
      { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
      { id: 'analytics', label: 'Analytics', icon: 'BarChart3' },
      { id: 'settings', label: 'Settings', icon: 'Settings' },
    ];
  }

  return [{ id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' }];
}
