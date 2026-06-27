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

/**
 * ═══════════════════════════════════════════════════════════════════
 * SINGLE SOURCE OF TRUTH for role-based page access.
 *
 * Every component (Sidebar, App.tsx route guard, etc.) MUST use
 * these functions to determine what a user can see/access.
 * ═══════════════════════════════════════════════════════════════════
 */

/** Page IDs shared across ALL roles (individual, staff, admin) */
const COMMON_PAGES = [
  'dashboard',
  'alerts',
  'incidents',
  'monitoring',
  'logs',
  'response',
  'threat-intel',
  'ai-investigation',
  'mitre',
  'analytics',
  'settings',
] as const;

/** Page IDs ONLY for admin/boss (org control) */
const ADMIN_ONLY_PAGES = [
  'devices',
  'users',
  'audit-logs',
  'rate-limits',
] as const;

/** All possible page IDs */
const ALL_PAGES = [...COMMON_PAGES, ...ADMIN_ONLY_PAGES] as const;

type PageId = typeof ALL_PAGES[number];

interface NavItem {
  id: PageId;
  label: string;
  icon: string;
}

/**
 * Navigation item metadata (icons + labels) for every page.
 */
const NAV_META: Record<PageId, { label: string; icon: string }> = {
  dashboard: { label: 'Dashboard', icon: 'LayoutDashboard' },
  alerts: { label: 'Alerts', icon: 'AlertTriangle' },
  incidents: { label: 'Incidents', icon: 'FileSearch' },
  monitoring: { label: 'Live Monitor', icon: 'Activity' },
  logs: { label: 'Event Logs', icon: 'ScrollText' },
  response: { label: 'Response Center', icon: 'Shield' },
  'threat-intel': { label: 'Threat Intel', icon: 'Globe' },
  'ai-investigation': { label: 'AI Investigation', icon: 'Brain' },
  mitre: { label: 'MITRE ATT&CK', icon: 'Crosshair' },
  analytics: { label: 'Analytics', icon: 'BarChart3' },
  settings: { label: 'Settings', icon: 'Settings' },
  devices: { label: 'Devices', icon: 'Monitor' },
  users: { label: 'Users', icon: 'Users' },
  'audit-logs': { label: 'Audit Logs', icon: 'ScrollText' },
  'rate-limits': { label: 'Rate Limits', icon: 'Activity' },
};

/** Navigation item labels — used by Sidebar.tsx to populate the nav */
export const NAV_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(NAV_META).map(([id, meta]) => [id, meta.label])
) as Record<string, string>;

/** Navigation item icons — used by Sidebar.tsx to populate the nav */
export const NAV_ICONS: Record<string, string> = Object.fromEntries(
  Object.entries(NAV_META).map(([id, meta]) => [id, meta.icon])
) as Record<string, string>;

/**
 * Get the NAVIGATION ITEMS (for sidebar) based on user context.
 * Returns { id, label, icon } array.
 * This is used by Sidebar.tsx to draw the nav menu.
 */
export function getNavItemsForUser(user: User | null): NavItem[] {
  const pageIds = getAllowedPageIds(user);
  return pageIds
    .map(id => {
      const meta = NAV_META[id as PageId];
      if (!meta) return null;
      return { id: id as PageId, label: meta.label, icon: meta.icon };
    })
    .filter((item): item is NavItem => item !== null);
}

/**
 * Get the ALLOWED PAGE IDs (for route guarding) based on user context.
 * This is used by App.tsx to block access to pages the user shouldn't see.
 *
 * ROLES:
 *   Individual — single user protecting their own devices
 *   Staff      — org member with monitoring/response access, NO management
 *   Admin/Boss — full org control (devices, users, audit-logs, rate-limits)
 */
export function getAllowedPageIds(user: User | null): string[] {
  const purpose = user?.purpose || 'individual';
  const role = user?.role || 'viewer';

  if (purpose === 'organization' && role === 'admin') {
    // Admin/Boss: common pages + admin-only management pages
    return [...COMMON_PAGES, ...ADMIN_ONLY_PAGES];
  }

  // Individual & Staff: common pages only (no admin management)
  return [...COMMON_PAGES];
}
