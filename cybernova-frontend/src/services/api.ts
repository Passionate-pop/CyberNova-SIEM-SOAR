/**
 * CyberNova API Service Layer
 *
 * Features:
 *   - Auto-attaches JWT from localStorage
 *   - 401 → auto-logout (clears stored user)
 *   - Global error interceptor → shows connection error banner on failure
 */

// Track API health for connection error banner
let _apiDown = false;
let _apiDownListeners: Array<(down: boolean) => void> = [];
let _authClearedListeners: Array<() => void> = [];

export function onApiHealthChange(cb: (down: boolean) => void): () => void {
  _apiDownListeners.push(cb);
  return () => { _apiDownListeners = _apiDownListeners.filter(l => l !== cb); };
}
export function isApiDown(): boolean { return _apiDown; }
function setApiDown(down: boolean) {
  if (_apiDown !== down) {
    _apiDown = down;
    _apiDownListeners.forEach(cb => cb(down));
  }
}

/**
 * Subscribe to auth-cleared events (e.g. session expiry).
 * Components like App.tsx use this to reset their in-memory state.
 */
export function onAuthCleared(cb: () => void): () => void {
  _authClearedListeners.push(cb);
  return () => { _authClearedListeners = _authClearedListeners.filter(l => l !== cb); };
}

import { logAuthEvent } from '../utils/authTelemetry';
import {
  seedDemoData as seedFrontendDemo,
  getDemoAlerts,
  getDemoIncidents,
  getDemoLogs,
  getDemoThreatIntel,
  getDemoGlobalFeed,
  getDemoResponseActions,
  getDemoAIAnalysis,
  getDemoAuditLogs,
  getDemoPlaybooks,
} from './demoData';
import type {
  Alert, Incident, DashboardMetrics, TopThreat,
  SystemLog, NetworkConnection, ProcessInfo,
  ResponseAction, ThreatIntelItem, GlobalThreatFeed, AIAnalysis,
  LoginCredentials, User, UserRole, ActionType, RuleConfig, TokenResponse,
  Device, AuditLog, DeviceStatus, Playbook,
} from '../types';
import { PERMISSIONS } from '../types';

export type Permission = typeof PERMISSIONS[keyof typeof PERMISSIONS];

const VALID_ROLES = ['admin', 'analyst', 'viewer'] as const;

function isUserRole(role: unknown): role is UserRole {
  return typeof role === 'string' && (VALID_ROLES as readonly string[]).includes(role);
}

function normalizePermissions(perms: unknown[]): string[] {
  if (!Array.isArray(perms)) return [];
  const strings = perms.filter((p): p is string => typeof p === 'string');
  return Array.from(new Set(strings));
}

interface JwtPayload {
  user_id?: string;
  username?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  tenant_id?: string;
  purpose?: string;
  org_type?: string;
  org_name?: string;
  company_size?: string;
}
import { config } from '../config';

// ===== HTTP Client =====

const AUTH_STORAGE_KEY = 'cybernova-auth';

interface StoredAuth {
  state?: {
    token?: string;
  };
}

function getStoredToken(): string | null {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (stored) {
      const parsed: StoredAuth = JSON.parse(stored);
      return parsed.state?.token || null;
    }
  } catch (error) {
    logAuthEvent({ type: 'auth_storage_corrupt', error: error instanceof Error ? error.message : String(error) });
  }
  return null;
}

/**
 * Clear the full auth state from localStorage on 401.
 * This ensures the next render cycle shows the login page
 * instead of attempting to render the authenticated UI.
 */
function clearAuthState(): void {
  try {
    // Reset the Zustand persist store so isAuthenticated=false
    const freshState = { state: { user: null, token: null, isAuthenticated: false }, version: 0 };
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(freshState));
  } catch {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  }
  // Also clear any legacy token storage
  localStorage.removeItem('cybernova_token');
  // Notify listeners to update in-memory state (avoid circular import deps)
  _authClearedListeners.forEach(cb => cb());
}

export function clearAuth(): void {
  clearAuthState();
}

interface FetchOptions {
  method?: string;
  body?: unknown;
  noAuth?: boolean;
}

async function apiRequest<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { method = 'GET', body, noAuth = false } = options;
  const url = `${config.apiBaseUrl}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (!noAuth) {
    const token = getStoredToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    logAuthEvent({ type: 'session_expired', path: endpoint });
    // Clear the entire auth state so the login page shows — NO page reload
    clearAuthState();
    setApiDown(true);
    throw new Error('Session expired');
  }

  if (!res.ok) {
    // Only mark API as down for server errors (5xx) — not for client errors (4xx)
    // 4xx means the server is up but the request was bad/not found — not a connectivity issue
    if (res.status >= 500) {
      setApiDown(true);
    }
    const errorBody = await res.json().catch(() => ({ detail: res.statusText }));
    const rawDetail = errorBody.detail ?? res.statusText;
    // Handle non-string detail (e.g. Pydantic validation errors as array of objects)
    const detailStr = typeof rawDetail === 'string'
      ? rawDetail
      : Array.isArray(rawDetail)
        ? rawDetail.map((d: Record<string, unknown>) => d.msg || d.message || JSON.stringify(d)).join('; ')
        : typeof rawDetail === 'object'
          ? JSON.stringify(rawDetail)
          : String(rawDetail);
    logAuthEvent({ type: 'api_error', endpoint, status: res.status, message: detailStr });
    throw new Error(detailStr);
  }

  // Reset API health on successful request
  if (_apiDown) setApiDown(false);

  return res.json();
}

async function safeFetch<T>(endpoint: string, options?: FetchOptions): Promise<T> {
  return apiRequest<T>(endpoint, options);
}


// ===== Lake-1: Auth =====

export async function login(credentials: LoginCredentials): Promise<User> {
  // Backend returns TokenResponse: { access_token, refresh_token, token_type, expires_in }
  // Frontend needs User: { id, username, role, roles, permissions, tenant_id, token }
  let tokenResponse: TokenResponse;
  try {
    tokenResponse = await apiRequest<TokenResponse>(
      '/api/v1/auth/login',
      { method: 'POST', body: credentials, noAuth: true }
    );
  } catch (error) {
    logAuthEvent({ type: 'login_failed', reason: error instanceof Error ? error.message : String(error) });
    throw error;
  }

  // Decode the JWT payload to extract user info
  const payload = decodeJwtPayload(tokenResponse.access_token);

  if (!Array.isArray(payload.roles)) {
    logAuthEvent({ type: 'invalid_roles_array', value: payload.roles });
  }

  const rawRoles: UserRole[] = Array.isArray(payload.roles)
    ? payload.roles.filter((r) => {
        const valid = isUserRole(r);
        if (!valid) {
          logAuthEvent({ type: 'invalid_role', value: r });
        }
        return valid;
      })
    : [];
  const safeRoles: UserRole[] = rawRoles.length > 0 ? rawRoles : ['viewer'];
  if (rawRoles.length === 0) {
    logAuthEvent({ type: 'fallback_role_used', role: 'viewer' });
  }
  const role: UserRole = safeRoles[0];

  return {
    id: payload.user_id || 'unknown',
    username: payload.username || credentials.username,
    email: payload.email || '',
    role,
    roles: safeRoles,
    permissions: normalizePermissions(payload.permissions || []),
    tenant_id: payload.tenant_id || 'default',
    token: tokenResponse.access_token,
    // Organization context from JWT
    purpose: (payload.purpose as User['purpose']) || undefined,
    org_type: (payload.org_type as User['org_type']) || undefined,
    org_name: payload.org_name || undefined,
    company_size: payload.company_size || undefined,
  };
}

export async function registerUser(
  username: string, email: string, password: string,
  fallbackRole: UserRole = 'viewer', orgKey?: string, _orgName?: string, _tenantName?: string
): Promise<User> {
  const body: Record<string, unknown> = { username, email, password, roles: [fallbackRole] };
  if (orgKey) body.org_key = orgKey;
  if (_tenantName) body.tenant_name = _tenantName;
  let tokenResponse: TokenResponse;
  try {
    tokenResponse = await apiRequest<TokenResponse>(
      '/api/v1/auth/register',
      { method: 'POST', body, noAuth: true }
    );
  } catch (error) {
    logAuthEvent({ type: 'login_failed', reason: `Registration failed: ${error instanceof Error ? error.message : String(error)}` });
    throw error;
  }

  const payload = decodeJwtPayload(tokenResponse.access_token);

  if (!Array.isArray(payload.roles)) {
    logAuthEvent({ type: 'invalid_roles_array', value: payload.roles });
  }

  const rawRoles: UserRole[] = Array.isArray(payload.roles)
    ? payload.roles.filter((r) => {
        const valid = isUserRole(r);
        if (!valid) {
          logAuthEvent({ type: 'invalid_role', value: r });
        }
        return valid;
      })
    : [];
  const safeRoles: UserRole[] = rawRoles.length > 0 ? rawRoles : [fallbackRole];
  if (rawRoles.length === 0) {
    logAuthEvent({ type: 'fallback_role_used', role: fallbackRole });
  }
  const role: UserRole = safeRoles[0];

  return {
    id: payload.user_id || 'unknown',
    username: payload.username || username,
    email: payload.email || email,
    role,
    roles: safeRoles,
    permissions: normalizePermissions(payload.permissions || []),
    tenant_id: payload.tenant_id || 'default',
    token: tokenResponse.access_token,
    // Organization context from JWT
    purpose: (payload.purpose as User['purpose']) || undefined,
    org_type: (payload.org_type as User['org_type']) || undefined,
    org_name: payload.org_name || undefined,
    company_size: payload.company_size || undefined,
    // One-time org key from registration response (for admin to share with staff)
    org_key: tokenResponse.org_key || undefined,
  };
}

function decodeJwtPayload(token: string): JwtPayload {
  try {
    const base64 = token.split('.')[1];
    const json = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json) as JwtPayload;
  } catch (error) {
    console.error('Failed to decode JWT payload:', error);
    return {};
  }
}

/**
 * Reconstruct a User object from a stored JWT token.
 * Used on page load to initialize auth state from token alone,
 * without needing a server round-trip.
 */
export function reconstructUserFromToken(token: string, fallbackUsername?: string): User | null {
  try {
    const payload = decodeJwtPayload(token);
    if (!payload || !payload.user_id) {
      return null;
    }

    const rawRoles: UserRole[] = Array.isArray(payload.roles)
      ? payload.roles.filter((r): r is UserRole => isUserRole(r))
      : [];
    const safeRoles: UserRole[] = rawRoles.length > 0 ? rawRoles : ['viewer'];
    const role: UserRole = safeRoles[0];

    return {
      id: payload.user_id,
      username: payload.username || fallbackUsername || 'User',
      email: payload.email || '',
      role,
      roles: safeRoles,
      permissions: normalizePermissions(payload.permissions || []),
      tenant_id: payload.tenant_id || 'default',
      token,
      // Organization context from JWT (needed after page refresh)
      purpose: (payload.purpose as User['purpose']) || undefined,
      org_type: (payload.org_type as User['org_type']) || undefined,
      org_name: payload.org_name || undefined,
      company_size: payload.company_size || undefined,
    };
  } catch {
    return null;
  }
}


// ===== Lake-0: Core Metrics =====

export async function fetchMetrics(): Promise<DashboardMetrics> {
  try {
    const metrics = await safeFetch<DashboardMetrics>('/api/v1/dashboard/summary');
    if (metrics && metrics.total_alerts !== undefined) return metrics;
    // Backend returned valid response but no real data yet — return zeros, NOT fake data
    return { total_alerts: 0, active_incidents: 0, risk_score: 0, system_health: 100, alerts_today: 0, blocked_ips: 0, threats_mitigated: 0, uptime: 99.9 };
  } catch {
    // Connection error — return zeros with uptime=0 to signal offline state
    return { total_alerts: 0, active_incidents: 0, risk_score: 0, system_health: 0, alerts_today: 0, blocked_ips: 0, threats_mitigated: 0, uptime: 0 };
  }
}

export async function fetchTopThreats(): Promise<TopThreat[]> {
  const alerts = await fetchAlerts();
  return deriveTopThreats(alerts);
}

// ===== Notifications =====

export interface NotificationItem {
  id: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  timestamp: string;
}

export async function fetchNotifications(): Promise<{ notifications: NotificationItem[]; unread_count: number }> {
  return safeFetch('/api/v1/notifications?limit=50');
}

export async function markNotificationRead(id: string): Promise<{ success: boolean }> {
  return apiRequest(`/api/v1/notifications/${id}/read`, { method: 'PUT' });
}

export async function markAllNotificationsRead(): Promise<{ success: boolean }> {
  return apiRequest('/api/v1/notifications/read-all', { method: 'PUT' });
}

// ===== Playbook CRUD =====

export async function savePlaybook(playbook: Partial<Playbook>): Promise<Playbook> {
  return apiRequest('/api/v1/response/playbooks', {
    method: 'POST',
    body: playbook,
  });
}

export async function updatePlaybook(id: string, playbook: Partial<Playbook>): Promise<{ success: boolean }> {
  return apiRequest(`/api/v1/response/playbooks/${id}`, {
    method: 'PUT',
    body: playbook,
  });
}

export async function deletePlaybook(id: string): Promise<{ success: boolean }> {
  return apiRequest(`/api/v1/response/playbooks/${id}`, {
    method: 'DELETE',
  });
}

// ===== Network Connections & Processes (real endpoints) =====

export async function fetchConnections(): Promise<NetworkConnection[]> {
  try {
    const conns = await safeFetch<NetworkConnection[]>('/api/v1/dashboard/connections');
    if (conns && conns.length > 0) return conns;
  } catch { /* fall through */ }
  return [];
}

export async function fetchProcesses(): Promise<ProcessInfo[]> {
  try {
    const procs = await safeFetch<ProcessInfo[]>('/api/v1/dashboard/processes');
    if (procs && procs.length > 0) return procs;
  } catch { /* fall through */ }
  return [];
}


// ===== Noise Control (Alert Actions) =====

export async function snoozeAlert(alertId: string, hours: number = 24): Promise<{ success: boolean }> {
  return apiRequest(`/api/v1/detect/alerts/${alertId}/snooze`, {
    method: 'POST',
    body: { hours },
  });
}

export async function whitelistEntity(entity: string, entityType: string = 'ip', reason?: string): Promise<{ success: boolean }> {
  return apiRequest('/api/v1/detect/whitelist', {
    method: 'POST',
    body: { entity, entity_type: entityType, reason },
  });
}

export async function markAlertSafe(alertId: string): Promise<{ success: boolean }> {
  return apiRequest(`/api/v1/detect/alerts/${alertId}/mark-safe`, {
    method: 'POST',
  });
}

// ===== User Management =====

export async function updateUserRole(userId: string, roles: string[]): Promise<{ status: string; user_id: string; roles: string[] }> {
  return apiRequest(`/api/v1/admin/users/${userId}/roles`, {
    method: 'PUT',
    body: { roles },
  });
}

export async function disableUser(userId: string): Promise<{ success: boolean; message: string }> {
  return apiRequest(`/api/v1/soar/disable-user/${userId}`, {
    method: 'POST',
  });
}

// ===== SOAR Actions =====

export async function blockIP(ip: string, reason: string = 'Threat detected', durationHours: number = 0): Promise<{ success: boolean; message: string }> {
  return apiRequest('/api/v1/soar/block-ip', {
    method: 'POST',
    body: { ip_address: ip, reason, duration_hours: durationHours },
  });
}

export async function isolateDevice(deviceId: string): Promise<{ success: boolean; message: string }> {
  return apiRequest(`/api/v1/soar/isolate-device/${deviceId}`, {
    method: 'POST',
  });
}

// ===== Playbooks =====

export async function fetchPlaybooks(): Promise<Playbook[]> {
  try {
    const result = await safeFetch<{ playbooks: Playbook[] }>('/api/v1/response/playbooks');
    if (result.playbooks && result.playbooks.length > 0) return result.playbooks || [];
    return [];
  } catch { /* fall through */ }
  try { return getDemoPlaybooks(); } catch { return []; }
}

// ===== System Control =====

export async function resetDemo(): Promise<{ success: boolean; deleted: Record<string, number> }> {
  return apiRequest('/api/v1/demo/reset', { method: 'POST' });
}

// ===== Setup =====

export async function checkSetupStatus(): Promise<{ needs_setup: boolean; admin_exists: boolean; db_connected: boolean; redis_connected: boolean }> {
  return apiRequest('/api/v1/setup/status', { noAuth: true });
}

export async function createFirstAdmin(email: string, password: string, companyName: string): Promise<User> {
  return apiRequest('/api/v1/setup/admin', {
    method: 'POST',
    noAuth: true,
    body: { email, password, company_name: companyName },
  });
}

// ===== Lake-3: Detection =====

export async function fetchAlerts(): Promise<Alert[]> {
  try {
    const alerts = await safeFetch<Alert[]>('/api/v1/dashboard/alerts');
    if (alerts && alerts.length > 0) {
      return alerts
        .filter(a => a.type !== 'agent_heartbeat')
        .map(a => ({ ...a, id: a.alert_id }));
    }
    // Backend returned empty array — this is valid (no alerts yet), NOT an error
    return [];
  } catch { /* fall through to demo data */ }
  // Only fall back to demo data on connection errors, not empty results
  try { return getDemoAlerts().map(a => ({ ...a, id: a.alert_id })); } catch { return []; }
}

export async function fetchAlertById(id: string): Promise<Alert | undefined> {
  try {
    return await apiRequest<Alert>(`/api/v1/dashboard/alerts/${id}`);
  } catch {
    const demoAlerts = getDemoAlerts();
    return demoAlerts.find(a => a.alert_id === id);
  }
}

export async function fetchIncidents(): Promise<Incident[]> {
  try {
    const incidents = await safeFetch<Incident[]>('/api/v1/dashboard/incidents');
    if (incidents && incidents.length > 0) return incidents;
    return [];
  } catch { /* fall through */ }
  try { return getDemoIncidents(); } catch { return []; }
}

export async function fetchIncidentById(id: string): Promise<Incident | undefined> {
  const incidents = await fetchIncidents();
  return incidents.find(i => i.incident_id === id);
}

// ===== Incidents =====

export async function resolveIncident(incidentId: string): Promise<{ incident_id: string; status: string; updated: boolean }> {
  return apiRequest(`/api/v1/detect/incidents/${incidentId}/resolve`, { method: 'POST' });
}

export async function escalateIncident(incidentId: string): Promise<{ incident_id: string; status: string; escalation_level: number; updated: boolean }> {
  return apiRequest(`/api/v1/detect/incidents/${incidentId}/escalate`, { method: 'POST' });
}

export async function exportIncidentReport(incidentId: string): Promise<Blob> {
  const token = getStoredToken();
  const url = `${config.apiBaseUrl}/api/v1/detect/incidents/${incidentId}/export`;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error('Failed to export incident report');
  return res.blob();
}

// ===== Devices =====

export async function seedDemoData(): Promise<{ status: string; message: string }> {
  seedFrontendDemo();
  try {
    return await apiRequest('/api/v1/dashboard/seed', { method: 'POST' });
  } catch {
    return { status: 'ok', message: 'Demo data seeded (frontend fallback)' };
  }
}

export async function simulateAttack(): Promise<{ status: string; message: string }> {
  return apiRequest('/api/v1/pipeline/simulate-attack', { method: 'POST' });
}

export async function injectTestSoarActions(): Promise<{ status: string; actions_created: number; message: string }> {
  return apiRequest('/api/v1/pipeline/test-soar-actions', { method: 'POST' });
}

export async function fetchPipelineStatus(): Promise<{
  running: boolean;
  stats: {
    events_ingested: number;
    events_normalized: number;
    events_enriched: number;
    alerts_created: number;
    incidents_created: number;
    errors: number;
    last_event_time: string | null;
    last_alert_time: string | null;
    processing_latency_ms: number;
    queue_depths: Record<string, number>;
  };
}> {
  return safeFetch('/api/v1/pipeline/status');
}

export async function fetchDevices(): Promise<Device[]> {
  try {
    const result = await safeFetch<{ devices: Array<Record<string, unknown>>; total: number }>('/api/v1/admin/devices');
    if (result.devices && result.devices.length > 0) {
      return (result.devices || []).map((d) => ({
        id: (d.id as string) || '',
        hostname: (d.hostname as string) || 'unknown',
        ip_address: (d.ip_address as string) || '',
        os_type: (d.os_type as string) || undefined,
        status: (d.status as DeviceStatus) || 'offline',
        last_heartbeat: (d.last_heartbeat as string) || undefined,
        tenant_id: (d.tenant_id as string) || '',
        is_active: (d.is_active as boolean) ?? true,
      }));
    }
    return [];
  } catch { /* fall through */ }
  return [];
}

// ===== Users =====

export async function fetchUsers(): Promise<User[]> {
  try {
    const result = await safeFetch<{ users: Array<Record<string, unknown>>; total: number }>('/api/v1/admin/users/');
    if (result.users && result.users.length > 0) {
      return (result.users || []).map((u) => ({
        id: (u.id as string) || '',
        username: (u.username as string) || 'unknown',
        email: (u.email as string) || '',
        role: ((u.roles as string[])?.[0] as UserRole) || 'viewer',
        roles: (u.roles as UserRole[]) || ['viewer'],
        permissions: [],
        tenant_id: (u.tenant_id as string) || '',
        token: '',
      }));
    }
  } catch { /* fall through — admin-only endpoint, viewers get empty list */ }
  return [];
}

// ===== Audit Logs =====

export async function fetchAuditLogs(): Promise<AuditLog[]> {
  try {
    const result = await safeFetch<{ logs: Array<Record<string, unknown>>; total: number }>('/api/v1/audit/logs');
    if (result.logs && result.logs.length > 0) {
      return (result.logs || []).map((l) => ({
        id: (l.id as string) || '',
        timestamp: (l.timestamp as string) || '',
        user_id: (l.user_id as string) || 'system',
        action: (l.action as string) || '',
        resource_type: (l.resource_type as string) || undefined,
        resource_id: (l.resource_id as string) || undefined,
        details: (l.details as Record<string, unknown>) || undefined,
        ip_address: (l.ip_address as string) || undefined,
      }));
    }
    return [];
  } catch { /* fall through */ }
  try { return getDemoAuditLogs(); } catch { return []; }
}


// ===== Lake-2: Monitoring =====

export async function fetchLogs(): Promise<SystemLog[]> {
  try {
    const logs = await safeFetch<SystemLog[]>('/api/v1/dashboard/logs');
    if (logs && logs.length > 0) return logs;
    return [];
  } catch { /* fall through */ }
  try { return getDemoLogs(); } catch { return []; }
}


// ===== Lake-4: Response =====

export async function fetchResponseActions(): Promise<ResponseAction[]> {
  try {
    const actions = await safeFetch<ResponseAction[]>('/api/v1/dashboard/response/actions');
    if (actions && actions.length > 0) return actions;
    return [];
  } catch { /* fall through */ }
  try { return getDemoResponseActions(); } catch { return []; }
}

export async function executeAction(actionType: ActionType, target: string): Promise<ResponseAction> {
  return apiRequest<ResponseAction>(
    '/api/v1/dashboard/response/action',
    {
      method: 'POST',
      body: {
        action_type: actionType,
        target,
      },
    }
  );
}


// ===== Lake-7: Threat Intelligence =====

export async function fetchThreatIntel(): Promise<ThreatIntelItem[]> {
  try {
    const intel = await safeFetch<ThreatIntelItem[]>('/api/v1/dashboard/threat-intel');
    if (intel && intel.length > 0) return intel;
    return [];
  } catch { /* fall through */ }
  try { return getDemoThreatIntel(); } catch { return []; }
}

export async function fetchGlobalFeed(): Promise<GlobalThreatFeed[]> {
  try {
    const feed = await safeFetch<GlobalThreatFeed[]>('/api/v1/dashboard/global-feed');
    if (feed && feed.length > 0) return feed;
    return [];
  } catch { /* fall through */ }
  try { return getDemoGlobalFeed(); } catch { return []; }
}


// ===== Lake-6: AI =====

export async function fetchAIAnalysis(incidentId?: string): Promise<AIAnalysis> {
  try {
    const params = incidentId ? `?incident_id=${incidentId}` : '';
    const analysis = await safeFetch<AIAnalysis>(`/api/v1/dashboard/ai/analysis${params}`);
    if (analysis && analysis.summary && analysis.summary !== 'No incidents to analyze') return analysis;
  } catch { /* fall through */ }
  try { return getDemoAIAnalysis(incidentId); } catch {
    return { summary: 'No analysis available', attack_narrative: '', risk_assessment: '', recommended_actions: [], confidence: 0, timeline_reconstruction: [], mitre_techniques: [], affected_assets: [] };
  }
}

// ===== Billing =====

export interface Plan {
  id: string;
  name: string;
  price_monthly: number;
  events_limit: number;
  rate_limit: number;
  features: string[];
}

export interface SubscriptionStatus {
  tenant_id: string;
  plan: string;
  plan_name: string;
  status: string;
  events_limit: number;
  events_used: number;
  events_remaining: number;
  rate_limit: number;
  features: string[];
  is_active: boolean;
}

export interface UsageStats {
  events_used: number;
  events_limit: number;
  events_remaining: number;
  percent_used: number;
}

export async function fetchPlans(): Promise<Plan[]> {
  const result = await safeFetch<{ plans: Plan[] }>('/api/v1/billing/plans');
  return result.plans || [];
}

export async function fetchSubscription(): Promise<SubscriptionStatus> {
  return safeFetch<SubscriptionStatus>('/api/v1/billing/subscription');
}

export async function fetchUsage(): Promise<UsageStats> {
  return safeFetch<UsageStats>('/api/v1/billing/usage');
}

export async function upgradePlan(planId: string): Promise<{ status: string; plan: string }> {
  return apiRequest('/api/v1/billing/upgrade', {
    method: 'POST',
    body: { plan: planId },
  });
}

export async function createCheckout(planId: string): Promise<{ checkout_url: string; session_id: string }> {
  return apiRequest('/api/v1/billing/checkout', {
    method: 'POST',
    body: { plan: planId },
  });
}

// ===== Security =====

export interface SecurityOverview {
  waf_stats?: {
    total_inspections: number;
    rules_count: number;
    cache?: {
      hits: number;
      misses: number;
      size: number;
      maxsize: number;
      hit_rate: number;
    };
  };
  protection_stats?: Record<string, number>;
  severity_counts?: Record<string, number>;
  pipeline_running?: boolean;
  redis_connected?: boolean;
  db_connected?: boolean;
}

export async function fetchSecurityOverview(): Promise<SecurityOverview> {
  return safeFetch<SecurityOverview>('/api/v1/security/overview');
}

// ===== Organization Key Management =====

export interface OrgKeyItem {
  id: string;
  name: string;
  is_active: boolean;
  created_at: string;
}

export interface OrgSettings {
  tenant_id: string;
  name: string;
  domain: string;
  plan: string;
  device_count: number;
  user_count: number;
}

export async function generateOrgKey(name: string = 'default'): Promise<{ org_key: string; name: string; expires_at: string }> {
  return apiRequest('/api/v1/organizations/generate-key', {
    method: 'POST',
    body: { name },
  });
}

export async function listOrgKeys(): Promise<OrgKeyItem[]> {
  return safeFetch<OrgKeyItem[]>('/api/v1/organizations/keys');
}

export async function fetchOrgSettings(): Promise<OrgSettings> {
  return safeFetch<OrgSettings>('/api/v1/organizations/settings');
}

// ===== Rate Limits =====

export async function fetchRateLimitStats(): Promise<{
  stats: Array<{
    category: string;
    tenant_id: string;
    limit: number;
    current_count: number;
    blocked_count: number;
    remaining: number;
    utilization_pct: number;
    last_path: string;
    window_start: number;
  }>;
  tier: string;
  tier_limits: Record<string, number>;
  categories: Record<string, { label: string; limit: number; color: string }>;
}> {
  return apiRequest('/api/v1/dashboard/rate-limits');
}

// ===== Settings =====

interface BackendRule {
  id?: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
}

export async function fetchRules(): Promise<RuleConfig[]> {
  // Detection rules from backend
  const result = await apiRequest<{ rules: BackendRule[] }>('/api/v1/detect/rules');
  return (result.rules || []).map((r) => ({
    id: r.id || r.name || 'unknown',
    name: r.name || 'Unknown Rule',
    description: r.description || '',
    enabled: r.enabled !== false,
    severity: (r.severity as RuleConfig['severity']) || 'medium',
    category: r.category || 'General',
  }));
}

export async function updateRule(ruleId: string, enabled: boolean): Promise<RuleConfig> {
  return apiRequest(`/api/v1/detect/rules/${ruleId}`, {
    method: 'PATCH',
    body: { enabled },
  });
}

function deriveTopThreats(alerts: Alert[]): TopThreat[] {
  const countByType: Record<string, { count: number; severity: string }> = {};

  for (const a of alerts) {
    if (!countByType[a.type]) {
      countByType[a.type] = { count: 0, severity: a.severity };
    }
    countByType[a.type].count++;
  }

  return Object.entries(countByType)
    .map(([name, data]) => ({
      name,
      count: data.count,
      severity: data.severity as 'low' | 'medium' | 'high' | 'critical',
      trend: 'stable' as const,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}
