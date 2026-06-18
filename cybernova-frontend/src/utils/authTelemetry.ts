type AuthEvent =
  | { type: 'invalid_role'; value: unknown }
  | { type: 'invalid_roles_array'; value: unknown }
  | { type: 'fallback_role_used'; role: string }
  | { type: 'permission_check'; permission: string; allowed: boolean }
  | { type: 'login_failed'; reason: string }
  | { type: 'session_expired'; path: string }
  | { type: 'api_error'; endpoint: string; status: number; message: string }
  | { type: 'auth_storage_corrupt'; error: string };

type AuthMetrics = {
  invalidRole: number;
  invalidRolesArray: number;
  fallbackUsed: number;
  permissionChecks: number;
  loginFailed: number;
  sessionExpired: number;
  apiError: number;
  storageCorrupt: number;
};

const metrics: AuthMetrics = {
  invalidRole: 0,
  invalidRolesArray: 0,
  fallbackUsed: 0,
  permissionChecks: 0,
  loginFailed: 0,
  sessionExpired: 0,
  apiError: 0,
  storageCorrupt: 0,
};

export function logAuthEvent(event: AuthEvent) {
  if (import.meta.env.DEV) {
    console.debug('[AUTH]', event);
  }

  switch (event.type) {
    case 'invalid_role':
      metrics.invalidRole++;
      break;
    case 'invalid_roles_array':
      metrics.invalidRolesArray++;
      break;
    case 'fallback_role_used':
      metrics.fallbackUsed++;
      break;
    case 'permission_check':
      metrics.permissionChecks++;
      break;
    case 'login_failed':
      metrics.loginFailed++;
      console.error('[AUTH] Login failed:', event.reason);
      break;
    case 'session_expired':
      metrics.sessionExpired++;
      console.warn('[AUTH] Session expired while on:', event.path);
      break;
    case 'api_error':
      metrics.apiError++;
      console.error('[AUTH] API error:', event.endpoint, event.status, event.message);
      break;
    case 'auth_storage_corrupt':
      metrics.storageCorrupt++;
      console.error('[AUTH] Auth storage corrupt:', event.error);
      break;
  }
}

export function getAuthMetrics() {
  return { ...metrics };
}
