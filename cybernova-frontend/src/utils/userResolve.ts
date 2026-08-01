/**
 * CyberNova — User Resolution Helpers
 *
 * Both App.tsx and Dashboard.tsx need to determine a user's `purpose`
 * and `role` even when the Zustand auth store loses fields during
 * rehydration. These helpers try multiple fallback sources so the
 * UI always renders correctly.
 */

/**
 * Read the raw JWT payload from localStorage without importing
 * the full auth service (avoids circular deps).
 */
function readJwtFromStorage(): Record<string, unknown> | null {
  try {
    const stored = localStorage.getItem('cybernova-auth');
    if (!stored) return null;
    const parsed = JSON.parse(stored);
    const token = parsed.state?.token;
    if (!token) return null;
    const base64 = token.split('.')[1];
    const json = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Resolve user purpose from every available source.
 * Priority: user object → localStorage → JWT → default.
 */
export function resolveUserPurpose(user: any): string {
  // 1. From the user object in the auth store
  if (user?.purpose) return user.purpose;
  // 2. From localStorage (set during onboarding)
  const stored = localStorage.getItem('cybernova_purpose');
  if (stored) return stored;
  // 3. From the JWT token payload directly (most reliable)
  const jwt = readJwtFromStorage();
  if (jwt?.purpose) return jwt.purpose as string;
  // 4. From the last user blob stored during registration
  try {
    const lastUser = JSON.parse(localStorage.getItem('cybernova_last_user') || '{}');
    if (lastUser.purpose) return lastUser.purpose;
  } catch {}
  return 'individual';
}

/**
 * Resolve user role from every available source.
 * Priority: user object → localStorage org_type → JWT → default.
 */
export function resolveUserRole(user: any): string {
  // 1. From the user object in the auth store
  if (user?.role) return user.role;
  if (user?.roles?.[0]) return user.roles[0];
  // 2. From localStorage org_type (set during login for org users)
  if (localStorage.getItem('cybernova_org_type') === 'boss') return 'admin';
  // 3. From the JWT token payload directly
  const jwt = readJwtFromStorage();
  if (jwt && Array.isArray(jwt.roles) && (jwt.roles as string[]).length > 0) {
    return (jwt.roles as string[])[0];
  }
  return 'viewer';
}

/**
 * Resolve user org_type from every available source.
 * Priority: user object → localStorage → JWT → default.
 */
export function resolveOrgType(user: any): string {
  if (user?.org_type) return user.org_type;
  const stored = localStorage.getItem('cybernova_org_type');
  if (stored) return stored;
  const jwt = readJwtFromStorage();
  if (jwt?.org_type) return jwt.org_type as string;
  return '';
}
