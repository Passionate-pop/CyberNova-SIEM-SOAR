import { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { useAuthStore } from './stores/useAuthStore';
import { useUIStore } from './stores/useUIStore';
import { Sidebar, type Page } from './components/layout/Sidebar';
import { TopNavbar } from './components/layout/TopNavbar';
import { ErrorBoundary } from './components/ui/ErrorBoundary';
import { getAllowedPageIds } from './utils/permissions';

const LoginPage = lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })));
const OnboardingPage = lazy(() => import('./pages/OnboardingPage').then(m => ({ default: m.OnboardingPage })));
const UnifiedDashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const DevicesPage = lazy(() => import('./pages/DevicesPage').then(m => ({ default: m.DevicesPage })));
const UsersPage = lazy(() => import('./pages/UsersPage').then(m => ({ default: m.UsersPage })));
const AlertsPage = lazy(() => import('./pages/AlertsPage').then(m => ({ default: m.AlertsPage })));
const IncidentsPage = lazy(() => import('./pages/IncidentsPage').then(m => ({ default: m.IncidentsPage })));
const MonitoringPage = lazy(() => import('./pages/MonitoringPage').then(m => ({ default: m.MonitoringPage })));
const LogsPage = lazy(() => import('./pages/LogsPage').then(m => ({ default: m.LogsPage })));
const ResponsePage = lazy(() => import('./pages/ResponsePage').then(m => ({ default: m.ResponsePage })));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage').then(m => ({ default: m.ThreatIntelPage })));
const AIInvestigationPage = lazy(() => import('./pages/AIInvestigationPage').then(m => ({ default: m.AIInvestigationPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const AuditLogsPage = lazy(() => import('./pages/AuditLogsPage').then(m => ({ default: m.AuditLogsPage })));
const AnalyticsDashboard = lazy(() => import('./pages/AnalyticsDashboard').then(m => ({ default: m.AnalyticsDashboardWithInsights })));
const SetupPage = lazy(() => import('./pages/SetupPage').then(m => ({ default: m.SetupPage })));
const AddDevicePage = lazy(() => import('./pages/AddDevicePage').then(m => ({ default: m.AddDevicePage })));
const RateLimitDashboard = lazy(() => import('./pages/RateLimitDashboard').then(m => ({ default: m.RateLimitDashboard })));
const MitrePage = lazy(() => import('./pages/MitrePage').then(m => ({ default: m.MitrePage })));
import { isApiDown, onApiHealthChange, onAuthCleared, reconstructUserFromToken } from './services/api';

const pageComponents: Record<Page, React.ComponentType> = {
  dashboard: UnifiedDashboard,
  devices: DevicesPage,
  users: UsersPage,
  alerts: AlertsPage,
  incidents: IncidentsPage,
  monitoring: MonitoringPage,
  logs: LogsPage,
  response: ResponsePage,
  'threat-intel': ThreatIntelPage,
  'ai-investigation': AIInvestigationPage,
  settings: SettingsPage,
  'audit-logs': AuditLogsPage,
  analytics: AnalyticsDashboard,
  'add-device': AddDevicePage,
  'rate-limits': RateLimitDashboard,
  'mitre': MitrePage,
};

export default function App() {
  const { user, isAuthenticated, isLoading, setUser } = useAuthStore();
  const { sidebarCollapsed, toggleSidebar } = useUIStore();

  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [apiDown, setApiDown] = useState(isApiDown());
  const [needsSetup, setNeedsSetup] = useState(false);
  const [onboardingDone, setOnboardingDone] = useState(false);

  const purpose = localStorage.getItem('cybernova_purpose');
  const onboardingComplete = onboardingDone ? 'true' : localStorage.getItem('cybernova_onboarding_complete');

  // ── ALL hooks must be declared BEFORE any conditional returns ──

  // API health listener
  useEffect(() => {
    const unsub = onApiHealthChange(setApiDown);
    return unsub;
  }, []);

  // Listen for session expiry (401) — reset in-memory auth state without page reload
  useEffect(() => {
    const unsub = onAuthCleared(() => {
      useAuthStore.setState({
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
      });
    });
    return unsub;
  }, []);

  // On page load: initialize auth from token existence (no /auth/me call)
  const initialized = useRef(false);
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    const { token, user: storedUser } = useAuthStore.getState();

    if (token && !storedUser) {
      const reconstructed = reconstructUserFromToken(token);
      if (reconstructed) {
        useAuthStore.setState({
          user: reconstructed,
          isAuthenticated: true,
          isLoading: false,
        });
        return;
      }
    }

    useAuthStore.setState({ isLoading: false });
  }, []);

  // Check if setup is needed on first load
  useEffect(() => {
    if (!isAuthenticated || !user) {
      fetch('/api/v1/setup/status')
        .then(r => r.json())
        .then(d => { if (d.needs_setup) setNeedsSetup(true); })
        .catch(() => {});
    }
  }, []);

  // Restore purpose for returning users who completed onboarding but lost localStorage
  useEffect(() => {
    if (!purpose && onboardingComplete && user) {
      localStorage.setItem('cybernova_purpose', user.purpose || 'individual');
    }
  }, [purpose, onboardingComplete, user]);

  // ── Conditional rendering (after all hooks) ──

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-cyber-muted">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-full overflow-hidden border border-cyan-500/40">
            <img src="/logo.svg" alt="CyberNova Logo" width={48} height={48} className="h-full w-full object-cover" />
          </div>
          <span>Loading CyberNova...</span>
        </div>
      </div>
    );
  }

  if (needsSetup) {
    return (
      <Suspense fallback={
        <div className="flex min-h-screen items-center justify-center text-cyber-muted">
          <div className="flex flex-col items-center gap-3">
            <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          </div>
        </div>
      }>
        <SetupPage onSetupComplete={(user) => { setNeedsSetup(false); setUser(user); }} />
      </Suspense>
    );
  }

  if (!isAuthenticated || !user) {
    return (
      <Suspense fallback={
        <div className="flex min-h-screen items-center justify-center text-cyber-muted">
          <div className="flex flex-col items-center gap-3">
            <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          </div>
        </div>
      }>
        <LoginPage onLogin={setUser} />
      </Suspense>
    );
  }

  // First-time users: never completed onboarding → show OnboardingPage
  if (!onboardingComplete) {
    return (
      <Suspense fallback={
        <div className="flex min-h-screen items-center justify-center text-cyber-muted">
          <div className="flex flex-col items-center gap-3">
            <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          </div>
        </div>
      }>
        <OnboardingPage
          onComplete={() => {
            const currentUser = useAuthStore.getState().user;
            localStorage.setItem('cybernova_purpose', currentUser?.purpose || 'individual');
            localStorage.setItem('cybernova_onboarding_complete', 'true');
            setOnboardingDone(true);
          }}
        />
      </Suspense>
    );
  }

  // Silently redirect to dashboard if currentPage isn't allowed for this role.
  // The sidebar already only shows permitted pages, so this is just a safety net
  // for edge cases like URL manipulation.
  const resolvedPurpose = resolveUserPurpose(user);
  const resolvedRole = resolveUserRole(user);
  const allowedPages = getAllowedPages(resolvedPurpose, resolvedRole);
  const safePage = allowedPages.includes(currentPage) ? currentPage : 'dashboard';
  const CurrentPageComponent = pageComponents[safePage];

  return (
    <div className="min-h-screen bg-cyber-bg">
      {apiDown && (
        <div className="fixed top-0 left-0 right-0 z-50 bg-amber-500/20 border-b border-amber-500/30 px-4 py-2 text-center">
          <p className="text-xs text-amber-400">
            ⚠ Backend connection interrupted. Reconnecting...
          </p>
        </div>
      )}

      <Sidebar
        currentPage={safePage}
        onNavigate={setCurrentPage}
        onLogout={() => {
          localStorage.removeItem('cybernova_device_added');
          localStorage.removeItem('cybernova_purpose');
          localStorage.removeItem('cybernova_onboarding_complete');
          localStorage.removeItem('cybernova_org_key');
          localStorage.removeItem('cybernova_org_type');
          localStorage.removeItem('cybernova_org_name');
          useAuthStore.getState().logout();
          window.location.href = '/';
        }}
        collapsed={sidebarCollapsed}
        onToggle={toggleSidebar}
      />

      <div
        className="transition-all duration-200"
        style={{ marginLeft: sidebarCollapsed ? 68 : 240 }}
      >
        <TopNavbar
          currentPage={safePage}
          username={user.username || 'User'}
          role={user.role || 'viewer'}
        />

        <main className="p-6">
          <ErrorBoundary key={safePage}>
            <div className="animate-page-enter">
              <Suspense fallback={
                <div className="flex items-center justify-center h-[40vh]">
                  <div className="flex flex-col items-center gap-3">
                    <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    <span className="text-sm text-cyber-muted">Loading page...</span>
                  </div>
                </div>
              }>
                <CurrentPageComponent />
              </Suspense>
            </div>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

/**
 * Read the JWT token payload directly from the persisted auth store.
 * This is the most reliable source of user claims — it bypasses any
 * corruption in the user object.
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
 * Try to determine user's purpose from EVERY available source.
 * The user object from the auth store may lose its `purpose` field
 * due to JWT refresh stripping claims, corrupted persist storage, etc.
 */
function resolveUserPurpose(user: any): string {
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

function resolveUserRole(user: any): string {
  // 1. From the user object in the auth store
  if (user?.role) return user.role;
  if (user?.roles?.[0]) return user.roles[0];
  // 2. From localStorage org_type (set during login for org users)
  if (localStorage.getItem('cybernova_org_type') === 'boss') return 'admin';
  // 3. From the JWT token payload directly
  const jwt = readJwtFromStorage();
  if (jwt && Array.isArray(jwt.roles) && (jwt.roles as string[]).length > 0) return (jwt.roles as string[])[0];
  return 'viewer';
}

function getAllowedPages(purpose: string, role: string): Page[] {
  // Build a minimal user-like object to pass to the centralized function
  const user = { purpose, role } as any;
  return getAllowedPageIds(user) as Page[];
}
