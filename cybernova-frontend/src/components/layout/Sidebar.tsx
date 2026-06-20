import {
  LayoutDashboard, AlertTriangle, FileSearch, Activity,
  Shield, Globe, Brain, Settings, LogOut, ChevronLeft, ChevronRight,
  Monitor, Users, ScrollText, BarChart3, Cpu, Crosshair
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { useAuth } from '../../hooks/useAuth';
import { hasPermission, PERMISSIONS, type Page } from '../../types';
import { getNavItemsForUser as getNavFromUtils } from '../../utils/permissions';

export type { Page };

interface SidebarProps {
  currentPage: Page;
  onNavigate: (page: Page) => void;
  onLogout: () => void;
  collapsed: boolean;
  onToggle: () => void;
}

const ICONS: Record<string, React.ReactNode> = {
  LayoutDashboard: <LayoutDashboard size={20} />,
  AlertTriangle: <AlertTriangle size={20} />,
  FileSearch: <FileSearch size={20} />,
  Activity: <Activity size={20} />,
  Shield: <Shield size={20} />,
  Globe: <Globe size={20} />,
  Brain: <Brain size={20} />,
  Settings: <Settings size={20} />,
  Monitor: <Monitor size={20} />,
  Users: <Users size={20} />,
  ScrollText: <ScrollText size={20} />,
  BarChart3: <BarChart3 size={20} />,
  Cpu: <Cpu size={20} />,
  Crosshair: <Crosshair size={20} />,
};

const adminNav: { id: Page; label: string; icon: string; permission?: string }[] = [
  { id: 'dashboard', label: 'Executive Dashboard', icon: 'LayoutDashboard' },
  { id: 'devices', label: 'Devices', icon: 'Monitor' },
  { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle', permission: PERMISSIONS.ALERTS_VIEW },
  { id: 'incidents', label: 'Incidents', icon: 'FileSearch', permission: PERMISSIONS.INCIDENTS_VIEW },
  { id: 'monitoring', label: 'Live Monitor', icon: 'Activity', permission: PERMISSIONS.PIPELINE_VIEW },
  { id: 'response', label: 'Response Center', icon: 'Shield' },
  { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
  { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: 'Crosshair' },
  { id: 'users', label: 'Users', icon: 'Users', permission: PERMISSIONS.USERS_VIEW },
  { id: 'analytics', label: 'Analytics', icon: 'BarChart3', permission: PERMISSIONS.AUDIT_VIEW },
  { id: 'logs', label: 'Event Logs', icon: 'ScrollText', permission: PERMISSIONS.PIPELINE_VIEW },
  { id: 'audit-logs', label: 'Audit Logs', icon: 'ScrollText', permission: PERMISSIONS.AUDIT_VIEW },
  { id: 'rate-limits', label: 'Rate Limits', icon: 'Activity', permission: PERMISSIONS.PIPELINE_VIEW },
  { id: 'settings', label: 'Settings', icon: 'Settings', permission: PERMISSIONS.SETTINGS_VIEW },
];

const staffNav: { id: Page; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' },
  { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle' },
  { id: 'incidents', label: 'Incidents', icon: 'FileSearch' },
  { id: 'monitoring', label: 'Live Monitor', icon: 'Activity' },
  { id: 'logs', label: 'Event Logs', icon: 'ScrollText' },
  { id: 'response', label: 'Response Center', icon: 'Shield' },
  { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
  { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: 'Crosshair' },
  { id: 'analytics', label: 'Analytics', icon: 'BarChart3' },
  { id: 'settings', label: 'Settings', icon: 'Settings' },
];

const individualNav: { id: Page; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' },
  { id: 'incidents', label: 'Incidents', icon: 'FileSearch' },
  { id: 'alerts', label: 'Alerts', icon: 'AlertTriangle' },
  { id: 'monitoring', label: 'Live Monitor', icon: 'Activity' },
  { id: 'logs', label: 'Event Logs', icon: 'ScrollText' },
  { id: 'response', label: 'Response Center', icon: 'Shield' },
  { id: 'threat-intel', label: 'Threat Intel', icon: 'Globe' },
  { id: 'ai-investigation', label: 'AI Investigation', icon: 'Brain' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: 'Crosshair' },
  { id: 'analytics', label: 'Analytics', icon: 'BarChart3' },
  { id: 'settings', label: 'Settings', icon: 'Settings' },
];

function resolveNavItems(user: any): { id: Page; label: string; icon: string; permission?: string }[] {
  const navConfig = getNavFromUtils(user);
  const allItems = [...adminNav, ...staffNav, ...individualNav];
  return navConfig
    .map(item => allItems.find(a => a.id === item.id))
    .filter((item): item is NonNullable<typeof item> => item !== undefined);
}

function getHeaderInfo(user: any): { title: string; subtitle: string; accentColor: string } {
  const purpose = localStorage.getItem('cybernova_purpose') || 'individual';
  // Prefer user object's org_name (from JWT), fallback to localStorage
  const orgName = user?.org_name || localStorage.getItem('cybernova_org_name');
  
  if (purpose === 'organization') {
    if (user?.role === 'admin') {
      return {
        title: orgName || 'CyberNova',
        subtitle: 'Control Center',
        accentColor: 'from-purple-500 to-purple-600',
      };
    }
    return {
      title: orgName || 'Organization',
      subtitle: 'Staff Portal',
      accentColor: 'from-cyan-500 to-cyan-600',
    };
  }
  return {
    title: 'CyberNova',
    subtitle: 'Personal Protection',
    accentColor: 'from-cyan-500 to-purple-600',
  };
}

export function Sidebar({ currentPage, onNavigate, onLogout, collapsed, onToggle }: SidebarProps) {
  const { user } = useAuth();
  
  const navItems = resolveNavItems(user);
  const filteredNavItems = navItems.filter(item => {
    if (!item.permission) return true;
    return hasPermission(user, item.permission);
  });
  
  const { title: headerTitle, subtitle: headerSubtitle } = getHeaderInfo(user);

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 flex h-screen flex-col border-r border-cyber-border bg-cyber-sidebar transition-all duration-300',
        collapsed ? 'w-[68px]' : 'w-60'
      )}
    >
      {/* Logo Header */}
      <div className="flex h-16 items-center border-b border-cyber-border px-4">          <div className="flex items-center gap-2.5">
          <div className="relative h-9 w-9 shrink-0 overflow-hidden rounded-full border border-cyan-500/40">
            <img src="/logo.png" alt="CyberNova Logo" width={36} height={36} className="h-full w-full object-cover" />
          </div>
          {!collapsed && (
            <div>
              <h1 className="text-base font-bold text-cyber-text tracking-tight">{headerTitle}</h1>
              <p className="text-[10px] font-medium text-cyber-accent uppercase tracking-widest">
                {headerSubtitle}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        <div className="space-y-1">
          {filteredNavItems.map((item) => (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={cn(
                'group relative flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200',
                currentPage === item.id
                  ? 'bg-cyber-accent/10 text-cyber-accent'
                  : 'text-cyber-muted hover:bg-cyber-border/50 hover:text-cyber-text'
              )}
            >
              {currentPage === item.id && (
                <div className="absolute left-0 top-1/2 h-6 w-0.5 -translate-y-1/2 rounded-r-full bg-cyber-accent" />
              )}
              <span className="shrink-0">{ICONS[item.icon] || <LayoutDashboard size={20} />}</span>
              {!collapsed && (
                <span className="flex-1 text-left">{item.label}</span>
              )}
            </button>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-cyber-border p-3 space-y-1">
        <button
          onClick={onLogout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-cyber-muted hover:bg-red-500/10 hover:text-red-400 transition-colors"
        >
          <LogOut size={20} />
          {!collapsed && <span>Logout</span>}
        </button>
        <button
          onClick={onToggle}
          className="flex w-full items-center justify-center rounded-lg p-2 text-cyber-muted hover:bg-cyber-border/50 hover:text-cyber-text transition-colors"
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>
    </aside>
  );
}