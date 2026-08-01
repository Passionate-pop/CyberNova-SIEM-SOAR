import { Bell, Search, User, Wifi, X, AlertTriangle, Info, CheckCircle, WifiOff } from 'lucide-react';
import { useState, useEffect, useRef, useCallback } from 'react';
import { isApiDown, onApiHealthChange, fetchNotifications, markNotificationRead, markAllNotificationsRead } from '../../services/api';
import { useWebSocket, type WebSocketMessage } from '../../hooks/useWebSocket';
import { useAuthStore } from '../../stores/useAuthStore';
import type { Page } from './Sidebar';
import type { NotificationItem } from '../../services/api';

interface TopNavbarProps {
  currentPage: Page;
  username: string;
  role?: string;
}

type LocalNotification = NotificationItem;

const pageTitles: Record<Page, string> = {
  dashboard: 'Dashboard Overview',
  alerts: 'Alert Management',
  incidents: 'Incident Response',
  monitoring: 'Live Monitoring',
  response: 'Response Center',
  'threat-intel': 'Threat Intelligence',
  'ai-investigation': 'AI Investigation',
  settings: 'System Settings',
  devices: 'Device Management',
  users: 'User Management',
  logs: 'System Logs',
  'audit-logs': 'Audit Logs',
  analytics: 'Analytics Dashboard',
  'add-device': 'Add Device',
  'rate-limits': 'Rate Limit Dashboard',
  mitre: 'MITRE ATT&CK Coverage',
};

const pageDescriptions: Record<Page, string> = {
  dashboard: 'Real-time security posture and threat landscape',
  alerts: 'View, filter, and investigate security alerts',
  incidents: 'Track and manage active security incidents',
  monitoring: 'Live system logs, network connections, and processes',
  response: 'Execute defensive actions and trigger automations',
  'threat-intel': 'Global threat intelligence and indicator feeds',
  'ai-investigation': 'AI-powered incident analysis and recommendations',
  settings: 'Configure platform settings and detection rules',
  devices: 'Monitor and manage all connected devices',
  users: 'Manage user accounts and permissions',
  logs: 'Browse system and application logs',
  'audit-logs': 'Review audit trail and compliance records',
  analytics: 'Analytics and performance insights',
  'add-device': 'Install and configure a new monitoring agent',
  'rate-limits': 'Monitor rate limit usage across all request categories',
  mitre: 'Detection coverage across the MITRE ATT&CK framework',
};

export function TopNavbar({ currentPage, username, role = 'viewer' }: TopNavbarProps) {
  const [apiDown, setApiDown] = useState(() => isApiDown());
  useEffect(() => {
    const unsub = onApiHealthChange(setApiDown);
    return unsub;
  }, []);
  const roleColors: Record<string, string> = {
    admin: 'bg-red-500/20 text-red-400',
    soc_manager: 'bg-purple-500/20 text-purple-400',
    analyst: 'bg-blue-500/20 text-blue-400',
    engineer: 'bg-amber-500/20 text-amber-400',
    viewer: 'bg-gray-500/20 text-gray-400',
  };
  
  const roleLabels: Record<string, string> = {
    admin: 'Admin',
    soc_manager: 'SOC Manager',
    analyst: 'Analyst',
    engineer: 'Engineer',
    viewer: 'Viewer',
  };


  // Auth store for WebSocket token
  const { token, user } = useAuthStore();

  const [notifications, setNotifications] = useState<LocalNotification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [hasUnread, setHasUnread] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // WebSocket hook for real-time notification updates
  useWebSocket({
    token: token || undefined,
    tenantId: user?.tenant_id,
    onMessage: useCallback((msg: WebSocketMessage) => {
      // Immediately refetch notifications when new alerts or system notifications arrive
      if (msg.type === 'new_alert' || msg.type === 'alert_updated' || msg.type === 'system_notification') {
        loadNotifications();
      }
    }, []),
  });

  const loadNotifications = async () => {
    try {
      const data = await fetchNotifications();
      setNotifications(data.notifications || []);
      setHasUnread(data.unread_count > 0);
    } catch {
      // Keep current state on error
    }
  };

  useEffect(() => {
    loadNotifications();
    // Poll every 10s as a fallback in case WebSocket is not connected
    const interval = setInterval(loadNotifications, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Close dropdown when clicking outside
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const markAsRead = async (id: string) => {
    try {
      await markNotificationRead(id);
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
      setHasUnread(notifications.some(n => !n.read));
    } catch {
      // Ignore
    }
  };

  const markAllAsRead = async () => {
    try {
      await markAllNotificationsRead();
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      setHasUnread(false);
    } catch {
      // Ignore
    }
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'alert':
        return <AlertTriangle size={14} className="text-red-400" />;
      case 'success':
        return <CheckCircle size={14} className="text-emerald-400" />;
      default:
        return <Info size={14} className="text-cyan-400" />;
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <>
      <header className="sticky top-0 z-30 border-b border-cyber-border bg-cyber-bg/80 backdrop-blur-xl">
        {apiDown && (
          <div className="bg-amber-500/90 text-center text-xs font-medium text-white py-1.5 px-4">
            ⚠️ Backend connection interrupted
          </div>
        )}
        <div className="flex h-16 items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <div>
          <h2 className="text-lg font-semibold text-cyber-text">{pageTitles[currentPage]}</h2>
          <p className="text-xs text-cyber-muted">{pageDescriptions[currentPage]}</p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="relative hidden md:block">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search alerts, incidents..."
            className="h-9 w-56 rounded-lg border border-cyber-border bg-cyber-surface pl-9 pr-3 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none focus:ring-1 focus:ring-cyber-accent/30"
          />
        </div>

        {/* Live indicator */}
        {apiDown ? (
          <div className="flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1">
            <WifiOff size={12} className="text-amber-400" />
            <span className="text-[10px] font-semibold text-amber-400 uppercase">Offline</span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1">
            <Wifi size={12} className="text-emerald-400" />
            <span className="text-[10px] font-semibold text-emerald-400 uppercase">Live</span>
          </div>
        )}

        {/* Notifications */}
        <div className="relative" ref={dropdownRef}>
          <button 
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative rounded-lg p-2 text-cyber-muted hover:bg-cyber-border/50 hover:text-cyber-text transition-colors"
          >
            <Bell size={18} />
            {hasUnread && (
              <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-red-500" />
            )}
          </button>

          {/* Notification Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 rounded-xl border border-cyber-border bg-cyber-card shadow-xl shadow-black/20 overflow-hidden animate-slide-in">
              {/* Header */}
              <div className="flex items-center justify-between border-b border-cyber-border px-4 py-3">
                <h3 className="text-sm font-semibold text-cyber-text">Notifications</h3>
                <div className="flex items-center gap-2">
                  {notifications.length > 0 && (
                    <>
                      <button 
                        onClick={markAllAsRead}
                        className="text-[10px] text-cyber-muted hover:text-cyber-accent"
                      >
                        Mark all read
                      </button>
                      <button 
                        onClick={() => { markAllAsRead(); loadNotifications(); }}
                        className="text-[10px] text-cyber-muted hover:text-red-400"
                      >
                        Clear
                      </button>
                    </>
                  )}
                  <button 
                    onClick={() => setShowNotifications(false)}
                    className="text-cyber-muted hover:text-cyber-text"
                  >
                    <X size={14} />
                  </button>
                </div>
              </div>

              {/* Notification List */}
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="py-8 text-center">
                    <Bell size={24} className="mx-auto mb-2 text-cyber-muted/50" />
                    <p className="text-xs text-cyber-muted">No notifications</p>
                  </div>
                ) : (
                  notifications.map((notification) => (
                    <div 
                      key={notification.id}
                      onClick={() => markAsRead(notification.id)}
                      className={`flex gap-3 px-4 py-3 border-b border-cyber-border/50 hover:bg-cyber-bg/50 cursor-pointer transition-colors ${
                        !notification.read ? 'bg-cyber-accent/5' : ''
                      }`}
                    >
                      <div className="mt-0.5">
                        {getNotificationIcon(notification.type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-medium text-cyber-text truncate">{notification.title}</p>
                          {!notification.read && (
                            <span className="h-2 w-2 rounded-full bg-cyber-accent shrink-0" />
                          )}
                        </div>
                        <p className="text-[11px] text-cyber-muted line-clamp-2 mt-0.5">{notification.message}</p>
                        <p className="text-[10px] text-cyber-muted/60 mt-1">{formatTime(notification.timestamp)}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User */}
        <div className="flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-surface px-3 py-1.5">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-accent/20">
            <User size={14} className="text-cyber-accent" />
          </div>
          <span className="text-xs font-medium text-cyber-text">{username}</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${roleColors[role] || roleColors.viewer}`}>
            {roleLabels[role] || role}
          </span>
        </div>
      </div>
      </div>
    </header>
    </>
  );
}
