import { useState, useCallback } from 'react';
import { Search, Filter, User, Shield, Monitor, AlertTriangle, Power, Clock } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { useFetch } from '../hooks/useFetch';
import { fetchAuditLogs } from '../services/api';
import { Pagination } from '../components/ui/Pagination';

const actionIcons: Record<string, React.ReactNode> = {
  login: <User size={14} className="text-blue-400" />,
  login_failed: <User size={14} className="text-red-400" />,
  logout: <User size={14} className="text-gray-400" />,
  role_change: <Shield size={14} className="text-purple-400" />,
  device_isolated: <Power size={14} className="text-red-400" />,
  device_unisolated: <Monitor size={14} className="text-emerald-400" />,
  device_registered: <Monitor size={14} className="text-cyan-400" />,
  alert_updated: <AlertTriangle size={14} className="text-amber-400" />,
  user_created: <User size={14} className="text-green-400" />,
  user_deleted: <User size={14} className="text-red-400" />,
};

const actionColors: Record<string, string> = {
  login: 'text-blue-400',
  login_failed: 'text-red-400',
  logout: 'text-gray-400',
  role_change: 'text-purple-400',
  device_isolated: 'text-red-400',
  device_unisolated: 'text-emerald-400',
  device_registered: 'text-cyan-400',
  alert_updated: 'text-amber-400',
  user_created: 'text-green-400',
  user_deleted: 'text-red-400',
};

function formatTarget(log: { resource_type?: string; resource_id?: string }): string {
  if (!log.resource_type) return '-';
  if (!log.resource_id) return log.resource_type;
  return `${log.resource_type}:${log.resource_id.slice(0, 8)}`;
}

function formatDetails(details?: Record<string, unknown>): string {
  if (!details) return '-';
  const entries = Object.entries(details).slice(0, 2);
  return entries.map(([k, v]) => `${k}: ${String(v)}`).join(', ') || '-';
}

export function AuditLogsPage() {
  const { data: logs, loading } = useFetch(useCallback(() => fetchAuditLogs(), []));
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 20;

  if (loading && !logs) {
    return (
      <div className="space-y-6">
        {/* KPI skeleton */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-cyber-border bg-cyber-card/50 p-4">
              <div className="animate-pulse h-3 w-12 bg-cyber-border/60 rounded mb-2" />
              <div className="animate-pulse h-8 w-20 bg-cyber-border/60 rounded" />
            </div>
          ))}
        </div>
        {/* Table skeleton */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card/80 overflow-hidden">
          <div className="flex items-center gap-3 border-b border-cyber-border px-5 py-3">
            <div className="animate-pulse h-8 w-56 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-8 w-28 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-3 w-16 bg-cyber-border/60 rounded" />
          </div>
          <div className="p-5 space-y-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex gap-4">
                <div className="animate-pulse h-4 w-28 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-16 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-24 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-32 bg-cyber-border/40 rounded" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  if (!logs) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-purple-500/10 flex items-center justify-center">
        <Search size={40} className="text-purple-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No Audit Logs Available</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        Audit trail logs will appear here once user actions are recorded. Ensure the backend is connected.
      </p>
    </div>
  );

  const filtered = logs
    .filter((log) => {
      if (actionFilter !== 'all' && log.action !== actionFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return (
          log.user_id.toLowerCase().includes(s) ||
          log.action.toLowerCase().includes(s) ||
          formatTarget(log).toLowerCase().includes(s) ||
          formatDetails(log.details).toLowerCase().includes(s)
        );
      }
      return true;
    });

  const totalPages = Math.ceil(filtered.length / itemsPerPage);
  const paginated = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const actionCounts = logs.reduce((acc, log) => {
    acc[log.action] = (acc[log.action] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {Object.entries(actionCounts).slice(0, 4).map(([action, count]) => (
          <div key={action} className="rounded-xl border bg-cyber-card/50 px-4 py-3 border-cyber-border">
            <p className="text-2xl font-bold text-cyber-text">{count}</p>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted capitalize">
              {action.replace('_', ' ')}
            </p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <Card noPadding>
        <div className="flex flex-wrap items-center gap-3 border-b border-cyber-border px-5 py-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search audit logs..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-cyber-muted" />
            <select
              value={actionFilter}
              onChange={(e) => { setActionFilter(e.target.value); setCurrentPage(1); }}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none appearance-none cursor-pointer"
            >
              <option value="all">All Actions</option>
              <option value="login">Login</option>
              <option value="login_failed">Login Failed</option>
              <option value="logout">Logout</option>
              <option value="device_isolated">Device Isolated</option>
              <option value="device_registered">Device Registered</option>
              <option value="user_created">User Created</option>
            </select>
          </div>
          <span className="text-xs text-cyber-muted">{filtered.length} logs</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left">
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Timestamp</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">User</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Action</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Target</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Details</th>
              </tr>
            </thead>
            <tbody>
              {paginated.length > 0 ? (
                paginated.map((log) => (
                  <tr key={log.id} className="border-b border-cyber-border/50 hover:bg-cyber-accent/5 transition-colors">
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-border">
                          <User size={12} className="text-cyber-muted" />
                        </div>
                        <span className="text-xs text-cyber-text font-mono">{log.user_id.slice(0, 8)}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`flex items-center gap-1 text-xs ${actionColors[log.action] || 'text-cyber-muted'}`}>
                        {actionIcons[log.action] || <Clock size={14} />}
                        <span className="capitalize">{log.action.replace('_', ' ')}</span>
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">{formatTarget(log)}</td>
                    <td className="px-5 py-3 text-xs text-cyber-muted max-w-xs truncate">{formatDetails(log.details)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-5 py-16 text-center">
                    <p className="text-sm text-cyber-muted">No audit logs found</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex justify-center border-t border-cyber-border p-4">
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={setCurrentPage}
          />
        </div>
      </Card>
    </div>
  );
}
