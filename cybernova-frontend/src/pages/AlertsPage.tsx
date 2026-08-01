import { useState, useCallback, useEffect } from 'react';
import { Search, Filter, ChevronDown, ExternalLink, CheckCircle, BellOff, Shield, Check, Ban, MonitorOff, AlertTriangle } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Modal } from '../components/ui/Modal';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { useFetch } from '../hooks/useFetch';
import { useWebSocket } from '../hooks/useWebSocket';
import { useAuthStore } from '../stores/useAuthStore';
import { fetchAlerts, snoozeAlert, whitelistEntity, markAlertSafe, blockIP, isolateDevice, fetchDevices } from '../services/api';
import type { Alert, Severity, AlertStatus } from '../types';

export function AlertsPage() {
  const { token, user } = useAuthStore();
  const { data: alerts, loading, refetch } = useFetch(useCallback(() => fetchAlerts(), []));

  // Real-time WebSocket integration
  useWebSocket({
    token: token || undefined,
    tenantId: user?.tenant_id,
    onMessage: (msg) => {
      if (msg.type === 'new_alert' || msg.type === 'alert_updated') {
        refetch();
      }
    },
  });

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>('all');
  const [sortField, setSortField] = useState<'timestamp' | 'severity'>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ type: string; alert: Alert } | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  if (loading && !alerts) {
    return (
    <div className="space-y-6">
      {/* KPI skeleton */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-cyber-border bg-cyber-card/50 p-4">
              <div className="animate-pulse h-3 w-12 bg-cyber-border/60 rounded mb-2" />
              <div className="animate-pulse h-8 w-16 bg-cyber-border/60 rounded" />
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
                <div className="animate-pulse h-4 w-24 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-16 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-28 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-14 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-24 bg-cyber-border/40 rounded" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  if (!alerts) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-red-500/10 flex items-center justify-center">
        <AlertTriangle size={40} className="text-red-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No Alert Data Available</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        Alerts will appear here once the detection pipeline is active and the backend is connected.
      </p>
      <button onClick={() => refetch()} className="rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-white hover:bg-cyber-accent/90 transition-colors">
        Retry Connection
      </button>
    </div>
  );

  const severityOrder: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

  const filtered = alerts
    .filter((a) => a.type !== 'agent_heartbeat')
    .filter((a) => {
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && a.status !== statusFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return (
          a.alert_id.toLowerCase().includes(s) ||
          a.type.toLowerCase().includes(s) ||
          a.source_ip.includes(s) ||
          a.description.toLowerCase().includes(s) ||
          a.affected_system.toLowerCase().includes(s)
        );
      }
      return true;
    })
    .sort((a, b) => {
      if (sortField === 'timestamp') {
        const diff = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        return sortDir === 'desc' ? -diff : diff;
      }
      const diff = severityOrder[a.severity] - severityOrder[b.severity];
      return sortDir === 'desc' ? -diff : diff;
    });

  const toggleSort = (field: 'timestamp' | 'severity') => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  return (
    <div className="space-y-6">
      {toast && (
        <div className={`fixed top-4 right-4 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 shadow-xl text-sm animate-slide-in ${
          toast.type === 'success' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-red-500/30 bg-red-500/10 text-red-400'
        }`}>
          {toast.type === 'success' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
          {toast.message}
        </div>
      )}
      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
          const count = filtered.filter(a => a.severity === sev).length;
          const colors: Record<Severity, string> = {
            critical: 'border-red-500/30 text-red-400',
            high: 'border-orange-500/30 text-orange-400',
            medium: 'border-amber-500/30 text-amber-400',
            low: 'border-blue-500/30 text-blue-400',
          };
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
              className={`rounded-xl border bg-cyber-card/50 px-4 py-3 text-left transition-all ${
                severityFilter === sev ? colors[sev] + ' ring-1 ring-current/30' : 'border-cyber-border'
              }`}
            >
              <p className="text-2xl font-bold text-cyber-text">{count}</p>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">{sev}</p>
            </button>
          );
        })}
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
              placeholder="Search alerts by ID, type, IP, system..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-cyber-muted" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as AlertStatus | 'all')}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none appearance-none cursor-pointer"
            >
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="closed">Closed</option>
            </select>
          </div>
          <span className="text-xs text-cyber-muted">{filtered.length} alerts</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left">
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Alert ID</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Type</th>
                <th
                  className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted cursor-pointer hover:text-cyber-text"
                  onClick={() => toggleSort('severity')}
                >
                  <span className="flex items-center gap-1">
                    Severity
                    {sortField === 'severity' && <ChevronDown size={12} className={sortDir === 'asc' ? 'rotate-180' : ''} />}
                  </span>
                </th>
                <th
                  className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted cursor-pointer hover:text-cyber-text"
                  onClick={() => toggleSort('timestamp')}
                >
                  <span className="flex items-center gap-1">
                    Timestamp
                    {sortField === 'timestamp' && <ChevronDown size={12} className={sortDir === 'asc' ? 'rotate-180' : ''} />}
                  </span>
                </th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Status</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Source</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">System</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length > 0 ? (
                filtered.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    className="border-b border-cyber-border/50 hover:bg-cyber-accent/5 transition-colors cursor-pointer"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="px-5 py-3">
                      <span className="font-mono text-xs text-cyber-accent">{alert.alert_id}</span>
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-text">{alert.type}</td>
                    <td className="px-5 py-3"><SeverityBadge severity={alert.severity} /></td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-5 py-3"><StatusBadge status={alert.status} /></td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">{alert.source_ip}</td>
                    <td className="px-5 py-3 text-xs text-cyber-text">{alert.affected_system}</td>
                    <td className="px-5 py-3">
                      <ExternalLink size={14} className="text-cyber-muted hover:text-cyber-accent" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="px-5 py-16 text-center">
                    <div className="flex flex-col items-center gap-4">
                      <div className="flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10">
                        <CheckCircle size={32} className="text-emerald-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-cyber-text">No alerts found</p>
                        <p className="text-xs text-cyber-muted mt-1">Your system is monitoring for threats. Verified alerts will appear here.</p>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Alert Detail Modal */}
      <Modal
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={`Alert: ${selectedAlert?.alert_id || ''}`}
        size="lg"
      >
        {selectedAlert && (
          <div className="space-y-6">
            <div className="flex items-center gap-3 flex-wrap">
              <SeverityBadge severity={selectedAlert.severity} size="md" />
              <StatusBadge status={selectedAlert.status} />
              <span className="rounded-full bg-cyber-border px-2.5 py-0.5 text-xs text-cyber-muted">{selectedAlert.type}</span>
            </div>

            <p className="text-sm text-cyber-text leading-relaxed">{selectedAlert.description}</p>

            <div className="grid grid-cols-2 gap-4">
              {[
                { label: 'Source IP', value: selectedAlert.source_ip },
                { label: 'Destination IP', value: selectedAlert.destination_ip },
                { label: 'Affected System', value: selectedAlert.affected_system },
                { label: 'Rule ID', value: selectedAlert.rule_id },
                { label: 'Timestamp', value: new Date(selectedAlert.timestamp).toLocaleString() },
                { label: 'Status', value: selectedAlert.status },
              ].map((field) => (
                <div key={field.label} className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">{field.label}</p>
                  <p className="mt-1 text-sm font-mono text-cyber-text">{field.value}</p>
                </div>
              ))}
            </div>

            {/* Noise Control Actions */}
            <div className="flex flex-wrap gap-3 pt-4 border-t border-cyber-border">
              <button
                onClick={() => setConfirmAction({ type: 'snooze', alert: selectedAlert })}
                disabled={actionLoading === 'snooze'}
                className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
              >
                <BellOff size={14} /> Snooze 24h
              </button>
              <button
                onClick={() => setConfirmAction({ type: 'whitelist', alert: selectedAlert })}
                disabled={actionLoading === 'whitelist'}
                className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
              >
                <Shield size={14} /> Whitelist IP
              </button>
              <button
                onClick={() => setConfirmAction({ type: 'safe', alert: selectedAlert })}
                disabled={actionLoading === 'safe'}
                className="flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs text-blue-400 hover:bg-blue-500/20 transition-colors disabled:opacity-50"
              >
                <Check size={14} /> Mark Safe
              </button>
            </div>

            {/* SOAR Actions — Only for HIGH/CRITICAL */}
            {(selectedAlert.severity === 'high' || selectedAlert.severity === 'critical') && (
              <div className="flex flex-wrap gap-3 pt-4 border-t border-red-500/20">
                <p className="w-full text-[10px] font-semibold uppercase tracking-wider text-red-400">SOAR Response Actions</p>
                <button
                  onClick={() => setConfirmAction({ type: 'block-ip', alert: selectedAlert })}
                  disabled={actionLoading === 'block-ip'}
                  className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                >
                  <Ban size={14} /> Block IP
                </button>
                <button
                  onClick={() => setConfirmAction({ type: 'isolate', alert: selectedAlert })}
                  disabled={actionLoading === 'isolate'}
                  className="flex items-center gap-2 rounded-lg border border-orange-500/30 bg-orange-500/10 px-4 py-2 text-xs text-orange-400 hover:bg-orange-500/20 transition-colors disabled:opacity-50"
                >
                  <MonitorOff size={14} /> Isolate Device
                </button>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Confirm Dialog */}
      <ConfirmDialog
        isOpen={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        onConfirm={async () => {
          if (!confirmAction) return;
          setActionLoading(confirmAction.type);
          try {
            if (confirmAction.type === 'snooze') {
              await snoozeAlert(confirmAction.alert.alert_id);
              setToast({ message: 'Alert snoozed for 24h', type: 'success' });
            } else if (confirmAction.type === 'whitelist') {
              await whitelistEntity(confirmAction.alert.source_ip, 'ip', `From alert ${confirmAction.alert.alert_id}`);
              setToast({ message: `IP ${confirmAction.alert.source_ip} whitelisted`, type: 'success' });
            } else if (confirmAction.type === 'safe') {
              await markAlertSafe(confirmAction.alert.alert_id);
              setToast({ message: 'Alert marked as safe', type: 'success' });
            } else if (confirmAction.type === 'block-ip') {
              await blockIP(confirmAction.alert.source_ip, `SOAR block from alert ${confirmAction.alert.alert_id}`);
              try { await markAlertSafe(confirmAction.alert.alert_id); } catch { /* non-critical - IP is already blocked */ }
              setToast({ message: `IP ${confirmAction.alert.source_ip} blocked and alert resolved`, type: 'success' });
            } else if (confirmAction.type === 'isolate') {
              const devices = await fetchDevices();
              const device = devices.find((d) => d.ip_address === confirmAction.alert.source_ip);
              if (device) {
                await isolateDevice(device.id as string);
                setToast({ message: `Device ${device.hostname} isolated successfully`, type: 'success' });
              } else {
                setToast({ message: `No device found with IP ${confirmAction.alert.source_ip} to isolate`, type: 'error' });
              }
            }
            setConfirmAction(null);
            setSelectedAlert(null);
            refetch();
          } catch (e) {
            setToast({ message: `Action failed: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
          } finally {
            setActionLoading(null);
          }
        }}
        title={
          confirmAction?.type === 'snooze' ? 'Snooze Alert' :
          confirmAction?.type === 'whitelist' ? 'Whitelist IP' :
          confirmAction?.type === 'safe' ? 'Mark Alert Safe' :
          confirmAction?.type === 'block-ip' ? 'Block IP Address' :
          confirmAction?.type === 'isolate' ? 'Isolate Device' :
          'Confirm Action'
        }
        message={
          confirmAction?.type === 'snooze' ? 'This alert will be suppressed for 24 hours.' :
          confirmAction?.type === 'whitelist' ? `Permanently whitelist IP ${confirmAction?.alert.source_ip}?` :
          confirmAction?.type === 'safe' ? 'Mark this alert as a false positive?' :
          confirmAction?.type === 'block-ip' ? `Block IP ${confirmAction?.alert.source_ip} across all systems?` :
          confirmAction?.type === 'isolate' ? `Isolate device with IP ${confirmAction?.alert.source_ip} from the network?` :
          'Are you sure?'
        }
        confirmLabel="Confirm"
      />
    </div>
  );
}
