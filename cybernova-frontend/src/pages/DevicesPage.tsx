import { useState, useCallback, useEffect } from 'react';
import { Search, ChevronDown, ExternalLink, Monitor, AlertTriangle, CheckCircle, XCircle, MonitorOff } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { useFetch } from '../hooks/useFetch';
import { fetchDevices, isolateDevice } from '../services/api';
import { useAuthStore } from '../stores/useAuthStore';
import type { Device, DeviceStatus } from '../types';

const statusColors: Record<DeviceStatus, string> = {
  active: 'text-emerald-400',
  offline: 'text-red-400',
  isolated: 'text-amber-400',
  error: 'text-red-400',
};

const statusBg: Record<DeviceStatus, string> = {
  active: 'bg-emerald-500/10 border-emerald-500/30',
  offline: 'bg-red-500/10 border-red-500/30',
  isolated: 'bg-amber-500/10 border-amber-500/30',
  error: 'bg-red-500/10 border-red-500/30',
};

export function DevicesPage() {
  const currentUser = useAuthStore(s => s.user);
  const { data: devices, loading, refetch } = useFetch(useCallback(() => fetchDevices(), []));
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<DeviceStatus | 'all'>('all');
  const [sortField, setSortField] = useState<'hostname' | 'last_heartbeat' | 'status'>('last_heartbeat');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ type: string; device: Device } | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handleAction = async () => {
    if (!confirmAction) return;
    setActionLoading(confirmAction.type);
    try {
      if (confirmAction.type === 'isolate') {
        await isolateDevice(confirmAction.device.id);
        setToast({ message: `Device ${confirmAction.device.hostname} isolated successfully`, type: 'success' });
      }
      setConfirmAction(null);
      setSelectedDevice(null);
      refetch();
    } catch (e) {
      setToast({ message: `Action failed: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
    } finally {
      setActionLoading(null);
    }
  };

  if (loading && !devices) {
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
                <div className="animate-pulse h-4 w-32 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-18 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-28 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-24 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-20 bg-cyber-border/40 rounded" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  if (!devices) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-cyan-500/10 flex items-center justify-center">
        <Monitor size={40} className="text-cyan-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No Devices Registered</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        Install the CyberNova agent on your devices to register and monitor them. The backend connection may be unavailable.
      </p>
      <button onClick={() => refetch()} className="rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-white hover:bg-cyber-accent/90 transition-colors">
        Retry Connection
      </button>
    </div>
  );

  const statusOrder: Record<DeviceStatus, number> = { active: 0, error: 1, isolated: 2, offline: 3 };

  const filtered = devices
    .filter((d) => {
      if (statusFilter !== 'all' && d.status !== statusFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return (
          d.hostname.toLowerCase().includes(s) ||
          d.ip_address.toLowerCase().includes(s) ||
          d.owner_id?.toLowerCase().includes(s)
        );
      }
      return true;
    })
    .sort((a, b) => {
      let diff: number;
      if (sortField === 'hostname') {
        diff = a.hostname.localeCompare(b.hostname);
      } else if (sortField === 'status') {
        diff = (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99);
      } else {
        diff = (a.last_heartbeat ? new Date(a.last_heartbeat).getTime() : 0) - (b.last_heartbeat ? new Date(b.last_heartbeat).getTime() : 0);
      }
      return sortDir === 'desc' ? -diff : diff;
    });

  const toggleSort = (field: 'hostname' | 'last_heartbeat' | 'status') => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const isolatedCount = devices.filter(d => d.status === 'isolated').length;
  const offlineCount = devices.filter(d => d.status === 'offline').length;
  const activeCount = devices.filter(d => d.status === 'active').length;

  // Group devices by owner for boss fleet view
  const isOrgBoss = currentUser?.purpose === 'organization' && currentUser?.org_type === 'boss';
  const devicesByOwner: Record<string, Device[]> = {};
  if (isOrgBoss) {
    for (const d of devices) {
      const owner = d.owner_id || 'Unassigned';
      if (!devicesByOwner[owner]) devicesByOwner[owner] = [];
      devicesByOwner[owner].push(d);
    }
  }

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

      {/* Fleet Overview — Boss Only: Staff servers grouped cleanly */}
      {isOrgBoss && Object.keys(devicesByOwner).length > 0 && (
        <Card title="Server Fleet" subtitle={`${Object.keys(devicesByOwner).length} staff member(s) — ${devices.length} server(s) total`}>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(devicesByOwner).map(([owner, ownerDevices]) => {
              const ownerActive = ownerDevices.filter(d => d.status === 'active').length;
              const overallHealth = ownerDevices.length > 0 ? Math.round((ownerActive / ownerDevices.length) * 100) : 0;
              return (
                <div
                  key={owner}
                  className="rounded-xl border border-cyber-border bg-cyber-bg/50 p-4 hover:border-cyber-accent/30 transition-all"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
                        <span className="text-xs font-bold text-white">{owner.charAt(0).toUpperCase()}</span>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-cyber-text">{owner}</p>
                        <p className="text-[10px] text-cyber-muted">{ownerDevices.length} server(s)</p>
                      </div>
                    </div>
                    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                      overallHealth >= 80 ? 'bg-green-500/10 text-green-400' :
                      overallHealth >= 50 ? 'bg-amber-500/10 text-amber-400' :
                      'bg-red-500/10 text-red-400'
                    }`}>
                      {overallHealth}%
                    </span>
                  </div>
                  {/* Mini device list */}
                  <div className="space-y-1.5">
                    {ownerDevices.slice(0, 3).map((d) => (
                      <div key={d.id} className="flex items-center justify-between text-xs">
                        <span className="text-cyber-muted truncate max-w-[120px]">{d.hostname}</span>
                        <span className={`flex items-center gap-1 ${statusColors[d.status]}`}>
                          {d.status === 'active' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                          {d.status === 'offline' && <span className="w-1.5 h-1.5 rounded-full bg-red-400" />}
                          {d.status === 'isolated' && <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />}
                          {d.status}
                        </span>
                      </div>
                    ))}
                    {ownerDevices.length > 3 && (
                      <p className="text-[10px] text-cyber-muted">+{ownerDevices.length - 3} more</p>
                    )}
                  </div>
                  {/* Health bar */}
                  <div className="mt-3 h-1.5 w-full bg-cyber-border rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        overallHealth >= 80 ? 'bg-green-500' :
                        overallHealth >= 50 ? 'bg-amber-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${overallHealth}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border bg-cyber-card/50 px-4 py-3 border-cyber-border">
          <p className="text-2xl font-bold text-cyber-text">{devices.length}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Total Devices</p>
        </div>
        <div className="rounded-xl border bg-emerald-500/10 border-emerald-500/30 px-4 py-3">
          <p className="text-2xl font-bold text-emerald-400">{activeCount}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">Active</p>
        </div>
        <div className="rounded-xl border bg-amber-500/10 border-amber-500/30 px-4 py-3">
          <p className="text-2xl font-bold text-amber-400">{isolatedCount}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-400">Isolated</p>
        </div>
        <div className="rounded-xl border bg-red-500/10 border-red-500/30 px-4 py-3">
          <p className="text-2xl font-bold text-red-400">{offlineCount}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-red-400">Offline</p>
        </div>
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
              placeholder="Search devices by name, IP, owner..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as DeviceStatus | 'all')}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none appearance-none cursor-pointer"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="isolated">Isolated</option>
              <option value="offline">Offline</option>
            </select>
          </div>
          <span className="text-xs text-cyber-muted">{filtered.length} devices</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left">
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Device Name</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Owner</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Status</th>
                <th
                  className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted cursor-pointer hover:text-cyber-text"
                  onClick={() => toggleSort('last_heartbeat')}
                >
                  <span className="flex items-center gap-1">
                    Last Seen
                    {sortField === 'last_heartbeat' && <ChevronDown size={12} className={sortDir === 'asc' ? 'rotate-180' : ''} />}
                  </span>
                </th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">IP</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">OS</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length > 0 ? (
                filtered.map((device) => (
                  <tr
                    key={device.id}
                    className="border-b border-cyber-border/50 hover:bg-cyber-accent/5 transition-colors cursor-pointer"
                    onClick={() => setSelectedDevice(device)}
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Monitor size={16} className="text-cyber-muted" />
                        <span className="font-medium text-cyber-text">{device.hostname}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-muted">{device.owner_id || '-'}</td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs border ${statusBg[device.status]}`}>
                        {device.status === 'active' && <CheckCircle size={10} />}
                        {device.status === 'isolated' && <AlertTriangle size={10} />}
                        {device.status === 'offline' && <XCircle size={10} />}
                        <span className={statusColors[device.status]}>{device.status.replace('_', ' ')}</span>
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">
                      {device.last_heartbeat ? new Date(device.last_heartbeat).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">{device.ip_address}</td>
                    <td className="px-5 py-3 text-xs text-cyber-muted">{device.os_type || 'Unknown'}</td>
                    <td className="px-5 py-3">
                      <ExternalLink size={14} className="text-cyber-muted hover:text-cyber-accent" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-5 py-16 text-center">
                    <div className="flex flex-col items-center gap-4">
                      <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyber-accent/10">
                        <Monitor size={32} className="text-cyber-accent" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-cyber-text">No devices found</p>
                        <p className="text-xs text-cyber-muted mt-1">Install CyberNova agents to start monitoring devices.</p>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Device Detail Modal */}
      <Modal
        isOpen={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        title={`Device: ${selectedDevice?.hostname || ''}`}
        size="lg"
      >
        {selectedDevice && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs border ${statusBg[selectedDevice.status]}`}>
                {selectedDevice.status === 'active' && <CheckCircle size={12} />}
                {selectedDevice.status === 'isolated' && <AlertTriangle size={12} />}
                {selectedDevice.status === 'offline' && <XCircle size={12} />}
                <span className={statusColors[selectedDevice.status]}>{selectedDevice.status.replace('_', ' ')}</span>
              </span>
              <span className="text-xs text-cyber-muted">ID: {selectedDevice.id.slice(0, 8)}</span>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Hostname</p>
                <p className="mt-1 text-sm text-cyber-text">{selectedDevice.hostname}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">IP Address</p>
                <p className="mt-1 text-sm text-cyber-text font-mono">{selectedDevice.ip_address}</p>
              </div>
              {selectedDevice.mac_address && (
                <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">MAC Address</p>
                  <p className="mt-1 text-sm text-cyber-text font-mono">{selectedDevice.mac_address}</p>
                </div>
              )}
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">OS</p>
                <p className="mt-1 text-sm text-cyber-text">{selectedDevice.os_type || 'Unknown'}{selectedDevice.os_version ? ` ${selectedDevice.os_version}` : ''}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Agent Version</p>
                <p className="mt-1 text-sm text-cyber-text">{selectedDevice.agent_version || 'N/A'}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Owner</p>
                <p className="mt-1 text-sm text-cyber-text">{selectedDevice.owner_id || 'Unassigned'}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Last Seen</p>
                <p className="mt-1 text-sm text-cyber-text">{selectedDevice.last_heartbeat ? new Date(selectedDevice.last_heartbeat).toLocaleString() : 'Never'}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Tenant</p>
                <p className="mt-1 text-sm text-cyber-text font-mono">{selectedDevice.tenant_id.slice(0, 8)}</p>
              </div>
            </div>

            {selectedDevice.status === 'active' && (
              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => setConfirmAction({ type: 'isolate', device: selectedDevice })}
                  disabled={actionLoading === 'isolate'}
                  className="flex items-center gap-2 rounded-lg bg-red-500/20 border border-red-500/30 px-4 py-2 text-sm text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50"
                >
                  <MonitorOff size={16} />
                  Isolate Device
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
        onConfirm={handleAction}
        title="Isolate Device"
        message={confirmAction ? `Are you sure you want to isolate device "${confirmAction.device.hostname}" (${confirmAction.device.ip_address}) from the network?` : ''}
        confirmLabel="Isolate"
        loading={actionLoading === 'isolate'}
      />
    </div>
  );
}
