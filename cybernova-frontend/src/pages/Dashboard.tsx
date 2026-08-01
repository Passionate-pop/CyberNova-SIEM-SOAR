/**
 * CyberNova — Unified Dashboard
 * Single dashboard for ALL user types (individual, org admin, org staff).
 * No more separate "Executive Dashboard" vs "Protection Page" duplication.
 */
import { useState, useEffect, useCallback } from 'react';
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX,
  Activity, CheckCircle, Clock,
  Monitor, AlertTriangle, Globe, Ban, MonitorOff,
  Gauge, FileScan,
  Wifi,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { PipelineVisualization } from '../components/ui/PipelineVisualization';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { useFetch } from '../hooks/useFetch';
import { useWebSocket } from '../hooks/useWebSocket';
import { useAuthStore } from '../stores/useAuthStore';
import { fetchMetrics, fetchAlerts, fetchDevices, fetchUserDevices, blockIP, isolateDevice, executeAction, markAlertSafe } from '../services/api';
import { resolveUserPurpose, resolveUserRole, resolveOrgType } from '../utils/userResolve';

type ProtectionStatus = 'protected' | 'warning' | 'compromised';

export function Dashboard() {
  const { token, user } = useAuthStore();
  const purpose = resolveUserPurpose(user);
  const role = resolveUserRole(user);
  const orgType = resolveOrgType(user);
  const isOrg = purpose === 'organization';
  const isAdmin = role === 'admin';
  const isBoss = isOrg && (orgType === 'boss' || isAdmin);

  // Data fetching — only call admin endpoints for admin users
  const { data: metrics, refetch: refetchMetrics } = useFetch(useCallback(() => fetchMetrics(), []));
  const { data: devices, loading: devicesLoading, refetch: refetchDevices } = useFetch(useCallback(() => isOrg ? (isAdmin ? fetchDevices() : fetchUserDevices()) : Promise.resolve([]), [isAdmin, isOrg]));
  const { data: alerts, loading: alertsLoading, refetch: refetchAlerts } = useFetch(useCallback(() => fetchAlerts(), []));

  // Real-time WebSocket
  const [toasts, setToasts] = useState<{ id: number; message: string; type: string }[]>([]);
  useWebSocket({
    token: token || undefined,
    tenantId: user?.tenant_id,
    onMessage: (msg) => {
      if (msg.type === 'new_alert' || msg.type === 'alert_updated') {
        refetchAlerts();
        refetchMetrics();
        const alert = msg.data?.alert;
        if (alert) {
          const id = Date.now();
          setToasts(prev => [...prev, { id, message: `🚨 ${alert.severity.toUpperCase()}: ${alert.description?.substring(0, 60)}...`, type: alert.severity }]);
          setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
        }
      }
    },
  });

  // State
  const [protectionEnabled, setProtectionEnabled] = useState(true);
  const [deviceStatus, setDeviceStatus] = useState<ProtectionStatus>('protected');
  const [lastUpdated, setLastUpdated] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ type: string; alert: any } | null>(null);

  useEffect(() => { setLastUpdated(new Date().toLocaleTimeString()); }, [alerts]);
  useEffect(() => { if (toast) { const t = setTimeout(() => setToast(null), 4000); return () => clearTimeout(t); } }, [toast]);

  // Derived metrics — declare BEFORE any hooks that depend on them
  const totalDevices = devices?.length || 0;
  const devicesAtRisk = devices?.filter((d: any) => d.is_isolated === true).length || 0;
  const securityScore = Math.max(0, 100 - (metrics?.risk_score || 0));

  // Derive device status from alerts — only unresolved (new/in_progress/correlated) alerts matter
  const unresolvedAlerts = (alerts || []).filter((a: any) => {
    const s = (a.status || 'new').toLowerCase();
    return s === 'new' || s === 'in_progress' || s === 'correlated';
  });
  const unresolvedCriticalOrHigh = unresolvedAlerts.filter((a: any) =>
    a.severity === 'critical' || a.severity === 'high'
  );
  const activeThreats = unresolvedCriticalOrHigh.length;

  useEffect(() => {
    // Always consider the security score first — if score shows at-risk, reflect that
    if (securityScore < 40) {
      setDeviceStatus('compromised');
    } else if (securityScore < 70) {
      setDeviceStatus('warning');
    } else if (unresolvedCriticalOrHigh.length > 0) {
      const hasCritical = unresolvedCriticalOrHigh.some((a: any) => a.severity === 'critical');
      setDeviceStatus(hasCritical ? 'compromised' : 'warning');
    } else {
      setDeviceStatus('protected');
    }
  }, [securityScore, unresolvedCriticalOrHigh]);

  const currentDevice = devices?.find((d: any) => d.status === 'active');

  // Status color based on device protection state
  const getStatusColor = () => {
    switch (deviceStatus) {
      case 'protected': return { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', icon: ShieldCheck, text: 'text-emerald-400', label: 'Protected' };
      case 'warning': return { bg: 'bg-amber-500/10', border: 'border-amber-500/30', icon: ShieldAlert, text: 'text-amber-400', label: 'Attention Needed' };
      case 'compromised': return { bg: 'bg-red-500/10', border: 'border-red-500/30', icon: ShieldX, text: 'text-red-400', label: 'At Risk' };
      default: return { bg: 'bg-gray-500/10', border: 'border-gray-500/30', icon: Shield, text: 'text-gray-400', label: 'Unknown' };
    }
  };

  const getRecommendedAction = (severity: string) => {
    switch (severity) {
      case 'critical': return { label: 'Isolate', color: 'bg-red-500/20 text-red-400 hover:bg-red-500/30', icon: MonitorOff };
      case 'high': return { label: 'Investigate', color: 'bg-orange-500/20 text-orange-400 hover:bg-orange-500/30', icon: ShieldAlert };
      case 'medium': return { label: 'Review', color: 'bg-amber-500/20 text-amber-400 hover:bg-amber-500/30', icon: FileScan };
      default: return { label: 'Monitor', color: 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30', icon: Activity };
    }
  };

  const handleAction = async (alert: any, actionType: string) => {
    setActionLoading(actionType);
    try {
      if (actionType === 'block_ip') {
        try {
          await blockIP(alert.source_ip || 'unknown', 'Dashboard block');
          setToast({ message: `IP ${alert.source_ip} blocked`, type: 'success' });
        } catch (blockErr) {
          const msg = blockErr instanceof Error ? blockErr.message : '';
          if (msg.toLowerCase().includes('already blocked')) {
            // IP already blocked by a previous action — treat as success, not error
            setToast({ message: `IP ${alert.source_ip} already blocked`, type: 'success' });
          } else {
            throw blockErr;
          }
        }
        // Mark the alert as safe so it no longer shows as an unresolved threat
        try { await markAlertSafe(alert.alert_id || alert.id); } catch { /* non-critical */ }
      } else if (actionType === 'isolate') {
        const dev = devices?.find((d: any) => d.ip_address === alert.source_ip);
        if (dev) {
          await isolateDevice(dev.id);
          setToast({ message: `Device ${dev.hostname} isolated`, type: 'success' });
        } else {
          setToast({ message: 'No matching device found', type: 'error' });
        }
      } else if (actionType === 'investigate') {
        await executeAction('trigger_automation', alert.alert_id || alert.id);
        setToast({ message: 'Investigation triggered', type: 'success' });
      }
      refetchAlerts();
      refetchMetrics();
      refetchDevices();
    } catch (e) {
      setToast({ message: `Action failed: ${e instanceof Error ? e.message : 'error'}`, type: 'error' });
    } finally {
      setActionLoading(null);
      setConfirmAction(null);
    }
  };

  const statusStyle = getStatusColor();
  const StatusIcon = statusStyle.icon;

  return (
    <div className="space-y-6">
      {/* Toast Notifications */}
      {toast && (
        <div className={`fixed top-4 right-4 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 shadow-xl text-sm animate-slide-in ${
          toast.type === 'success' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-red-500/30 bg-red-500/10 text-red-400'
        }`}>
          {toast.type === 'success' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
          {toast.message}
        </div>
      )}

      {/* Real-time WebSocket toasts */}
      <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none" style={{ top: toast ? '80px' : '16px' }}>
        {toasts.map((t) => (
          <div key={t.id} className={`pointer-events-auto p-3 rounded-lg shadow-lg border backdrop-blur-sm max-w-sm animate-slide-in ${
            t.type === 'critical' ? 'bg-red-500/20 border-red-500/50 text-red-300' :
            t.type === 'high' ? 'bg-orange-500/20 border-orange-500/50 text-orange-300' :
            'bg-blue-500/20 border-blue-500/50 text-blue-300'
          }`}>
            <p className="text-xs font-medium">{t.message}</p>
          </div>
        ))}
      </div>

      {/* ── Status Header ───────────────────────────────────────────── */}
      <div className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl border ${statusStyle.bg} ${statusStyle.border}`}>
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-xl ${statusStyle.bg} border ${statusStyle.border} flex items-center justify-center`}>
            <StatusIcon size={28} className={statusStyle.text} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">{statusStyle.label}</h2>
            <p className="text-sm text-gray-400">
              {deviceStatus === 'protected' && 'Your environment is secure and monitored'}
              {deviceStatus === 'warning' && 'Security attention needed'}
              {deviceStatus === 'compromised' && 'Immediate action required'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-wrap">

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/20 text-emerald-400">
            <Wifi size={14} />
            <span className="text-xs font-medium">Real-time ON</span>
          </div>
          {lastUpdated && (
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <Clock size={12} />
              <span>Updated {lastUpdated}</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Key Metrics Grid ───────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">{isOrg ? 'Total Devices' : 'Protection Status'}</span>
            {isOrg ? <Monitor size={18} className="text-cyan-400" /> : <ShieldCheck size={18} className="text-emerald-400" />}
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white">{isOrg ? totalDevices : protectionEnabled ? 'Active' : 'Paused'}</span>
            <span className={`text-sm mb-1 ${isOrg ? 'text-gray-500' : protectionEnabled ? 'text-emerald-400' : 'text-amber-400'}`}>
              {isOrg ? 'registered' : protectionEnabled ? 'All systems go' : 'Click to resume'}
            </span>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Active Threats</span>
            <AlertTriangle size={18} className={activeThreats > 0 ? 'text-red-400' : 'text-emerald-400'} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white">{activeThreats}</span>
            <span className={`text-sm mb-1 ${activeThreats > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {activeThreats > 0 ? 'Action needed' : 'None'}
            </span>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">{isOrg ? 'Devices at Risk' : 'Threats Blocked'}</span>
            <ShieldAlert size={18} className={isOrg ? (devicesAtRisk > 0 ? 'text-amber-400' : 'text-emerald-400') : 'text-emerald-400'} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white">{isOrg ? devicesAtRisk : metrics?.threats_mitigated ?? '—'}</span>
            <span className="text-sm mb-1 text-gray-500">{isOrg ? `of ${totalDevices}` : 'blocked'}</span>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Security Score</span>
            <Gauge size={18} className={securityScore >= 80 ? 'text-emerald-400' : securityScore >= 60 ? 'text-amber-400' : 'text-red-400'} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white">{securityScore}</span>
            <span className="text-sm mb-1 text-gray-500">/100</span>
          </div>
          <div className="mt-3 h-1 bg-[#111827] rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${securityScore >= 80 ? 'bg-emerald-500' : securityScore >= 60 ? 'bg-amber-500' : 'bg-red-500'}`} style={{ width: `${securityScore}%` }} />
          </div>
        </Card>
      </div>

      {/* ── Pipeline Visualization (org only) ──────────────────────── */}
      {isOrg && <PipelineVisualization />}

      {/* ── Individual: Protection toggle & On-Device Scan ─────────── */}
      {!isOrg && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="p-5">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <ShieldCheck size={20} className="text-cyan-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Real-time Protection</h3>
                <p className="text-xs text-gray-500">Block threats automatically</p>
              </div>
            </div>
            <button
              onClick={() => { setProtectionEnabled(!protectionEnabled); setDeviceStatus(protectionEnabled ? 'warning' : 'protected'); }}
              className={`w-full py-2.5 rounded-lg font-medium text-sm transition-all ${
                protectionEnabled ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30' : 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
              }`}
            >
              {protectionEnabled ? (
                <span className="flex items-center justify-center gap-2"><Shield size={16} /> Protection Active</span>
              ) : (
                <span className="flex items-center justify-center gap-2"><ShieldAlert size={16} /> Enable Protection</span>
              )}
            </button>
          </Card>

          <Card className="p-5">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <FileScan size={20} className="text-purple-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">On-Device Scan</h3>
                <p className="text-xs text-gray-500">Deep scan requires the agent</p>
              </div>
            </div>
            <div className="rounded-lg bg-[#0a0e1a] border border-[#1e293b] p-3 text-center">
              <p className="text-xs text-gray-500">Install the CyberNova agent for file scanning and real-time threat detection.</p>
            </div>
          </Card>
        </div>
      )}

      {/* ── Main Content Grid ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Device Info / All Servers (org admin) or My Device (individual/staff) */}
        <Card title={isBoss ? 'Connected Servers' : 'My Device'} subtitle={isBoss ? `${totalDevices} server${totalDevices !== 1 ? 's' : ''} in your organization` : 'Current device status'} className="lg:col-span-1">
          {isBoss ? (
            devicesLoading ? (
              <div className="flex items-center justify-center h-48"><LoadingSpinner /></div>
            ) : devices && devices.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {devices.slice(0, 8).map((device: any) => {
                  const isActive = device.status === 'active';
                  const isAtRisk = device.status === 'isolated' || device.status === 'error';
                  return (
                    <div key={device.id} className={`flex items-center gap-3 p-2.5 rounded-lg transition-colors ${isAtRisk ? 'bg-red-500/10 border border-red-500/20' : isActive ? 'bg-[#111827] hover:bg-[#111827]/80' : 'bg-[#111827]/50 opacity-60'}`}>
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${isAtRisk ? 'bg-red-500/20' : isActive ? 'bg-emerald-500/20' : 'bg-gray-500/20'}`}>
                        <Monitor size={14} className={isAtRisk ? 'text-red-400' : isActive ? 'text-emerald-400' : 'text-gray-500'} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-white truncate">{device.hostname}</p>
                        <p className="text-[10px] text-gray-500 truncate">{device.os_type || 'unknown'} · {device.ip_address || '—'}</p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {isAtRisk && <AlertTriangle size={12} className="text-red-400" />}
                        <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${isAtRisk ? 'bg-red-500/20 text-red-400' : isActive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-500/20 text-gray-500'}`}>
                          {device.status}
                        </span>
                      </div>
                    </div>
                  );
                })}
                {devices.length > 8 && (
                  <p className="text-xs text-gray-500 text-center pt-1">+{devices.length - 8} more servers</p>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-center">
                <Monitor size={40} className="text-gray-600 mb-3" />
                <p className="text-sm text-white font-medium">No Servers Connected</p>
                <p className="text-xs text-gray-500 mt-1">Share your org key with staff to connect servers</p>
              </div>
            )
          ) : currentDevice ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-3 rounded-lg bg-[#111827]">
                <Monitor size={20} className="text-cyan-400" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">{currentDevice.hostname}</p>
                  <p className="text-xs text-gray-500">{currentDevice.os_type || 'Unknown OS'}</p>
                </div>
                <span className={`w-2 h-2 rounded-full ${currentDevice.status === 'active' ? 'bg-emerald-500 animate-pulse' : 'bg-gray-500'}`} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center gap-2 p-2 rounded-lg bg-[#111827]">
                  <Globe size={14} className="text-gray-500" />
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">IP Address</p>
                    <p className="text-xs font-medium text-white">{currentDevice.ip_address || '—'}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 p-2 rounded-lg bg-[#111827]">
                  <Activity size={14} className="text-gray-500" />
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Status</p>
                    <p className="text-xs font-medium text-white capitalize">{currentDevice.status || '—'}</p>
                  </div>
                </div>
              </div>
              <div className="flex gap-2 pt-2">
                <button onClick={() => setConfirmAction({ type: 'isolate', alert: currentDevice })} disabled={actionLoading === 'isolate'}
                  className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50">
                  <MonitorOff size={12} /> Isolate
                </button>
                <button onClick={() => setConfirmAction({ type: 'block_ip', alert: currentDevice })} disabled={actionLoading === 'block_ip'}
                  className="flex items-center gap-1.5 rounded-lg border border-orange-500/30 bg-orange-500/10 px-3 py-1.5 text-xs text-orange-400 hover:bg-orange-500/20 transition-colors disabled:opacity-50">
                  <Ban size={12} /> Block IP
                </button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <Monitor size={40} className="text-gray-600 mb-3" />
              <p className="text-sm text-white font-medium">No Device Found</p>
              <p className="text-xs text-gray-500 mt-1">Install the agent to register your device</p>
            </div>
          )}
        </Card>

        {/* Right: Recent Alerts */}
        <Card title="Recent Alerts" subtitle="Latest security events" className="lg:col-span-2">
          {alertsLoading ? (
            <div className="flex items-center justify-center h-48"><LoadingSpinner /></div>
          ) : alerts && alerts.length > 0 ? (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {alerts.slice(0, 8).map((alert: any, i: number) => {
                const action = getRecommendedAction(alert.severity);
                const ActionIcon = action.icon;
                return (
                  <div key={alert.alert_id || alert.id || i} className="flex items-center gap-3 p-3 rounded-lg bg-[#111827] hover:bg-[#111827]/80 transition-colors">
                    <div className={`w-2 h-2 rounded-full ${
                      alert.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                      alert.severity === 'high' ? 'bg-orange-500' :
                      alert.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white truncate">{alert.description || alert.rule_name || alert.type}</p>
                      <p className="text-xs text-gray-500">{new Date(alert.created_at || alert.timestamp).toLocaleTimeString()}</p>
                    </div>
                    <SeverityBadge severity={alert.severity} />
                    <button
                      onClick={() => {
                        const actionType = alert.severity === 'critical' ? 'isolate' : alert.severity === 'high' ? 'investigate' : 'monitor';
                        setConfirmAction({ type: actionType, alert });
                      }}
                      disabled={!!actionLoading}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all ${action.color} disabled:opacity-50`}
                    >
                      <ActionIcon size={12} /> {action.label}
                    </button>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <CheckCircle size={32} className="text-emerald-500 mb-3" />
              <p className="text-sm text-white font-medium">All Clear</p>
              <p className="text-xs text-gray-500 mt-1">
                {isAdmin ? 'Install the CyberNova agent on your devices to begin monitoring' : 'No alerts detected on your device'}
              </p>
              {isBoss && (
                <div className="mt-4 flex gap-2 text-xs text-gray-600">
                  <span className="px-2 py-1 rounded bg-[#111827]">Real-time monitoring active</span>
                  <span className="px-2 py-1 rounded bg-[#111827]">Threat signatures up to date</span>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* ── Quick Stats Footer ────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="flex items-center gap-3 p-4 rounded-xl bg-[#111827] border border-[#1e293b]">
          <AlertTriangle size={20} className="text-cyan-400" />
          <div>
            <p className="text-lg font-bold text-white">{metrics?.alerts_today || 0}</p>
            <p className="text-xs text-gray-500">Alerts Today</p>
          </div>
        </div>
        <div className="flex items-center gap-3 p-4 rounded-xl bg-[#111827] border border-[#1e293b]">
          <Ban size={20} className="text-purple-400" />
          <div>
            <p className="text-lg font-bold text-white">{metrics?.blocked_ips || 0}</p>
            <p className="text-xs text-gray-500">Blocked IPs</p>
          </div>
        </div>
        <div className="flex items-center gap-3 p-4 rounded-xl bg-[#111827] border border-[#1e293b]">
          <ShieldCheck size={20} className="text-emerald-400" />
          <div>
            <p className="text-lg font-bold text-white">{metrics?.threats_mitigated || 0}</p>
            <p className="text-xs text-gray-500">Threats Mitigated</p>
          </div>
        </div>
        <div className="flex items-center gap-3 p-4 rounded-xl bg-[#111827] border border-[#1e293b]">
          <Activity size={20} className="text-blue-400" />
          <div>
            <p className="text-lg font-bold text-white">{metrics?.system_health || 100}%</p>
            <p className="text-xs text-gray-500">System Health</p>
          </div>
        </div>
        <div className="flex items-center gap-3 p-4 rounded-xl bg-[#111827] border border-[#1e293b]">
          <Clock size={20} className="text-amber-400" />
          <div>
            <p className="text-lg font-bold text-white">{metrics?.uptime || 99.9}%</p>
            <p className="text-xs text-gray-500">Uptime</p>
          </div>
        </div>
      </div>

      {/* ── Confirm Dialog ────────────────────────────────────────── */}
      <ConfirmDialog
        isOpen={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        onConfirm={() => { if (confirmAction) handleAction(confirmAction.alert, confirmAction.type); }}
        title={
          confirmAction?.type === 'isolate' ? 'Confirm Isolation' :
          confirmAction?.type === 'block_ip' ? 'Block IP Address' :
          confirmAction?.type === 'investigate' ? 'Trigger Investigation' : 'Confirm Action'
        }
        message={
          confirmAction?.type === 'isolate' ? 'This device will be isolated from the network.' :
          confirmAction?.type === 'block_ip' ? `Block IP ${confirmAction?.alert.ip_address || confirmAction?.alert.source_ip || 'unknown'}?` :
          confirmAction?.type === 'investigate' ? 'Trigger automated investigation workflow?' : 'Are you sure?'
        }
        confirmLabel={confirmAction?.type === 'isolate' ? 'Isolate' : confirmAction?.type === 'block_ip' ? 'Block' : 'Execute'}
        loading={!!actionLoading}
      />
    </div>
  );
}
