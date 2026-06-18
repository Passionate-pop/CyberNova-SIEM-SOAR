import { useState, useCallback, useMemo } from 'react';
import { Ban, Skull, Unplug, Zap, Clock, CheckCircle, XCircle, Loader, History, Lock, Shield, Search, ArrowUpDown, Filter, Bug } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { PlaybookBuilder } from '../components/response/PlaybookBuilder';
import { useFetch } from '../hooks/useFetch';
import { useRBAC } from '../hooks/useRBAC';
import { useWebSocket } from '../hooks/useWebSocket';
import { useAuthStore } from '../stores/useAuthStore';
import { fetchResponseActions, executeAction, injectTestSoarActions } from '../services/api';
import type { ActionType, ResponseAction } from '../types';
import { cn } from '../utils/cn';

interface ActionConfig {
  type: ActionType;
  label: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  placeholder: string;
}

const actionConfigs: ActionConfig[] = [
  {
    type: 'block_ip',
    label: 'Block IP',
    description: 'Block an IP address at the edge firewall',
    icon: <Ban size={24} />,
    color: 'from-red-500/20 to-red-500/5 border-red-500/30 hover:border-red-500/50',
    placeholder: 'Enter IP address (e.g., 192.168.1.100)',
  },
  {
    type: 'kill_process',
    label: 'Kill Process',
    description: 'Terminate a running process on target system',
    icon: <Skull size={24} />,
    color: 'from-orange-500/20 to-orange-500/5 border-orange-500/30 hover:border-orange-500/50',
    placeholder: 'Enter PID or process name',
  },
  {
    type: 'isolate_device',
    label: 'Isolate Device',
    description: 'Disconnect a device from the network',
    icon: <Unplug size={24} />,
    color: 'from-amber-500/20 to-amber-500/5 border-amber-500/30 hover:border-amber-500/50',
    placeholder: 'Enter hostname (e.g., WKS-042)',
  },
  {
    type: 'trigger_automation',
    label: 'Trigger Automation',
    description: 'Execute SOAR workflow via webhook',
    icon: <Zap size={24} />,
    color: 'from-purple-500/20 to-purple-500/5 border-purple-500/30 hover:border-purple-500/50',
    placeholder: 'Enter workflow name or ID',
  },
];

const actionIcons: Record<NonNullable<ResponseAction['status']>, React.ReactNode> = {
  pending: <Clock size={14} className="text-amber-400" />,
  executing: <Loader size={14} className="text-blue-400 animate-spin" />,
  completed: <CheckCircle size={14} className="text-emerald-400" />,
  failed: <XCircle size={14} className="text-red-400" />,
};


export function ResponsePage() {
  const { data: actions, loading, setData: setActions, refetch } = useFetch(useCallback(() => fetchResponseActions(), []));
  const { isAdmin: isAdminUser } = useRBAC();
  const { token, user: authUser } = useAuthStore();

  // Real-time WebSocket — refetch actions when a SOAR action occurs from any page
  useWebSocket({
    token: token || undefined,
    tenantId: authUser?.tenant_id,
    onMessage: (msg) => {
      if (msg.type === 'soar_action') {
        refetch();
      }
    },
  });
  const [selectedAction, setSelectedAction] = useState<ActionConfig | null>(null);
  const [target, setTarget] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [injecting, setInjecting] = useState(false);
  const [activeTab, setActiveTab] = useState<'actions' | 'playbooks'>('actions');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');

  const filteredActions = useMemo(() => {
    if (!actions) return [];
    let result = [...actions];
    
    // Status filter
    if (statusFilter !== 'all') {
      result = result.filter(a => a.status === statusFilter);
    }
    
    // Action type filter
    if (typeFilter !== 'all') {
      result = result.filter(a => a.action_type === typeFilter);
    }
    
    // Search by target, ID, or initiated_by
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(a => 
        a.target?.toLowerCase().includes(q) ||
        a.id?.toLowerCase().includes(q) ||
        a.initiated_by?.toLowerCase().includes(q) ||
        a.result?.toLowerCase().includes(q)
      );
    }
    
    // Sort by timestamp
    result.sort((a, b) => {
      const ta = new Date(a.timestamp || 0).getTime();
      const tb = new Date(b.timestamp || 0).getTime();
      return sortOrder === 'newest' ? tb - ta : ta - tb;
    });
    
    return result;
  }, [actions, statusFilter, typeFilter, searchQuery, sortOrder]);

  const handleExecute = async () => {
    if (!selectedAction || !target) return;
    setExecuting(true);
    setError(null);
    try {
      const result = await executeAction(selectedAction.type, target);
      setActions((prev) => prev ? [result, ...prev] : [result]);
      setConfirmOpen(false);
      setTarget('');
      setSelectedAction(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Action execution failed';
      setError(message);
      setConfirmOpen(false);
    } finally {
      setExecuting(false);
    }
  };


  return (
    <div className="space-y-6">
      {/* Error Banner */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
          <XCircle size={16} className="text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
          <button onClick={() => setError(null)} className="ml-auto text-red-400 hover:text-red-300">✕</button>
        </div>
      )}
      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-cyber-border">
        <button
          onClick={() => setActiveTab('actions')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'actions'
              ? 'border-cyber-accent text-cyber-accent'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          )}
        >
          <Zap size={16} className="inline mr-1.5" />
          Response Actions
        </button>
        <button
          onClick={() => setActiveTab('playbooks')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'playbooks'
              ? 'border-cyber-accent text-cyber-accent'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          )}
        >
          <Shield size={16} className="inline mr-1.5" />
          Playbook Builder
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'actions' && (
      <>{isAdminUser ? (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {actionConfigs.map((action) => (
          <button
            key={action.type}
            onClick={() => setSelectedAction(action)}
            className={cn(
              'group relative overflow-hidden rounded-xl border bg-gradient-to-br p-5 text-left transition-all duration-200',
              action.color,
              selectedAction?.type === action.type && 'ring-2 ring-cyber-accent/50'
            )}
          >
            <div className="mb-3 text-cyber-text">{action.icon}</div>
            <h3 className="text-sm font-semibold text-cyber-text">{action.label}</h3>
            <p className="mt-1 text-xs text-cyber-muted">{action.description}</p>
          </button>
        ))}
      </div>
      ) : (
        <div className="flex items-center justify-center gap-2 rounded-xl border border-cyber-border bg-cyber-card p-8">
          <Lock size={24} className="text-cyber-muted" />
          <div className="text-center">
            <p className="text-sm font-medium text-cyber-text">Response Actions Restricted</p>
            <p className="text-xs text-cyber-muted">Only Admin and SOC Managers can execute response actions</p>
          </div>
        </div>
      )}

      {/* Action Form */}
      {selectedAction && (
        <Card title={`Execute: ${selectedAction.label}`} subtitle="Lake-4 — Response & Automation">
          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Target</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={selectedAction.placeholder}
                className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2.5 px-4 text-sm font-mono text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none focus:ring-1 focus:ring-cyber-accent/30"
              />
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  if (target) setConfirmOpen(true);
                }}
                disabled={!target}
                className="rounded-lg bg-red-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-red-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Execute Action
              </button>
              <button
                onClick={() => { setSelectedAction(null); setTarget(''); }}
                className="rounded-lg border border-cyber-border px-4 py-2.5 text-sm font-medium text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/50 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </Card>
      )}

      {/* Action Logs */}
      <Card title="Action Log" subtitle="Response action history">
        {/* Filters */}
        <div className="mb-4 flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by target, ID, user..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-3 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          {/* Status filter */}
          <div className="relative">
            <Filter size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted pointer-events-none" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="appearance-none rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-8 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none cursor-pointer"
            >
              <option value="all">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="executing">Executing</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          {/* Type filter */}
          <div className="relative">
            <Filter size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted pointer-events-none" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="appearance-none rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-8 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none cursor-pointer"
            >
              <option value="all">All Actions</option>
              <option value="block_ip">Block IP</option>
              <option value="isolate_device">Isolate Device</option>
              <option value="kill_process">Kill Process</option>
              <option value="trigger_automation">Trigger Automation</option>
            </select>
          </div>
          {/* Sort */}
          <button
            onClick={() => setSortOrder(sortOrder === 'newest' ? 'oldest' : 'newest')}
            className="flex items-center gap-1.5 rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-muted hover:text-cyber-text hover:border-cyber-accent/30 transition-colors"
          >
            <ArrowUpDown size={14} />
            {sortOrder === 'newest' ? 'Newest' : 'Oldest'}
          </button>
          {/* Test SOAR inject — admin only */}
          {isAdminUser && (
            <button
              onClick={async () => {
                setInjecting(true);
                try {
                  await injectTestSoarActions();
                  setError(null);
                  refetch();
                } catch (err) {
                  setError(err instanceof Error ? err.message : 'Failed to inject test actions');
                } finally {
                  setInjecting(false);
                }
              }}
              disabled={injecting}
              className="flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-400 hover:bg-amber-500/10 hover:border-amber-500/50 transition-colors disabled:opacity-50"
              title="Inject 6 test SOAR actions to verify real-time WebSocket flow"
            >
              <Bug size={14} className={cn(injecting && 'animate-spin')} />
              {injecting ? 'Injecting...' : 'Test SOAR'}
            </button>
          )}
          {/* Results count */}
          <span className="text-xs text-cyber-muted ml-auto">
            {filteredActions.length} of {actions?.length || 0} actions
          </span>
        </div>
      
        {loading ? (
          <LoadingSpinner size="sm" />
        ) : filteredActions && filteredActions.length > 0 ? (
          <div className="overflow-x-auto -mx-4 sm:-mx-6">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-cyber-border">
                  {['ID', 'Action', 'Target', 'Status', 'Initiated By', 'Timestamp', 'Result'].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredActions.map((action) => (
                  <tr key={action.id} className="border-b border-cyber-border/30 hover:bg-cyber-accent/5 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-cyber-accent">{action.id?.substring(0, 8)}</td>
                    <td className="px-4 py-2.5">
                      <span className="rounded bg-cyber-border/50 px-2 py-0.5 text-[10px] font-semibold text-cyber-text uppercase whitespace-nowrap">
                        {action.action_type.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-cyber-text">{action.target}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        {action.status ? actionIcons[action.status] : null}
                        <StatusBadge status={action.status || 'pending'} />
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-cyber-muted">{action.initiated_by}</td>
                    <td className="px-4 py-2.5 font-mono text-cyber-muted whitespace-nowrap">
                      {new Date(action.timestamp ?? '').toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 text-cyber-muted max-w-[200px] truncate" title={action.result}>{action.result || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-20 px-6">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyber-accent/10 mb-4">
              <History size={32} className="text-cyber-accent" />
            </div>
            <p className="text-sm font-medium text-cyber-text mb-1">No actions executed yet</p>
            <p className="text-xs text-cyber-muted text-center">Response actions will be logged here when executed.
            <br /><span className="text-cyber-accent">Go to Dashboard → Seed Demo Data or use the Response Actions above to get started.</span></p>
          </div>
        )}
      </Card>

      {/* Confirm Dialog */}
      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleExecute}
        title={`Confirm: ${selectedAction?.label}`}
        message={`Are you sure you want to execute "${selectedAction?.label}" on target "${target}"? This action may have significant impact on the system.`}
        confirmLabel="Execute"
        loading={executing}
      />
      </>)}
      {activeTab === 'playbooks' && <PlaybookBuilder />}
    </div>
  );
}
