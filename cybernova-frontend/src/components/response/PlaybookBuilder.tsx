import { useState, useCallback } from 'react';
import {
  Plus, Pencil, Trash2, Shield, AlertTriangle, Zap,
  Lock, Activity, FileSearch, Ban,
} from 'lucide-react';
import { Card } from '../ui/Card';
import { ConfirmDialog } from '../ui/ConfirmDialog';
import { LoadingSpinner } from '../ui/LoadingSpinner';
import { useFetch } from '../../hooks/useFetch';
import { useRBAC } from '../../hooks/useRBAC';
import { fetchPlaybooks, savePlaybook, updatePlaybook, deletePlaybook } from '../../services/api';
import { cn } from '../../utils/cn';
import type { Playbook } from '../../types';

const SEVERITY_COLORS: Record<string, string> = {
  low: 'border-l-emerald-500/50',
  medium: 'border-l-amber-500/50',
  high: 'border-l-orange-500/50',
  critical: 'border-l-red-500/50',
};

const SEVERITY_BG: Record<string, string> = {
  low: 'bg-emerald-500/10 text-emerald-400',
  medium: 'bg-amber-500/10 text-amber-400',
  high: 'bg-orange-500/10 text-orange-400',
  critical: 'bg-red-500/10 text-red-400',
};

const ACTION_ICONS: Record<string, React.ReactNode> = {
  block_ip: <Ban size={14} />,
  isolate_host: <Lock size={14} />,
  notify_soc: <AlertTriangle size={14} />,
  notify_admin: <AlertTriangle size={14} />,
  log_alert: <FileSearch size={14} />,
  scan_host: <Activity size={14} />,
};

const ACTION_LABELS: Record<string, string> = {
  block_ip: 'Block IP',
  isolate_host: 'Isolate Host',
  notify_soc: 'Notify SOC',
  notify_admin: 'Notify Admin',
  log_alert: 'Log Alert',
  scan_host: 'Scan Host',
};

const EMPTY_PLAYBOOK: Playbook = {
  id: '',
  name: '',
  priority: 5,
  severity_action: 'ui_only',
  condition: { severity: [], min_risk_score: 0, rule_name: [] },
  actions: [],
  automated: false,
};

export function PlaybookBuilder() {
  const { data: playbooks, loading, refetch } = useFetch(useCallback(() => fetchPlaybooks(), []));
  const { isAdmin } = useRBAC();
  const [editingPlaybook, setEditingPlaybook] = useState<Playbook | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'view' | 'builder'>('view');

  const handleNew = () => {
    setEditingPlaybook({ ...EMPTY_PLAYBOOK, id: `pb_${Date.now()}` });
    setActiveTab('builder');
  };

  const handleEdit = (pb: Playbook) => {
    setEditingPlaybook(JSON.parse(JSON.stringify(pb)));
    setActiveTab('builder');
  };

  const handleDelete = async () => {
    if (!deletingId) return;
    setDeleteConfirmOpen(false);
    setDeletingId(null);
    try {
      await deletePlaybook(deletingId);
    } catch {
      // Ignore
    }
    refetch();
  };

  const handleSave = async () => {
    if (!editingPlaybook) return;
    const isExisting = playbooks?.some(p => p.id === editingPlaybook.id);
    try {
      if (isExisting) {
        await updatePlaybook(editingPlaybook.id, editingPlaybook);
      } else {
        await savePlaybook(editingPlaybook);
      }
    } catch {
      // Ignore
    }
    setActiveTab('view');
    setEditingPlaybook(null);
    refetch();
  };

  const addAction = () => {
    if (!editingPlaybook) return;
    setEditingPlaybook({
      ...editingPlaybook,
      actions: [...editingPlaybook.actions, { type: 'log_alert', params: {} }],
    });
  };

  const removeAction = (idx: number) => {
    if (!editingPlaybook) return;
    const actions = editingPlaybook.actions.filter((_, i) => i !== idx);
    setEditingPlaybook({ ...editingPlaybook, actions });
  };

  const updateAction = (idx: number, field: string, value: string) => {
    if (!editingPlaybook) return;
    const actions = [...editingPlaybook.actions];
    actions[idx] = { ...actions[idx], [field]: value };
    setEditingPlaybook({ ...editingPlaybook, actions });
  };

  const toggleSeverity = (sev: string) => {
    if (!editingPlaybook) return;
    const current = editingPlaybook.condition.severity || [];
    const next = current.includes(sev) ? current.filter(s => s !== sev) : [...current, sev];
    setEditingPlaybook({
      ...editingPlaybook,
      condition: { ...editingPlaybook.condition, severity: next },
    });
  };

  return (
    <div className="space-y-6 animate-slide-in">
      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-cyber-border">
        <button
          onClick={() => setActiveTab('view')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'view'
              ? 'border-cyber-accent text-cyber-accent'
              : 'border-transparent text-cyber-muted hover:text-cyber-text'
          )}
        >
          <Shield size={16} className="inline mr-1.5" />
          Playbooks
        </button>
        {isAdmin && (
          <button
            onClick={() => { if (!editingPlaybook) handleNew(); setActiveTab('builder'); }}
            className={cn(
              'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'builder'
                ? 'border-cyber-accent text-cyber-accent'
                : 'border-transparent text-cyber-muted hover:text-cyber-text'
            )}
          >
            <Plus size={16} className="inline mr-1.5" />
            Builder
          </button>
        )}
      </div>

      {activeTab === 'view' && (
        <>
          {loading ? (
            <LoadingSpinner size="sm" />
          ) : playbooks && playbooks.length > 0 ? (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {playbooks.map((pb) => (
                <div
                  key={pb.id}
                  className={cn(
                    'relative rounded-xl border border-cyber-border bg-cyber-card/80 backdrop-blur-sm p-5 border-l-4 transition-all hover:border-cyber-accent/50',
                    SEVERITY_COLORS[pb.condition.severity?.[0] || 'low']
                  )}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h3 className="text-sm font-semibold text-cyber-text">{pb.name}</h3>
                      <p className="text-[10px] font-mono text-cyber-muted mt-0.5">{pb.id}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={cn(
                        'px-2 py-0.5 rounded text-[10px] font-semibold uppercase',
                        pb.automated ? 'bg-purple-500/10 text-purple-400' : 'bg-cyber-border text-cyber-muted'
                      )}>
                        {pb.automated ? 'Auto' : 'Manual'}
                      </span>
                      {isAdmin && (
                        <button onClick={() => handleEdit(pb)} className="p-1 rounded text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/50">
                          <Pencil size={14} />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Conditions */}
                  <div className="mb-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted mb-1.5">Conditions</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(pb.condition.severity || []).map(s => (
                        <span key={s} className={cn('px-2 py-0.5 rounded text-[10px] font-medium', SEVERITY_BG[s] || 'bg-cyber-border text-cyber-muted')}>
                          {s}
                        </span>
                      ))}
                      {pb.condition.min_risk_score && pb.condition.min_risk_score > 0 && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-blue-500/10 text-blue-400">
                          Risk &ge; {pb.condition.min_risk_score}
                        </span>
                      )}
                      {(pb.condition.rule_name || []).map(r => (
                        <span key={r} className="px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-500/10 text-cyan-400">
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted mb-1.5">Actions</p>
                    <div className="space-y-1">
                      {pb.actions.map((action, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs text-cyber-muted">
                          <span className="text-cyber-accent/70">{ACTION_ICONS[action.type] || <Zap size={14} />}</span>
                          <span>{ACTION_LABELS[action.type] || action.type}</span>
                          {Object.keys(action.params).length > 0 && (
                            <span className="text-[10px] font-mono bg-cyber-border/50 px-1.5 py-0.5 rounded">
                              {JSON.stringify(action.params).slice(0, 40)}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Priority badge */}
                  <div className="absolute top-3 right-3 flex items-center gap-1 text-[10px] text-cyber-muted">
                    <span>P{pb.priority}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 px-6">
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyber-accent/10 mb-4">
                <Shield size={32} className="text-cyber-accent" />
              </div>
              <p className="text-sm font-medium text-cyber-text mb-1">No playbooks configured</p>
              <p className="text-xs text-cyber-muted text-center mb-4">Response playbooks define automated actions for security events</p>
              {isAdmin && (
                <button onClick={handleNew} className="flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2 text-sm font-semibold text-white hover:bg-cyber-accent/80 transition-colors">
                  <Plus size={16} />
                  Create Playbook
                </button>
              )}
            </div>
          )}
        </>
      )}

      {activeTab === 'builder' && editingPlaybook && (
        <div className="space-y-6">
          <Card title="Playbook Settings" subtitle="Define the playbook name and behavior">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Name</label>
                <input
                  type="text"
                  value={editingPlaybook.name}
                  onChange={(e) => setEditingPlaybook({ ...editingPlaybook, name: e.target.value })}
                  placeholder="My Playbook"
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm text-cyber-text focus:border-cyber-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">ID</label>
                <input
                  type="text"
                  value={editingPlaybook.id}
                  onChange={(e) => setEditingPlaybook({ ...editingPlaybook, id: e.target.value })}
                  placeholder="pb_my_playbook"
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm font-mono text-cyber-text focus:border-cyber-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Priority (lower = higher)</label>
                <input
                  type="number"
                  min={1}
                  max={10}
                  value={editingPlaybook.priority}
                  onChange={(e) => setEditingPlaybook({ ...editingPlaybook, priority: parseInt(e.target.value) || 5 })}
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm text-cyber-text focus:border-cyber-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Severity Action</label>
                <select
                  value={editingPlaybook.severity_action}
                  onChange={(e) => setEditingPlaybook({ ...editingPlaybook, severity_action: e.target.value })}
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm text-cyber-text focus:border-cyber-accent focus:outline-none"
                >
                  <option value="ui_only">UI Only</option>
                  <option value="notification">Notification</option>
                  <option value="automated">Automated</option>
                </select>
              </div>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editingPlaybook.automated}
                    onChange={(e) => setEditingPlaybook({ ...editingPlaybook, automated: e.target.checked })}
                    className="rounded border-cyber-border bg-cyber-bg text-cyber-accent focus:ring-cyber-accent"
                  />
                  <span className="text-sm text-cyber-text">Automated execution</span>
                </label>
              </div>
            </div>
          </Card>

          <Card title="Conditions" subtitle="When should this playbook trigger?">
            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Severity</label>
                <div className="flex flex-wrap gap-2">
                  {['low', 'medium', 'high', 'critical'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => toggleSeverity(sev)}
                      className={cn(
                        'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                        (editingPlaybook.condition.severity || []).includes(sev)
                          ? 'bg-cyber-accent/20 border-cyber-accent/50 text-cyber-accent'
                          : 'border-cyber-border text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/30'
                      )}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Min Risk Score</label>
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={editingPlaybook.condition.min_risk_score || 0}
                  onChange={(e) => setEditingPlaybook({
                    ...editingPlaybook,
                    condition: { ...editingPlaybook.condition, min_risk_score: parseInt(e.target.value) || 0 }
                  })}
                  className="w-full max-w-xs rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm text-cyber-text focus:border-cyber-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-cyber-muted uppercase tracking-wider">Rule Names (comma separated)</label>
                <input
                  type="text"
                  value={(editingPlaybook.condition.rule_name || []).join(', ')}
                  onChange={(e) => setEditingPlaybook({
                    ...editingPlaybook,
                    condition: {
                      ...editingPlaybook.condition,
                      rule_name: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                    }
                  })}
                  placeholder="brute_force_attempt, malware_detected"
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 px-3 text-sm font-mono text-cyber-text focus:border-cyber-accent focus:outline-none"
                />
              </div>
            </div>
          </Card>

          <Card
            title="Actions"
            subtitle="Response actions to execute"
            action={
              <button onClick={addAction} className="flex items-center gap-1 rounded-lg bg-cyber-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyber-accent/80 transition-colors">
                <Plus size={14} />
                Add Action
              </button>
            }
          >
            {editingPlaybook.actions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <p className="text-xs text-cyber-muted">No actions defined. Add at least one action.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {editingPlaybook.actions.map((action, idx) => (
                  <div key={idx} className="flex items-center gap-3 rounded-lg border border-cyber-border bg-cyber-bg p-3">
                    <span className="text-cyber-muted text-xs font-mono w-6">{idx + 1}.</span>
                    <select
                      value={action.type}
                      onChange={(e) => updateAction(idx, 'type', e.target.value)}
                      className="flex-1 rounded border border-cyber-border bg-cyber-surface py-1.5 px-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none"
                    >
                      <option value="log_alert">Log Alert</option>
                      <option value="block_ip">Block IP</option>
                      <option value="isolate_host">Isolate Host</option>
                      <option value="scan_host">Scan Host</option>
                      <option value="notify_soc">Notify SOC</option>
                      <option value="notify_admin">Notify Admin</option>
                    </select>
                    <button onClick={() => removeAction(idx)} className="p-1 rounded text-red-400 hover:bg-red-500/10">
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Save/Cancel */}
          <div className="flex items-center justify-end gap-3">
            <button
              onClick={() => { setActiveTab('view'); setEditingPlaybook(null); }}
              className="rounded-lg border border-cyber-border px-4 py-2 text-sm font-medium text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/50 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={!editingPlaybook.name}
              className="rounded-lg bg-cyber-accent px-6 py-2 text-sm font-semibold text-white hover:bg-cyber-accent/80 transition-colors disabled:opacity-40"
            >
              Save Playbook
            </button>
          </div>
        </div>
      )}

      <ConfirmDialog
        isOpen={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
        onConfirm={handleDelete}
        title="Delete Playbook"
        message="Are you sure you want to delete this playbook? This action cannot be undone."
        confirmLabel="Delete"
      />
    </div>
  );
}
