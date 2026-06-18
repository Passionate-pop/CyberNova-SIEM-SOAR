import { useState, useCallback, useEffect } from 'react';
import { Shield, Clock, Server, Link2, ChevronRight, CheckCircle, AlertTriangle, Loader2 } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Timeline } from '../components/ui/Timeline';
import { Modal } from '../components/ui/Modal';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { useFetch } from '../hooks/useFetch';
import { fetchIncidents, resolveIncident, escalateIncident, exportIncidentReport } from '../services/api';
import type { Incident } from '../types';
import { cn } from '../utils/cn';

export function IncidentsPage() {
  const { data: incidents, loading, refetch } = useFetch(useCallback(() => fetchIncidents(), []));
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [confirmAction, setConfirmAction] = useState<'resolve' | 'escalate' | null>(null);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handleResolve = async () => {
    if (!selectedIncident) return;
    setActionLoading('resolve');
    try {
      await resolveIncident(selectedIncident.incident_id);
      setToast({ message: `Incident ${selectedIncident.incident_id} resolved`, type: 'success' });
      setConfirmAction(null);
      setSelectedIncident(null);
      refetch();
    } catch (e) {
      setToast({ message: `Failed to resolve: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
    } finally {
      setActionLoading(null);
    }
  };

  const handleEscalate = async () => {
    if (!selectedIncident) return;
    setActionLoading('escalate');
    try {
      const result = await escalateIncident(selectedIncident.incident_id);
      setToast({ message: `Incident escalated to level ${result.escalation_level}`, type: 'success' });
      setConfirmAction(null);
      setSelectedIncident(null);
      refetch();
    } catch (e) {
      setToast({ message: `Failed to escalate: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
    } finally {
      setActionLoading(null);
    }
  };

  const handleExport = async () => {
    if (!selectedIncident) return;
    try {
      const blob = await exportIncidentReport(selectedIncident.incident_id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `incident_${selectedIncident.incident_id}.json`;
      a.click();
      window.URL.revokeObjectURL(url);
      setToast({ message: 'Incident report exported', type: 'success' });
    } catch (e) {
      // Fallback: copy incident data to clipboard
      try {
        navigator.clipboard.writeText(JSON.stringify(selectedIncident, null, 2));
        setToast({ message: 'Incident data copied to clipboard', type: 'success' });
      } catch {
        setToast({ message: 'Export failed', type: 'error' });
      }
    }
  };

  if (loading && !incidents) {
    return (
      <div className="space-y-6">
        {/* Card skeletons */}
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-cyber-border bg-cyber-card/80 p-5">
              <div className="mb-3 flex items-center gap-2">
                <div className="animate-pulse h-4 w-20 bg-cyber-border/60 rounded" />
                <div className="animate-pulse h-5 w-16 bg-cyber-border/60 rounded-lg" />
                <div className="animate-pulse h-5 w-14 bg-cyber-border/60 rounded-lg" />
              </div>
              <div className="animate-pulse h-5 w-3/4 bg-cyber-border/60 rounded mb-2" />
              <div className="animate-pulse h-3 w-full bg-cyber-border/40 rounded mb-1" />
              <div className="animate-pulse h-3 w-2/3 bg-cyber-border/40 rounded mb-4" />
              <div className="flex items-center gap-4">
                <div className="animate-pulse h-3 w-28 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-3 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-3 w-24 bg-cyber-border/40 rounded" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }
  if (!incidents) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-amber-500/10 flex items-center justify-center">
        <Shield size={40} className="text-amber-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No Incident Data Available</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        Incidents will be created when security alerts are correlated. Ensure the backend is running.
      </p>
      <button onClick={() => refetch()} className="rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-white hover:bg-cyber-accent/90 transition-colors">
        Retry Connection
      </button>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Incident Cards */}
      <div className="grid gap-4">
        {incidents.length > 0 ? (
          incidents.map((incident) => (
          <Card key={incident.incident_id} noPadding>
            <div
              className="flex items-start justify-between gap-4 p-5 cursor-pointer hover:bg-cyber-accent/5 transition-colors"
              onClick={() => setSelectedIncident(incident)}
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <span className="font-mono text-xs text-cyber-accent">{incident.incident_id}</span>
                  <SeverityBadge severity={incident.severity} />
                  <StatusBadge status={incident.status} />
                </div>
                <h3 className="text-sm font-semibold text-cyber-text">{incident.title}</h3>
                <p className="mt-1 text-xs text-cyber-muted line-clamp-2">{incident.description}</p>

                <div className="mt-3 flex items-center gap-4 flex-wrap text-[10px] text-cyber-muted">
                  <span className="flex items-center gap-1"><Clock size={11} /> {new Date(incident.created_at).toLocaleString()}</span>
                  <span className="flex items-center gap-1"><Link2 size={11} /> {(incident.related_alerts || []).length} alerts</span>
                  <span className="flex items-center gap-1"><Server size={11} /> {(incident.affected_systems || []).join(', ')}</span>
                  <span className="flex items-center gap-1"><Shield size={11} /> {incident.assigned_to}</span>
                </div>
              </div>
              <ChevronRight size={18} className="text-cyber-muted mt-1 shrink-0" />
            </div>

            {/* Attack Chain Bar */}
            <div className="border-t border-cyber-border px-5 py-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted mb-2">Attack Chain</p>
              <div className="flex items-center gap-1 overflow-x-auto">
                {(incident.attack_chain || []).map((step, i) => {
                  const statusColor = step.status === 'completed'
                    ? 'bg-red-500/15 border-red-500/30 text-red-400'
                    : step.status === 'in_progress'
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                    : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400';
                  return (
                    <div key={i} className="flex items-center gap-1 shrink-0">
                      <div className={cn('rounded-md border px-2 py-1 text-[10px] font-medium', statusColor)}>
                        {step.phase}
                      </div>
                      {i < (incident.attack_chain || []).length - 1 && (
                        <ChevronRight size={12} className="text-cyber-border" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </Card>
        ))
        ) : (
          <Card noPadding>
            <div className="flex flex-col items-center justify-center py-20 px-6">
              <div className="flex items-center justify-center w-20 h-20 rounded-full bg-cyber-accent/10 mb-4">
                <Shield size={40} className="text-cyber-accent" />
              </div>
              <h3 className="text-lg font-semibold text-cyber-text mb-2">No Active Incidents</h3>
              <p className="text-sm text-cyber-muted text-center max-w-md">
                All clear! Incidents will be created when security alerts are correlated together.
                The system is actively monitoring your environment.
              </p>
            </div>
          </Card>
        )}
      </div>

      {/* Incident Detail Modal */}
      <Modal
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        title={selectedIncident?.incident_id || ''}
        size="xl"
      >
        {selectedIncident && (
          <div className="space-y-6">
            {/* Header */}
            <div>
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <SeverityBadge severity={selectedIncident.severity} size="md" />
                <StatusBadge status={selectedIncident.status} />
              </div>
              <h3 className="text-lg font-semibold text-cyber-text">{selectedIncident.title}</h3>
              <p className="mt-2 text-sm text-cyber-muted leading-relaxed">{selectedIncident.description}</p>
            </div>

            {/* Meta */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2.5">
                <p className="text-[10px] font-semibold uppercase text-cyber-muted">Assigned To</p>
                <p className="mt-1 text-xs font-medium text-cyber-text">{selectedIncident.assigned_to}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2.5">
                <p className="text-[10px] font-semibold uppercase text-cyber-muted">Created</p>
                <p className="mt-1 text-xs font-mono text-cyber-text">{new Date(selectedIncident.created_at).toLocaleString()}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2.5">
                <p className="text-[10px] font-semibold uppercase text-cyber-muted">Related Alerts</p>
                <p className="mt-1 text-xs font-mono text-cyber-accent">{(selectedIncident.related_alerts || []).join(', ')}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2.5">
                <p className="text-[10px] font-semibold uppercase text-cyber-muted">Systems</p>
                <p className="mt-1 text-xs text-cyber-text">{(selectedIncident.affected_systems || []).join(', ')}</p>
              </div>
            </div>

            {/* Attack Chain */}
            <div>
              <h4 className="text-sm font-semibold text-cyber-text mb-3">Attack Chain (MITRE ATT&CK)</h4>
              <div className="grid gap-2">
                {(selectedIncident.attack_chain || []).map((step, i) => {
                  const statusColor = step.status === 'completed'
                    ? 'border-red-500/30 bg-red-500/5'
                    : step.status === 'in_progress'
                    ? 'border-amber-500/30 bg-amber-500/5'
                    : 'border-emerald-500/30 bg-emerald-500/5';
                  return (
                    <div key={i} className={cn('flex items-center justify-between rounded-lg border px-4 py-2.5', statusColor)}>
                      <div className="flex items-center gap-3">
                        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-border text-[10px] font-bold text-cyber-text">
                          {i + 1}
                        </span>
                        <div>
                          <p className="text-xs font-semibold text-cyber-text">{step.phase}</p>
                          <p className="text-[10px] font-mono text-cyber-muted">{step.technique}</p>
                        </div>
                      </div>
                      <StatusBadge status={step.status} />
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Timeline */}
            <div>
              <h4 className="text-sm font-semibold text-cyber-text mb-4">Investigation Timeline</h4>
              <Timeline events={selectedIncident.timeline || []} />
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3 pt-2 border-t border-cyber-border">
              <button
                onClick={() => setConfirmAction('resolve')}
                disabled={actionLoading === 'resolve'}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {actionLoading === 'resolve' ? <Loader2 size={14} className="animate-spin inline mr-1" /> : <CheckCircle size={14} className="inline mr-1" />}
                Mark Resolved
              </button>
              <button
                onClick={() => setConfirmAction('escalate')}
                disabled={actionLoading === 'escalate'}
                className="rounded-lg border border-cyber-border px-4 py-2 text-xs font-medium text-cyber-text hover:bg-cyber-border/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {actionLoading === 'escalate' ? <Loader2 size={14} className="animate-spin inline mr-1" /> : <AlertTriangle size={14} className="inline mr-1" />}
                Escalate
              </button>
              <button
                onClick={handleExport}
                className="rounded-lg border border-cyber-border px-4 py-2 text-xs font-medium text-cyber-text hover:bg-cyber-border/50 transition-colors"
              >
                Export Report
              </button>
            </div>

            {/* Confirm Action Dialog */}
            <ConfirmDialog
              isOpen={confirmAction === 'resolve' || confirmAction === 'escalate'}
              onClose={() => setConfirmAction(null)}
              onConfirm={confirmAction === 'resolve' ? handleResolve : handleEscalate}
              title={confirmAction === 'resolve' ? 'Resolve Incident' : 'Escalate Incident'}
              message={
                confirmAction === 'resolve'
                  ? 'Are you sure you want to mark this incident as resolved?'
                  : 'Are you sure you want to escalate this incident to the next level?'
              }
              confirmLabel={confirmAction === 'resolve' ? 'Resolve' : 'Escalate'}
              loading={actionLoading === 'resolve' || actionLoading === 'escalate'}
            />
          </div>
        )}
      </Modal>
    </div>
  );
}
