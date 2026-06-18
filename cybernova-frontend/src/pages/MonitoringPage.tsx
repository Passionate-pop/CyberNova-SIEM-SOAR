import { useState, useCallback } from 'react';
import { Terminal, Network, Cpu, RefreshCw, Pause, Play } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { usePolling } from '../hooks/usePolling';
import { fetchLogs, fetchConnections, fetchProcesses } from '../services/api';
import { cn } from '../utils/cn';

type Tab = 'logs' | 'network' | 'processes';

const levelColors: Record<string, string> = {
  info: 'text-blue-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
  debug: 'text-cyber-muted',
};

export function MonitoringPage() {
  const [tab, setTab] = useState<Tab>('logs');
  const [paused, setPaused] = useState(false);
  const [logFilter, setLogFilter] = useState('');

  const { data: logs, loading: logsLoading, refetch: refetchLogs } = usePolling(
    useCallback(() => fetchLogs(), []),
    5000,
    tab === 'logs' && !paused
  );
  const { data: connections, loading: connLoading } = usePolling(
    useCallback(() => fetchConnections(), []),
    5000,
    tab === 'network' && !paused
  );
  const { data: processes, loading: procLoading } = usePolling(
    useCallback(() => fetchProcesses(), []),
    5000,
    tab === 'processes' && !paused
  );

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'logs', label: 'System Logs', icon: <Terminal size={16} /> },
    { id: 'network', label: 'Network', icon: <Network size={16} /> },
    { id: 'processes', label: 'Processes', icon: <Cpu size={16} /> },
  ];

  const filteredLogs = logs?.filter((l) => {
    if (!logFilter) return true;
    const s = logFilter.toLowerCase();
    return l.message.toLowerCase().includes(s) || l.source.toLowerCase().includes(s) || l.host.toLowerCase().includes(s);
  });

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 rounded-xl border border-cyber-border bg-cyber-card/50 p-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium transition-all',
                tab === t.id
                  ? 'bg-cyber-accent/15 text-cyber-accent'
                  : 'text-cyber-muted hover:text-cyber-text'
              )}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(!paused)}
            className={cn(
              'flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
              paused ? 'border-amber-500/30 text-amber-400 bg-amber-500/10' : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
            )}
          >
            {paused ? <Play size={12} /> : <Pause size={12} />}
            {paused ? 'Resume' : 'Live'}
          </button>
          <button
            onClick={refetchLogs}
            className="rounded-lg border border-cyber-border p-1.5 text-cyber-muted hover:text-cyber-text transition-colors"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* System Logs Tab */}
      {tab === 'logs' && (
        <Card
          title="System Log Stream"
          subtitle="Lake-2 — Real-time data ingestion"
          action={
            <input
              type="text"
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              placeholder="Filter logs..."
              className="w-48 rounded-lg border border-cyber-border bg-cyber-bg px-3 py-1.5 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          }
          noPadding
        >
          {logsLoading ? (
            <LoadingSpinner size="sm" />
          ) : filteredLogs && filteredLogs.length > 0 ? (
            <div className="max-h-[600px] overflow-y-auto font-mono text-xs">
              {filteredLogs.map((log) => (
                <div
                  key={log.id}
                  className="flex items-start gap-3 border-b border-cyber-border/30 px-5 py-2 hover:bg-cyber-accent/5 transition-colors"
                >
                  <span className="shrink-0 text-[10px] text-cyber-muted/60 w-[150px]">
                    {new Date(log.timestamp).toLocaleTimeString()}.{new Date(log.timestamp).getMilliseconds()}
                  </span>
                  <span className={cn('shrink-0 w-[40px] uppercase font-bold text-[10px]', levelColors[log.level])}>
                    {log.level}
                  </span>
                  <span className="shrink-0 w-[80px] text-cyber-accent/70">{log.source}</span>
                  <span className="shrink-0 w-[90px] text-cyber-muted">{log.host}</span>
                  <span className="text-cyber-text min-w-0 flex-1">{log.message}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 px-6">
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyan-500/10 mb-4">
                <Terminal size={32} className="text-cyan-400" />
              </div>
              <p className="text-sm font-medium text-cyber-text mb-1">No system logs</p>
              <p className="text-xs text-cyber-muted text-center">System logs will appear here as events are processed.
              <br /><span className="text-cyber-accent">Go to Dashboard → Seed Demo Data to populate the system.</span></p>
            </div>
          )}
        </Card>
      )}

      {/* Network Tab */}
      {tab === 'network' && (
        <Card title="Network Connections" subtitle="Active and recent connections" noPadding>
          {connLoading ? (
            <LoadingSpinner size="sm" />
          ) : connections && connections.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyber-border">
                    {['Source', 'Destination', 'Protocol', 'Port', 'Status', 'Sent', 'Received'].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {connections.map((conn) => (
                    <tr key={conn.id} className="border-b border-cyber-border/30 hover:bg-cyber-accent/5 transition-colors">
                      <td className="px-4 py-2 font-mono text-cyber-text">{conn.source_ip}</td>
                      <td className="px-4 py-2 font-mono text-cyber-text">{conn.destination_ip}</td>
                      <td className="px-4 py-2">
                        <span className="rounded bg-cyber-border px-1.5 py-0.5 text-[10px] font-bold text-cyber-text">
                          {conn.protocol}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-cyber-muted">{conn.port}</td>
                      <td className="px-4 py-2"><StatusBadge status={conn.status} /></td>
                      <td className="px-4 py-2 font-mono text-cyber-muted">{typeof conn.bytes_sent === 'number' ? (conn.bytes_sent / 1024).toFixed(1) : '0.0'} KB</td>
                      <td className="px-4 py-2 font-mono text-cyber-muted">{typeof conn.bytes_received === 'number' ? (conn.bytes_received / 1024).toFixed(1) : '0.0'} KB</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 px-6">
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-purple-500/10 mb-4">
                <Network size={32} className="text-purple-400" />
              </div>
              <p className="text-sm font-medium text-cyber-text mb-1">No network connections</p>
              <p className="text-xs text-cyber-muted text-center">Network activity will be displayed here</p>
            </div>
          )}
        </Card>
      )}

      {/* Processes Tab */}
      {tab === 'processes' && (
        <Card title="Running Processes" subtitle="Monitored host processes" noPadding>
          {procLoading ? (
            <LoadingSpinner size="sm" />
          ) : processes && processes.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyber-border">
                    {['PID', 'Name', 'User', 'CPU %', 'Memory %', 'Status', 'Risk Score'].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {processes.sort((a, b) => b.risk_score - a.risk_score).map((proc) => (
                    <tr key={proc.pid} className="border-b border-cyber-border/30 hover:bg-cyber-accent/5 transition-colors">
                      <td className="px-4 py-2 font-mono text-cyber-accent">{proc.pid}</td>
                      <td className="px-4 py-2 font-medium text-cyber-text">{proc.name}</td>
                      <td className="px-4 py-2 text-cyber-muted">{proc.user}</td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 rounded-full bg-cyber-border overflow-hidden">
                            <div
                              className={cn('h-full rounded-full', proc.cpu > 80 ? 'bg-red-500' : proc.cpu > 50 ? 'bg-amber-500' : 'bg-cyan-500')}
                              style={{ width: `${Math.min(proc.cpu, 100)}%` }}
                            />
                          </div>
                          <span className="text-cyber-muted">{proc.cpu}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 rounded-full bg-cyber-border overflow-hidden">
                            <div
                              className={cn('h-full rounded-full', proc.memory > 30 ? 'bg-red-500' : proc.memory > 15 ? 'bg-amber-500' : 'bg-purple-500')}
                              style={{ width: `${Math.min(proc.memory * 2.5, 100)}%` }}
                            />
                          </div>
                          <span className="text-cyber-muted">{proc.memory}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-2"><StatusBadge status={proc.status} /></td>
                      <td className="px-4 py-2">
                        <span className={cn(
                          'inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold',
                          proc.risk_score >= 75 ? 'bg-red-500/15 text-red-400' :
                          proc.risk_score >= 50 ? 'bg-amber-500/15 text-amber-400' :
                          proc.risk_score >= 25 ? 'bg-blue-500/15 text-blue-400' :
                          'bg-emerald-500/15 text-emerald-400'
                        )}>
                          {proc.risk_score}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 px-6">
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-orange-500/10 mb-4">
                <Cpu size={32} className="text-orange-400" />
              </div>
              <p className="text-sm font-medium text-cyber-text mb-1">No processes monitored</p>
              <p className="text-xs text-cyber-muted text-center">Process monitoring will display running processes</p>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
