import { useState, useCallback } from 'react';
import { Search, Filter, RefreshCw } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { useFetch } from '../hooks/useFetch';
import { fetchLogs } from '../services/api';
import { Pagination } from '../components/ui/Pagination';

const severityColors: Record<string, string> = {
  info: 'text-blue-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
  debug: 'text-gray-400',
};

export function LogsPage() {
  const { data: logs, loading, refetch } = useFetch(useCallback(() => fetchLogs(), []));
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 50;

  if (loading && !logs) {
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
        {/* Log stream skeleton */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card/80 overflow-hidden">
          <div className="flex items-center gap-3 border-b border-cyber-border px-5 py-3">
            <div className="animate-pulse h-8 w-56 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-8 w-28 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-8 w-20 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-3 w-16 bg-cyber-border/60 rounded" />
          </div>
          <div className="p-5 space-y-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex gap-3">
                <div className="animate-pulse h-3 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-3 w-12 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-3 w-24 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-3 flex-1 bg-cyber-border/40 rounded" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  if (!logs) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-cyan-500/10 flex items-center justify-center">
        <Search size={40} className="text-cyan-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No Log Data Available</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        System logs will appear here once the backend is connected and events are being processed.
        Check that the CyberNova backend is running.
      </p>
      <button onClick={() => refetch()} className="rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-white hover:bg-cyber-accent/90 transition-colors">
        Retry Connection
      </button>
    </div>
  );

  const filtered = logs
    .filter((log) => {
      if (levelFilter !== 'all' && log.level !== levelFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return (
          log.message.toLowerCase().includes(s) ||
          log.source.toLowerCase().includes(s) ||
          log.host.toLowerCase().includes(s)
        );
      }
      return true;
    });

  const totalPages = Math.ceil(filtered.length / itemsPerPage);
  const paginated = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const levelCounts = logs.reduce((acc, log) => {
    acc[log.level] = (acc[log.level] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border bg-cyber-card/50 px-4 py-3 border-cyber-border">
          <p className="text-2xl font-bold text-cyber-text">{logs.length}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Total Logs</p>
        </div>
        {Object.entries(levelCounts).slice(0, 3).map(([level, count]) => (
          <div key={level} className={`rounded-xl border px-4 py-3 ${level === 'error' ? 'bg-red-500/10 border-red-500/30' : level === 'warn' ? 'bg-amber-500/10 border-amber-500/30' : 'bg-blue-500/10 border-blue-500/30'}`}>
            <p className={`text-2xl font-bold ${severityColors[level]}`}>{count}</p>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">{level}</p>
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
              onChange={(e) => { setSearch(e.target.value); setCurrentPage(1); }}
              placeholder="Search logs..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-cyber-muted" />
            <select
              value={levelFilter}
              onChange={(e) => { setLevelFilter(e.target.value); setCurrentPage(1); }}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none appearance-none cursor-pointer"
            >
              <option value="all">All Levels</option>
              <option value="error">Error</option>
              <option value="warn">Warning</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
          </div>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1 px-3 py-2 rounded-lg border border-cyber-border text-xs text-cyber-muted hover:text-cyber-text"
          >
            <RefreshCw size={12} />
            Refresh
          </button>
          <span className="text-xs text-cyber-muted">{filtered.length} logs</span>
        </div>

        {/* Log Stream */}
        <div className="max-h-[600px] overflow-y-auto font-mono text-xs">
          {paginated.map((log) => (
            <div
              key={log.id}
              className="flex items-start gap-3 px-5 py-2 border-b border-cyber-border/30 hover:bg-cyber-accent/5"
            >
              <span className="text-cyber-muted shrink-0">
                {new Date(log.timestamp).toLocaleTimeString()}
              </span>
              <span className={`shrink-0 w-12 capitalize ${severityColors[log.level]}`}>
                {log.level}
              </span>
              <span className="text-cyber-accent shrink-0">[{log.source}]</span>
              <span className="text-cyber-text flex-1">{log.message}</span>
              <span className="text-cyber-muted shrink-0">{log.host}</span>
            </div>
          ))}
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