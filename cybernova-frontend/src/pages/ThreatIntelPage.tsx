import { useState, useCallback, useMemo } from 'react';
import { Globe, Search, AlertTriangle, ExternalLink, MapPin, Tag, Database, Activity } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { useFetch } from '../hooks/useFetch';
import { fetchThreatIntel, fetchGlobalFeed } from '../services/api';
import { cn } from '../utils/cn';

type Tab = 'indicators' | 'global-feed';

const typeColors: Record<string, string> = {
  ip: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  domain: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  hash: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  url: 'bg-red-500/15 text-red-400 border-red-500/30',
};

export function ThreatIntelPage() {
  const { data: indicators, loading: indLoading, error: indError } = useFetch(useCallback(() => fetchThreatIntel(), []));
  const { data: globalFeed, loading: feedLoading } = useFetch(useCallback(() => fetchGlobalFeed(), []));
  const [tab, setTab] = useState<Tab>('indicators');
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const filteredIndicators = useMemo(() => {
    if (!indicators) return [];
    try {
      return indicators.filter((ind) => {
        if (!ind) return false;
        if (typeFilter !== 'all' && ind.type !== typeFilter) return false;
        if (!search) return true;
        const s = search.toLowerCase();
        const indicator = (ind.indicator || '').toLowerCase();
        const description = (ind.description || '').toLowerCase();
        const tags = Array.isArray(ind.tags) ? ind.tags : [];
        return indicator.includes(s) || description.includes(s) || tags.some(t => t && t.toLowerCase().includes(s));
      });
    } catch {
      console.warn('Failed to filter threat indicators', search, typeFilter);
      return indicators;
    }
  }, [indicators, search, typeFilter]);

  if (indError && (!indicators || indicators.length === 0)) {
    return (
      <div className="space-y-6">
        <Card noPadding>
          <div className="flex flex-col items-center justify-center py-20 px-6">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-red-500/10 mb-4">
              <AlertTriangle size={32} className="text-red-400" />
            </div>
            <p className="text-sm font-medium text-cyber-text mb-1">Unable to fetch threat data</p>
            <p className="text-xs text-cyber-muted text-center">{indError}</p>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1 rounded-xl border border-cyber-border bg-cyber-card/50 p-1">
          <button
            onClick={() => setTab('indicators')}
            className={cn(
              'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium transition-all',
              tab === 'indicators' ? 'bg-cyber-accent/15 text-cyber-accent' : 'text-cyber-muted hover:text-cyber-text'
            )}
          >
            <AlertTriangle size={14} />
            Threat Indicators
          </button>
          <button
            onClick={() => setTab('global-feed')}
            className={cn(
              'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium transition-all',
              tab === 'global-feed' ? 'bg-cyber-accent/15 text-cyber-accent' : 'text-cyber-muted hover:text-cyber-text'
            )}
          >
            <Globe size={14} />
            Global Feed
          </button>
        </div>
      </div>

      {/* Indicators Tab */}
      {tab === 'indicators' && (
        <>
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search indicators, tags, descriptions..."
                className="w-full rounded-lg border border-cyber-border bg-cyber-card py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-1">
              {['all', 'ip', 'domain', 'hash', 'url'].map((type) => (
                <button
                  key={type}
                  onClick={() => setTypeFilter(type)}
                  className={cn(
                    'rounded-lg px-3 py-1.5 text-xs font-medium transition-all',
                    typeFilter === type ? 'bg-cyber-accent/15 text-cyber-accent' : 'text-cyber-muted hover:text-cyber-text'
                  )}
                >
                  {type.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Indicator Cards */}
          {indLoading ? (
            <LoadingSpinner />
          ) : filteredIndicators && filteredIndicators.length > 0 ? (
            <div className="grid gap-3">
              {filteredIndicators.map((ind) => (
                <Card key={ind.id} noPadding>
                  <div className="flex items-start justify-between gap-4 p-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase', typeColors[ind.type])}>
                          {ind.type}
                        </span>
                        <code className="font-mono text-sm font-semibold text-cyber-text">{ind.indicator}</code>
                        {ind.country && (
                          <span className="flex items-center gap-1 text-[10px] text-cyber-muted">
                            <MapPin size={10} /> {ind.country}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-cyber-muted">{ind.description}</p>
                      <div className="mt-2 flex items-center gap-2 flex-wrap">
                        {ind.tags.map((tag) => (
                          <span key={tag} className="flex items-center gap-1 rounded-full bg-cyber-border/60 px-2 py-0.5 text-[10px] text-cyber-muted">
                            <Tag size={8} /> {tag}
                          </span>
                        ))}
                      </div>
                      <p className="mt-2 text-[10px] text-cyber-muted/60">
                        Source: {ind.source} · Last seen: {new Date(ind.last_seen).toLocaleString()}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      <div className={cn(
                        'text-2xl font-bold',
                        ind.risk_score >= 80 ? 'text-red-400' :
                        ind.risk_score >= 60 ? 'text-orange-400' :
                        ind.risk_score >= 40 ? 'text-amber-400' :
                        'text-blue-400'
                      )}>
                        {ind.risk_score}
                      </div>
                      <p className="text-[10px] text-cyber-muted uppercase">Risk Score</p>
                      {/* Risk bar */}
                      <div className="mt-2 h-1.5 w-20 rounded-full bg-cyber-border overflow-hidden">
                        <div
                          className={cn(
                            'h-full rounded-full',
                            ind.risk_score >= 80 ? 'bg-red-500' :
                            ind.risk_score >= 60 ? 'bg-orange-500' :
                            ind.risk_score >= 40 ? 'bg-amber-500' :
                            'bg-blue-500'
                          )}
                          style={{ width: `${ind.risk_score}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <Card noPadding>
              <div className="flex flex-col items-center justify-center py-20 px-6">
                <div className="flex items-center justify-center w-16 h-16 rounded-full bg-red-500/10 mb-4">
                  <Database size={32} className="text-red-400" />
                </div>
                <p className="text-sm font-medium text-cyber-text mb-1">No threat indicators</p>
                <p className="text-xs text-cyber-muted text-center">Threat indicators from VirusTotal, AbuseIPDB, and OTX will appear here.
                <br /><span className="text-cyber-accent">Go to Dashboard → Seed Demo Data to populate the system.</span></p>
              </div>
            </Card>
          )}
        </>
      )}

      {/* Global Feed Tab */}
      {tab === 'global-feed' && (
        <>
          {feedLoading ? (
            <LoadingSpinner />
          ) : globalFeed && globalFeed.length > 0 ? (
            <div className="grid gap-4">
              {globalFeed.map((item) => (
                <Card key={item.id} noPadding>
                  <div className="p-5">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <SeverityBadge severity={item.severity} size="md" />
                          <span className="rounded-full bg-cyber-border px-2 py-0.5 text-[10px] font-medium text-cyber-muted">
                            {item.source}
                          </span>
                        </div>
                        <h3 className="text-sm font-semibold text-cyber-text">{item.title}</h3>
                        <p className="mt-2 text-xs text-cyber-muted leading-relaxed">{item.description}</p>
                      </div>
                      <ExternalLink size={16} className="text-cyber-muted shrink-0 mt-1" />
                    </div>

                    <div className="mt-4 border-t border-cyber-border pt-3">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted mb-2">
                        Indicators of Compromise ({item.iocs.length})
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {item.iocs.map((ioc) => (
                          <code key={ioc} className="rounded-md border border-cyber-border bg-cyber-bg/50 px-2 py-1 text-[11px] font-mono text-cyber-accent">
                            {ioc}
                          </code>
                        ))}
                      </div>
                    </div>

                    <p className="mt-3 text-[10px] text-cyber-muted/60">
                      Published: {new Date(item.published_at).toLocaleString()}
                    </p>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <Card noPadding>
              <div className="flex flex-col items-center justify-center py-20 px-6">
                <div className="flex items-center justify-center w-16 h-16 rounded-full bg-green-500/10 mb-4">
                  <Activity size={32} className="text-green-400" />
                </div>
                <p className="text-sm font-medium text-cyber-text mb-1">No global threat feed</p>
                <p className="text-xs text-cyber-muted text-center">Global threat intelligence feed will be displayed here</p>
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
