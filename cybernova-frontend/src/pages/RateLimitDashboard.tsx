import { useState, useEffect } from 'react';
import { fetchRateLimitStats } from '../services/api';
import { Card } from '../components/ui/Card';
import {
  Activity, AlertTriangle, Shield, Search, Settings,
  Globe, Database, RefreshCw, Clock, Gauge,
} from 'lucide-react';

interface RateLimitStat {
  category: string;
  tenant_id: string;
  limit: number;
  current_count: number;
  blocked_count: number;
  remaining: number;
  utilization_pct: number;
  last_path: string;
  window_start: number;
}

interface RateLimitData {
  stats: RateLimitStat[];
  tier: string;
  tier_limits: Record<string, number>;
  categories: Record<string, { label: string; limit: number; color: string }>;
}

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  dashboard_read: <Activity size={20} />,
  auth: <Shield size={20} />,
  ingestion: <Database size={20} />,
  search: <Search size={20} />,
  admin: <Settings size={20} />,
  default: <Globe size={20} />,
};

function GaugeChart({ pct, color, size = 80 }: { pct: number; color: string; size?: number }) {
  const radius = size / 2 - 8;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(pct, 100) / 100) * circumference;
  const strokeWidth = 6;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700"
        />
      </svg>
      <span className="absolute text-sm font-bold text-white">
        {Math.round(pct)}%
      </span>
    </div>
  );
}

function StatusBadge({ pct }: { pct: number }) {
  if (pct >= 90) return <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">Critical</span>;
  if (pct >= 70) return <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30">Warning</span>;
  if (pct >= 40) return <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">Moderate</span>;
  return <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">Healthy</span>;
}

export function RateLimitDashboard() {
  const [data, setData] = useState<RateLimitData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = async () => {
    try {
      setError(null);
      const result = await fetchRateLimitStats();
      setData(result);
    } catch (err: any) {
      if (err?.response?.status !== 429) {
        setError(err?.response?.data?.error || 'Failed to load rate limit data');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center">
        <AlertTriangle size={32} className="text-red-400 mb-2" />
        <p className="text-red-400 text-sm">{error}</p>
      </div>
    );
  }

  const tierColors: Record<string, string> = {
    free: '#f59e0b',
    pro: '#06b6d4',
    enterprise: '#8b5cf6',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Gauge className="text-cyan-400" />
            Rate Limit Dashboard
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time per-category rate limit utilization
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Tier badge */}
          {data && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border" style={{
              borderColor: `${tierColors[data.tier] || '#6366f1'}40`,
              backgroundColor: `${tierColors[data.tier] || '#6366f1'}15`,
            }}>
              <span className="text-xs font-medium uppercase tracking-wider" style={{
                color: tierColors[data.tier] || '#6366f1',
              }}>
                {data.tier} Plan
              </span>
            </div>
          )}
          {/* Refresh */}
          <button
            onClick={() => { fetchData(); }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-border/50 hover:bg-cyber-border text-xs text-gray-300 transition-colors"
          >
            <RefreshCw size={14} />
            Refresh
          </button>
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
              autoRefresh ? 'bg-cyan-500/20 text-cyan-400' : 'bg-cyber-border/50 text-gray-400'
            }`}
          >
            <Clock size={14} />
            Auto
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-sm flex items-center gap-2">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {(data?.stats?.length ? data.stats : Object.entries(data?.categories || {}).map(([key, cat]) => ({
          category: key,
          limit: cat.limit,
          current_count: 0,
          blocked_count: 0,
          remaining: cat.limit,
          utilization_pct: 0,
          last_path: '',
          window_start: Date.now() / 1000,
          tenant_id: '',
        }))).map((stat) => {
          const catConfig = data?.categories?.[stat.category] || {
            label: stat.category,
            limit: stat.limit,
            color: '#6366f1',
          };

          return (
            <Card key={stat.category} className="hover:border-cyan-500/30 transition-all duration-300">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{
                    backgroundColor: `${catConfig.color}20`,
                    color: catConfig.color,
                  }}>
                    {CATEGORY_ICONS[stat.category] || <Activity size={20} />}
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">{catConfig.label}</h3>
                    <p className="text-xs text-gray-500">{stat.category}</p>
                  </div>
                </div>
                <StatusBadge pct={stat.utilization_pct} />
              </div>

              <div className="flex items-center justify-center mb-4">
                <GaugeChart pct={stat.utilization_pct} color={catConfig.color} size={100} />
              </div>

              <div className="grid grid-cols-3 gap-2 text-center">
                <div>
                  <p className="text-lg font-bold text-white">{stat.current_count}</p>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider">Used</p>
                </div>
                <div>
                  <p className="text-lg font-bold text-white">{stat.remaining}</p>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider">Remaining</p>
                </div>
                <div>
                  <p className="text-lg font-bold text-white">{stat.limit}</p>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider">Limit</p>
                </div>
              </div>

              {stat.blocked_count > 0 && (
                <div className="mt-3 pt-3 border-t border-cyber-border">
                  <div className="flex items-center gap-1.5 text-xs">
                    <AlertTriangle size={12} className="text-red-400" />
                    <span className="text-red-400">{stat.blocked_count} requests blocked</span>
                  </div>
                </div>
              )}

              {stat.last_path && (
                <div className="mt-2">
                  <p className="text-[10px] text-gray-600 truncate font-mono">
                    Last: {stat.last_path}
                  </p>
                </div>
              )}
            </Card>
          );
        })}
      </div>

      {/* Tier Limits Summary */}
      {data?.tier_limits && (
        <Card title="Plan Limits Summary" subtitle="Per-tier rate limit allocation">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {Object.entries(data.tier_limits).map(([key, value]) => (
              <div key={key} className="text-center p-3 rounded-lg bg-cyber-bg/50">
                <p className="text-lg font-bold text-white">{value.toLocaleString()}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider">
                  {key.replace(/_/g, ' ')}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Legend */}
      <Card className="!p-4">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Status Legend</h3>
        <div className="flex flex-wrap gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
            <span className="text-gray-400">Healthy (&lt;40%)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span className="text-gray-400">Moderate (40-70%)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span className="text-gray-400">Warning (70-90%)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span className="text-gray-400">Critical (&gt;90%)</span>
          </div>
        </div>
      </Card>
    </div>
  );
}
