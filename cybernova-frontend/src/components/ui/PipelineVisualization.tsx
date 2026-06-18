import { useEffect, useState } from 'react';
import { ArrowRight, Zap, Shield, Database, Search, AlertTriangle } from 'lucide-react';
import { Card } from './Card';
import { fetchPipelineStatus } from '../../services/api';

interface PipelineStageData {
  key: string;
  label: string;
  icon: typeof Zap;
  countKey: string;
  color: string;
  activeColor: string;
  glowColor: string;
}

const STAGES: PipelineStageData[] = [
  {
    key: 'ingestion',
    label: 'Ingestion',
    icon: Database,
    countKey: 'events_ingested',
    color: 'from-cyan-500/20 to-cyan-500/5',
    activeColor: 'text-cyan-400',
    glowColor: 'shadow-cyan-500/25',
  },
  {
    key: 'normalization',
    label: 'Normalization',
    icon: Shield,
    countKey: 'events_normalized',
    color: 'from-blue-500/20 to-blue-500/5',
    activeColor: 'text-blue-400',
    glowColor: 'shadow-blue-500/25',
  },
  {
    key: 'enrichment',
    label: 'Enrichment',
    icon: Zap,
    countKey: 'events_enriched',
    color: 'from-purple-500/20 to-purple-500/5',
    activeColor: 'text-purple-400',
    glowColor: 'shadow-purple-500/25',
  },
  {
    key: 'detection',
    label: 'Detection',
    icon: Search,
    countKey: 'alerts_created',
    color: 'from-amber-500/20 to-amber-500/5',
    activeColor: 'text-amber-400',
    glowColor: 'shadow-amber-500/25',
  },
  {
    key: 'alerts',
    label: 'Alerts',
    icon: AlertTriangle,
    countKey: 'alerts_created',
    color: 'from-red-500/20 to-red-500/5',
    activeColor: 'text-red-400',
    glowColor: 'shadow-red-500/25',
  },
];

export function PipelineVisualization() {
  const [running, setRunning] = useState(false);
  const [stats, setStats] = useState<Record<string, number>>({
    events_ingested: 0,
    events_normalized: 0,
    events_enriched: 0,
    alerts_created: 0,
  });
  const [lastAlertTime, setLastAlertTime] = useState<string | null>(null);
  const [latency, setLatency] = useState(0);
  const displayLatency = typeof latency === 'number' && !isNaN(latency) ? latency : 0;

  const fetchStatus = async () => {
    try {
      const data = await fetchPipelineStatus();
      setRunning(data.running);
      setStats({
        events_ingested: data.stats.events_ingested,
        events_normalized: data.stats.events_normalized,
        events_enriched: data.stats.events_enriched,
        alerts_created: data.stats.alerts_created,
      });
      setLastAlertTime(data.stats.last_alert_time);
      setLatency(typeof data?.stats?.processing_latency_ms === 'number' ? data.stats.processing_latency_ms : 0);
    } catch {
      // Silently fail — polling will retry
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const hasActivity = Object.values(stats).some(v => v > 0);
  const lastAlertDisplay = lastAlertTime
    ? new Date(lastAlertTime).toLocaleTimeString()
    : '—';

  return (
    <Card title="Real-Time Pipeline" subtitle={`Status: ${running ? 'Active' : 'Idle'} • Latency: ${displayLatency.toFixed(0)}ms`}>
      <div className="space-y-4">
        {/* Pipeline Flow */}
        <div className="flex items-center justify-between gap-2">
          {STAGES.map((stage, i) => {
            const Icon = stage.icon;
            const count = stats[stage.countKey] || 0;
            const isActive = count > 0 && running;

            return (
              <div key={stage.key} className="flex items-center flex-1">
                {/* Stage Block */}
                <div
                  className={`
                    relative flex-1 rounded-xl border p-3 text-center transition-all duration-500
                    ${isActive
                      ? `bg-gradient-to-br ${stage.color} border-current/30 shadow-lg ${stage.glowColor}`
                      : hasActivity
                        ? 'bg-[#111827]/50 border-gray-700/50'
                        : 'bg-[#111827]/30 border-gray-800/30'
                    }
                  `}
                  style={isActive ? { borderColor: 'currentColor' } : {}}
                >
                  {/* Active pulse ring */}
                  {isActive && (
                    <div className={`absolute inset-0 rounded-xl border-2 ${stage.activeColor} animate-ping opacity-20`} />
                  )}

                  <div className="relative z-10">
                    <Icon
                      size={20}
                      className={`mx-auto mb-1.5 transition-colors ${
                        isActive ? stage.activeColor : 'text-gray-600'
                      }`}
                    />
                    <p className={`text-[10px] font-semibold uppercase tracking-wider ${
                      isActive ? stage.activeColor : 'text-gray-500'
                    }`}>
                      {stage.label}
                    </p>
                    <p className={`text-lg font-bold mt-0.5 ${
                      isActive ? 'text-white' : 'text-gray-400'
                    }`}>
                      {count}
                    </p>
                  </div>
                </div>

                {/* Arrow Connector */}
                {i < STAGES.length - 1 && (
                  <div className="flex-shrink-0 px-1">
                    <ArrowRight
                      size={14}
                      className={`transition-colors ${
                        isActive || (i + 1 < STAGES.length && (stats[STAGES[i + 1].countKey] || 0) > 0)
                          ? 'text-gray-400'
                          : 'text-gray-700'
                      }`}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Bottom Stats Bar */}
        <div className="flex items-center justify-between pt-2 border-t border-gray-800/50">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${running ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
              <span className="text-[10px] text-gray-500 uppercase tracking-wider">
                {running ? 'Processing' : 'Idle'}
              </span>
            </div>
            <span className="text-[10px] text-gray-600">|</span>
            <span className="text-[10px] text-gray-500">
              Last alert: {lastAlertDisplay}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-gray-500">
              Queue depth: {stats.events_ingested - stats.events_normalized} pending
            </span>
          </div>
        </div>
      </div>
    </Card>
  );
}
