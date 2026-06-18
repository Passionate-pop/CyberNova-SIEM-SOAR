/**
 * CyberNova - Analytics Dashboard with Insights & Drill-down
 * Decision engine for product improvement
 */
import { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle, X,
  Clock, Zap, ChevronRight, 
  CheckCircle, XCircle, RefreshCw, User, Timer, ChevronLeft, Users
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { useAuthStore } from '../stores/useAuthStore';

interface Insight {
  id: string;
  type: 'activation_drop' | 'step_drop' | 'slow_ttfd';
  severity: 'high' | 'medium' | 'low';
  message: string;
  action: string;
  created_at?: string;
}

interface DrillDownData {
  title: string;
  filters: Record<string, string>;
  step: string;
}

interface SessionEvent {
  event_id: string;
  event_name: string;
  category: string;
  timestamp: string;
  time_offset_seconds: number;
  metadata: Record<string, any>;
}

interface UserStuck {
  user_id: string;
  last_event: string;
  time_spent_seconds: number;
}

const EVENT_LABELS: Record<string, string> = {
  signup_completed: 'Signup Completed',
  org_created: 'Organization Created',
  org_key_viewed: 'ORG_KEY Viewed',
  command_copied: 'Command Copied',
  agent_started: 'Agent Started',
  device_connected: 'Device Connected',
};

function InsightBadge({ insight, onClick }: { insight: Insight; onClick: () => void }) {
  const icons: Record<string, React.ReactNode> = {
    activation_drop: <AlertTriangle size={14} />,
    step_drop: <XCircle size={14} />,
    slow_ttfd: <Clock size={14} />,
  };
  
  const colors: Record<string, string> = {
    high: 'bg-red-500/20 text-red-400 border-red-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };

  return (
    <div 
      onClick={onClick}
      className={`flex items-start gap-3 p-3 rounded-lg border ${colors[insight.severity]} cursor-pointer hover:opacity-80 transition-opacity`}
    >
      <div className="mt-0.5">{icons[insight.type]}</div>
      <div className="flex-1">
        <p className="text-sm text-white">{insight.message}</p>
        {insight.action && (
          <p className="text-xs text-white/60 mt-1">Action: {insight.action}</p>
        )}
      </div>
      <ChevronRight size={16} className="text-white/40 mt-0.5" />
    </div>
  );
}

function SessionTimelineModal({ 
  isOpen, 
  onClose, 
  userId,
  apiBase 
}: { 
  isOpen: boolean; 
  onClose: () => void; 
  userId: string | null;
  apiBase: string;
}) {
  const [events, setEvents] = useState<SessionEvent[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen || !userId) return;
    
    const fetchTimeline = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${apiBase}/api/v1/analytics/session/${userId}`, {
          headers: { Authorization: `Bearer ${useAuthStore.getState().token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setEvents(data.timeline || []);
        }
      } catch (e) {
        console.error('Failed to fetch session timeline:', e);
      }
      setLoading(false);
    };

    fetchTimeline();
  }, [isOpen, userId, apiBase]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-3xl bg-cyber-card border border-cyber-border rounded-xl shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-cyber-border">
          <div className="flex items-center gap-3">
            <button onClick={onClose} className="p-1 hover:bg-cyber-border/50 rounded">
              <ChevronLeft size={20} className="text-white" />
            </button>
            <div>
              <h3 className="text-lg font-semibold text-white">User Session Timeline</h3>
              <p className="text-sm text-cyber-muted">User ID: {userId}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-cyber-border/50">
            <X size={20} className="text-white" />
          </button>
        </div>

        <div className="p-4 max-h-96 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw size={24} className="animate-spin text-cyan-400" />
            </div>
          ) : events.length === 0 ? (
            <div className="text-center py-8 text-cyber-muted">
              No events recorded for this user
            </div>
          ) : (
            <div className="space-y-0">
              {events.map((event, i) => (
                <div key={event.event_id} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className={`w-3 h-3 rounded-full ${
                      i === 0 ? 'bg-green-400' : i === events.length - 1 ? 'bg-cyan-400' : 'bg-cyber-border'
                    }`} />
                    {i < events.length - 1 && (
                      <div className="w-0.5 h-12 bg-cyber-border/50" />
                    )}
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white">
                        {EVENT_LABELS[event.event_name] || event.event_name}
                      </span>
                      <span className="text-xs text-cyber-muted">+{event.time_offset_seconds}s</span>
                    </div>
                    <p className="text-xs text-cyber-muted mt-0.5">
                      {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '—'}
                    </p>
                    {Object.keys(event.metadata || {}).length > 0 && (
                      <p className="text-xs text-cyber-muted/70 mt-1">
                        {JSON.stringify(event.metadata)}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end p-4 border-t border-cyber-border">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-cyber-border text-white hover:bg-cyber-border/30"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function DrillDownModal({ 
  isOpen, 
  onClose, 
  data,
  apiBase,
  onViewUsers
}: { 
  isOpen: boolean; 
  onClose: () => void; 
  data: DrillDownData | null;
  apiBase: string;
  onViewUsers: (userId: string) => void;
}) {
  const [users, setUsers] = useState<UserStuck[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen || !data?.step) return;
    
    const fetchUsers = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${apiBase}/api/v1/analytics/users-stuck?step=${data.step}`, {
          headers: { Authorization: `Bearer ${useAuthStore.getState().token}` },
        });
        if (res.ok) {
          const result = await res.json();
          setUsers(result.users_stuck || []);
        }
      } catch (e) {
        console.error('Failed to fetch users stuck:', e);
      }
      setLoading(false);
    };

    fetchUsers();
  }, [isOpen, data, apiBase]);

  if (!isOpen || !data) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-cyber-card border border-cyber-border rounded-xl shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-cyber-border">
          <div>
            <h3 className="text-lg font-semibold text-white">{data.title}</h3>
            <p className="text-sm text-cyber-muted">{users.length} users stuck at this step</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-cyber-border/50">
            <X size={20} className="text-white" />
          </button>
        </div>

        <div className="p-4 max-h-96 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw size={24} className="animate-spin text-cyan-400" />
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-8 text-cyber-muted">
              No users stuck at this step
            </div>
          ) : (
            <div className="space-y-2">
              {users.map((user) => (
                <div 
                  key={user.user_id}
                  onClick={() => onViewUsers(user.user_id)}
                  className="flex items-center justify-between p-3 bg-cyber-bg rounded-lg hover:bg-cyber-border/30 cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center">
                      <User size={14} className="text-cyan-400" />
                    </div>
                    <div>
                      <p className="text-sm text-white font-mono">{user.user_id.slice(0, 8)}...</p>
                      <p className="text-xs text-cyber-muted">
                        Last event: {EVENT_LABELS[user.last_event] || user.last_event}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-cyber-muted">
                    <Timer size={14} />
                    <span className="text-sm">{user.time_spent_seconds}s</span>
                    <ChevronRight size={14} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 p-4 border-t border-cyber-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-cyber-border text-white hover:bg-cyber-border/30">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function NextActionCard({ insights }: { insights: Insight[] }) {
  const critical = insights.find(i => i.severity === 'high') || insights[0];

  return (
    <Card className="p-6 bg-gradient-to-br from-cyber-card to-cyber-bg">
      <h3 className="text-lg font-semibold text-white mb-4">Next Action</h3>
      
      {critical ? (
        <div className="space-y-4">
          <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
            <div className="flex items-start gap-2">
              <AlertTriangle size={18} className="text-red-400 mt-0.5" />
              <div>
                <p className="text-sm text-white">{critical.message}</p>
                {critical.action && (
                  <p className="text-xs text-red-400/70 mt-1">{critical.action}</p>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
          <div className="flex items-center gap-2">
            <CheckCircle size={18} className="text-green-400" />
            <p className="text-sm text-green-400">All metrics looking good!</p>
          </div>
        </div>
      )}
    </Card>
  );
}

export function AnalyticsDashboardWithInsights() {
  // Use same-origin API path through nginx proxy (empty = relative /api/... paths)
  // In dev mode with Vite, the proxy config in vite.config.ts handles forwarding
  const apiBase = import.meta.env.VITE_API_URL || '';
  const token = useAuthStore(s => s.token);
  
  const [viewMode, setViewMode] = useState<'live' | 'aggregated'>('live');
  const [insights, setInsights] = useState<Insight[]>([]);
  const [funnelData, setFunnelData] = useState<{ step: string; count: number }[]>([]);
  const [funnelLoading, setFunnelLoading] = useState(false);
  const [drillDown, setDrillDown] = useState<DrillDownData | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [showTimeline, setShowTimeline] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchInsights = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/analytics/insights`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setInsights(data.insights || []);
      }
    } catch (e) {
      console.error('Failed to fetch insights:', e);
    }
  }, [apiBase, token]);

  const fetchFunnel = useCallback(async () => {
    setFunnelLoading(true);
    try {
      const res = await fetch(`${apiBase}/api/v1/analytics/funnel?days=30`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        const funnel = data.funnel || {};
        setFunnelData(
          Object.entries(funnel).map(([step, count]) => ({
            step: EVENT_LABELS[step] || step,
            count: count as number,
          }))
        );
      }
    } catch (e) {
      console.error('Failed to fetch funnel:', e);
    }
    setFunnelLoading(false);
  }, [apiBase, token]);

  useEffect(() => {
    fetchInsights();
    fetchFunnel();
  }, [fetchInsights, fetchFunnel]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    Promise.all([
      fetchInsights(),
      fetchFunnel(),
      fetch(apiBase + '/api/v1/analytics/insights/generate', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }),
    ]).finally(() => setIsRefreshing(false));
  };

  const handleInsightClick = (insight: Insight) => {
    const stepMap: Record<string, string> = {
      activation_drop: 'device_connected',
      step_drop: 'agent_started',
      slow_ttfd: 'device_connected',
    };

    const titleMap: Record<string, string> = {
      activation_drop: 'Activation Drop Analysis',
      step_drop: 'Step Drop Analysis',
      slow_ttfd: 'TTFD Analysis',
    };

    const step = stepMap[insight.type] || 'agent_started';
    setDrillDown({
      title: titleMap[insight.type] || 'Analysis',
      filters: { type: insight.type },
      step,
    });
  };

  const handleViewUserTimeline = (userId: string) => {
    setSelectedUserId(userId);
    setShowTimeline(true);
    setDrillDown(null);
  };

  return (
    <div className="min-h-screen bg-cyber-bg">
      <div className="sticky top-0 z-40 bg-cyber-card border-b border-cyber-border px-6 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-semibold text-white">Analytics Dashboard</h1>
            
            <div className="flex items-center gap-1 bg-cyber-bg rounded-lg p-1">
              <button
                onClick={() => setViewMode('live')}
                className={`px-3 py-1.5 rounded text-sm ${viewMode === 'live' ? 'bg-cyan-600 text-white' : 'text-cyber-muted hover:text-white'}`}
              >
                Live
              </button>
              <button
                onClick={() => setViewMode('aggregated')}
                className={`px-3 py-1.5 rounded text-sm ${viewMode === 'aggregated' ? 'bg-cyan-600 text-white' : 'text-cyber-muted hover:text-white'}`}
              >
                Aggregated
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={handleRefresh} disabled={isRefreshing} className="p-2 rounded-lg border border-cyber-border hover:bg-cyber-border/30 disabled:opacity-50">
              <RefreshCw size={18} className={`text-white ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <span className="text-xs text-cyber-muted">Updated: {new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Zap size={16} className="text-yellow-400" />
            <span className="text-sm font-medium text-white">Insights & Alerts</span>
          </div>
          {insights.length === 0 ? (
            <Card className="p-4 text-center text-cyber-muted">
              <p>No insights generated yet. Click refresh to run the insight engine.</p>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-2">
              {insights.map(insight => (
                <InsightBadge key={insight.id} insight={insight} onClick={() => handleInsightClick(insight)} />
              ))}
            </div>
          )}
        </div>

        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <Card title="Onboarding Funnel" subtitle="User conversion across setup steps (last 30 days)">
              {funnelLoading ? (
                <LoadingSpinner />
              ) : funnelData.length > 0 ? (
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={funnelData} layout="vertical" margin={{ left: 100, right: 20 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} />
                      <YAxis type="category" dataKey="step" tick={{ fontSize: 11, fill: '#64748b' }} width={90} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e293b', borderRadius: '8px', fontSize: 12 }}
                        labelStyle={{ color: '#e2e8f0' }}
                      />
                      <Bar dataKey="count" fill="#06b6d4" radius={[0, 6, 6, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-48 text-center">
                  <Users size={32} className="text-cyber-muted mb-3" />
                  <p className="text-sm text-cyber-text">No funnel data yet</p>
                  <p className="text-xs text-cyber-muted mt-1">Funnel metrics will appear as users complete onboarding steps</p>
                </div>
              )}
            </Card>
          </div>
          <NextActionCard insights={insights} />
        </div>
      </div>

      <DrillDownModal 
        isOpen={!!drillDown} 
        onClose={() => setDrillDown(null)} 
        data={drillDown}
        apiBase={apiBase}
        onViewUsers={handleViewUserTimeline}
      />

      <SessionTimelineModal
        isOpen={showTimeline}
        onClose={() => { setShowTimeline(false); setSelectedUserId(null); }}
        userId={selectedUserId}
        apiBase={apiBase}
      />
    </div>
  );
}