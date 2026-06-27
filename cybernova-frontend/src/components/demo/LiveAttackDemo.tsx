/**
 * CyberNova — Live Attack Demonstration
 * Full-screen animated overlay that shows attacks being detected in real-time.
 * No actual malware needed — uses the real detection pipeline with simulated events.
 * Perfect for showing the boss how CyberNova catches attacks.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Activity, AlertTriangle, Terminal,
  Globe, Server, Database,
  X, Play, CheckCircle,
  Skull,
} from 'lucide-react';
import { simulateAttack, fetchMetrics } from '../../services/api';

// ── Attack stages for the demo timeline ─────────────────────────────────
const ATTACK_STAGES = [
  {
    id: 'recon',
    label: 'Reconnaissance',
    severity: 'low',
    type: 'Port Scan',
    icon: Activity,
    description: 'Attacker scans network for open ports and services',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    dotColor: 'bg-blue-500',
  },
  {
    id: 'brute',
    label: 'Brute Force',
    severity: 'medium',
    type: 'SSH Brute Force',
    icon: Terminal,
    description: 'Multiple failed SSH login attempts from external IP',
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/10',
    borderColor: 'border-amber-500/30',
    dotColor: 'bg-amber-500',
  },
  {
    id: 'breach',
    label: 'Initial Breach',
    severity: 'high',
    type: 'Authentication Bypass',
    icon: AlertTriangle,
    description: 'Attacker gains access via compromised credentials',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    dotColor: 'bg-orange-500',
  },
  {
    id: 'escalate',
    label: 'Privilege Escalation',
    severity: 'high',
    type: 'Sudo Exploit',
    icon: Skull,
    description: 'Unauthorized sudo execution — attacker escalates to root',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    dotColor: 'bg-red-500',
  },
  {
    id: 'exfil',
    label: 'Data Exfiltration',
    severity: 'critical',
    type: 'DNS Tunneling',
    icon: Database,
    description: 'Massive outbound data transfer to external C2 server',
    color: 'text-red-500',
    bgColor: 'bg-red-500/20',
    borderColor: 'border-red-500/40',
    dotColor: 'bg-red-600',
  },
  {
    id: 'ransom',
    label: 'Ransomware',
    severity: 'critical',
    type: 'File Encryption',
    icon: ShieldX,
    description: 'Known ransomware signature detected — file encryption in progress',
    color: 'text-purple-400',
    bgColor: 'bg-purple-500/20',
    borderColor: 'border-purple-500/40',
    dotColor: 'bg-purple-600',
  },
  {
    id: 'lateral',
    label: 'Lateral Movement',
    severity: 'high',
    type: 'Pass-the-Hash',
    icon: Server,
    description: 'Attacker moves laterally across the network via SMB',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    dotColor: 'bg-orange-500',
  },
  {
    id: 'mitigation',
    label: 'Auto-Mitigation',
    severity: 'blocked',
    type: 'SOAR Response',
    icon: ShieldCheck,
    description: 'CyberNova automatically blocks IPs and isolates affected devices',
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-500/10',
    borderColor: 'border-emerald-500/30',
    dotColor: 'bg-emerald-500',
  },
];

interface DemoAlert {
  id: string;
  stage_id: string;
  severity: string;
  rule_name: string;
  description: string;
  source_ip: string;
  timestamp: string;
}

// ── Props ───────────────────────────────────────────────────────────────
interface LiveAttackDemoProps {
  isOpen: boolean;
  onClose: () => void;
  onAlertsRefetch: () => void;
  onMetricsRefetch: () => void;
}

export function LiveAttackDemo({ isOpen, onClose, onAlertsRefetch, onMetricsRefetch }: LiveAttackDemoProps) {
  const [phase, setPhase] = useState<'idle' | 'running' | 'complete'>('idle');
  const [currentStageIndex, setCurrentStageIndex] = useState(-1);
  const [completedStages, setCompletedStages] = useState<Set<string>>(new Set());
  const [demoAlerts, setDemoAlerts] = useState<DemoAlert[]>([]);
  const [metrics, setMetrics] = useState({ total_alerts: 0, blocked_ips: 0, threats_mitigated: 0, risk_score: 0 });
  const alertLogRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Scroll alert log to bottom ────────────────────────
  useEffect(() => {
    if (alertLogRef.current) {
      alertLogRef.current.scrollTop = alertLogRef.current.scrollHeight;
    }
  }, [demoAlerts]);

  // ── Start demo with countdown ─────────────────────────
  const handleStart = useCallback(async () => {
    setPhase('running');
    setCurrentStageIndex(0);

    // Brief delay before starting
    await new Promise(r => setTimeout(r, 800));

    // Start the backend simulation
    try {
      await simulateAttack();
    } catch (e) {
      console.error('Simulate attack failed:', e);
    }

    // Play through stages with delays
    let stageIdx = 0;
    const playNextStage = () => {
      if (stageIdx >= ATTACK_STAGES.length) {
        setPhase('complete');
        onAlertsRefetch();
        onMetricsRefetch();
        return;
      }

      const stage = ATTACK_STAGES[stageIdx];

      // Add the alert for this stage
      setDemoAlerts(prev => [...prev, {
        id: `demo-${Date.now()}-${stageIdx}`,
        stage_id: stage.id,
        severity: stage.severity,
        rule_name: stage.type,
        description: stage.description,
        source_ip: stageIdx === 0 ? '203.0.113.45' :
                    stageIdx === 1 ? '45.33.32.156' :
                    stageIdx === 2 ? '192.168.1.100' :
                    stageIdx === 3 ? '10.0.0.50' :
                    stageIdx === 4 ? '198.51.100.99' :
                    stageIdx === 5 ? '185.220.101.42' :
                    stageIdx === 6 ? '10.0.0.100' : '203.0.113.45',
        timestamp: new Date().toISOString(),
      }]);

      // Mark stage as completed
      setCompletedStages(prev => new Set(prev).add(stage.id));
      setCurrentStageIndex(stageIdx + 1);

      // Update fake metrics to show progress (these get overridden by real data)
      setMetrics(prev => ({
        total_alerts: prev.total_alerts + 1,
        blocked_ips: stageIdx >= 6 ? prev.blocked_ips + 1 : prev.blocked_ips,
        threats_mitigated: stageIdx >= 6 ? prev.threats_mitigated + 1 : prev.threats_mitigated,
        risk_score: Math.min(100, prev.risk_score + 12),
      }));

      stageIdx++;
      timerRef.current = setTimeout(playNextStage, 2500);
    };

    // Start playing stages after backend simulation is running
    timerRef.current = setTimeout(playNextStage, 1500);

    // Poll real metrics from backend every 3 seconds
    pollRef.current = setInterval(async () => {
      try {
        const m = await fetchMetrics();
        setMetrics(m);
        onMetricsRefetch();
      } catch {}
    }, 3000);

  }, [onAlertsRefetch, onMetricsRefetch]);

  // ── Cleanup on close or unmount ────────────────────────
  const cleanup = useCallback(() => {
    if (timerRef.current) { clearTimeout(timerRef.current); timerRef.current = null; }
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => {
    if (!isOpen) {
      setPhase('idle');
      setCurrentStageIndex(-1);
      setCompletedStages(new Set());
      setDemoAlerts([]);
      setMetrics({ total_alerts: 0, blocked_ips: 0, threats_mitigated: 0, risk_score: 0 });
      cleanup();
    }
    return () => cleanup();
  }, [isOpen, cleanup]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/80 backdrop-blur-sm overflow-hidden">
      {/* Animated grid background */}
      <div className="absolute inset-0 opacity-5">
        <div className="w-full h-full" style={{
          backgroundImage: `linear-gradient(rgba(6, 182, 212, 0.3) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(6, 182, 212, 0.3) 1px, transparent 1px)`,
          backgroundSize: '40px 40px',
        }} />
      </div>

      <div className="relative w-[95vw] max-w-6xl max-h-[90vh] overflow-hidden rounded-2xl border border-cyan-500/30 bg-[#0a0e1a]/95 shadow-2xl shadow-cyan-500/10">
        {/* ── Header ────────────────────────────────────── */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-500/20">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/30 flex items-center justify-center">
              <ShieldAlert size={20} className="text-red-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Live Attack Demonstration</h2>
              <p className="text-xs text-cyan-400/70">
                {phase === 'idle' && 'Simulate a real multi-stage attack through the detection pipeline'}
                {phase === 'running' && `Detecting — Stage ${Math.min(currentStageIndex + 1, ATTACK_STAGES.length)}/${ATTACK_STAGES.length}`}
                {phase === 'complete' && 'All attack stages detected and mitigated'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-white/5 text-gray-500 hover:text-white transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-0 max-h-[calc(90vh-64px)] overflow-y-auto">
          {/* ── LEFT: Attack Timeline ────────────────────── */}
          <div className="lg:col-span-2 p-6 space-y-6 border-r border-cyan-500/10">
            {/* Live status bar */}
            <div className="flex items-center gap-4 p-3 rounded-xl bg-gradient-to-r from-red-500/5 via-cyan-500/5 to-emerald-500/5 border border-cyan-500/10">
              <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${
                  phase === 'idle' ? 'bg-gray-500' :
                  phase === 'running' ? 'bg-red-500 animate-pulse' :
                  'bg-emerald-500'
                }`} />
                <span className="text-sm font-medium text-white">
                  {phase === 'idle' ? 'Ready' : phase === 'running' ? 'Attack In Progress' : 'Attack Contained'}
                </span>
              </div>
              {phase === 'idle' && (
                <span className="text-xs text-gray-500 ml-auto">Press "Start Demo" to begin</span>
              )}
              {phase === 'running' && (
                <span className="text-xs text-cyan-400/70 ml-auto flex items-center gap-1">
                  <Activity size={12} className="animate-spin" />
                  Pipeline processing events
                </span>
              )}
              {phase === 'complete' && (
                <span className="text-xs text-emerald-400 ml-auto flex items-center gap-1">
                  <CheckCircle size={12} />
                  All threats mitigated
                </span>
              )}
            </div>

            {/* Attack Timeline */}
            <div className="space-y-0">
              {ATTACK_STAGES.map((stage, idx) => {
                const isCompleted = completedStages.has(stage.id);
                const isCurrent = currentStageIndex === idx && phase === 'running';
                const isPending = !isCompleted && !isCurrent;

                return (
                  <div key={stage.id} className="flex gap-4">
                    {/* Timeline dot + line */}
                    <div className="flex flex-col items-center">
                      <div className={`
                        w-8 h-8 rounded-xl flex items-center justify-center transition-all duration-500
                        ${isCompleted ? `${stage.bgColor} ${stage.dotColor.replace('bg-', '')} shadow-lg` :
                          isCurrent ? `${stage.bgColor} border-2 ${stage.borderColor} animate-pulse` :
                          'bg-gray-800/50 border border-gray-700/30'}
                      `}>
                        {isCompleted ? (
                          <CheckCircle size={14} className="text-emerald-400" />
                        ) : isCurrent ? (
                          <div className="w-3 h-3 rounded-full bg-cyan-400 animate-ping" />
                        ) : (
                          <div className="w-2 h-2 rounded-full bg-gray-600" />
                        )}
                      </div>
                      {idx < ATTACK_STAGES.length - 1 && (
                        <div className={`w-0.5 h-10 transition-colors duration-700 ${
                          isCompleted ? 'bg-emerald-500/50' :
                          isCurrent ? 'bg-cyan-500/30' :
                          'bg-gray-700/30'
                        }`} />
                      )}
                    </div>

                    {/* Stage content */}
                    <div className={`flex-1 pb-3 transition-all duration-500 ${
                      isPending ? 'opacity-40' : 'opacity-100'
                    }`}>
                      <div className={`p-3 rounded-xl border transition-all duration-500 ${
                        isCompleted ? `${stage.borderColor} ${stage.bgColor}` :
                        isCurrent ? 'border-cyan-500/40 bg-cyan-500/5' :
                        'border-gray-700/30 bg-transparent'
                      }`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <stage.icon size={14} className={isCompleted ? stage.color : isCurrent ? 'text-cyan-400' : 'text-gray-600'} />
                            <span className={`text-sm font-semibold ${isCompleted ? 'text-white' : isCurrent ? 'text-cyan-300' : 'text-gray-500'}`}>
                              {stage.label}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            {isCurrent && (
                              <span className="text-[10px] font-medium text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded-full animate-pulse">
                                DETECTING
                              </span>
                            )}
                            {isCompleted && phase === 'complete' && stage.id === 'mitigation' && (
                              <span className="text-[10px] font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                                CONTAINED
                              </span>
                            )}
                            {isCompleted && phase !== 'complete' && (
                              <span className="text-[10px] font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                                ALERT
                              </span>
                            )}
                          </div>
                        </div>
                        <p className={`text-xs mt-1 ${isCompleted || isCurrent ? 'text-gray-400' : 'text-gray-600'}`}>
                          {stage.description}
                        </p>
                        {isCurrent && (
                          <div className="mt-2 flex items-center gap-2">
                            <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-400 rounded-full animate-progress" style={{ width: '60%' }} />
                            </div>
                            <span className="text-[10px] text-cyan-400/70">Analyzing...</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── RIGHT: Live Alert Feed + Metrics ────────── */}
          <div className="p-6 space-y-4">
            {/* Metrics */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-cyan-500/5 border border-cyan-500/10">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Alerts</p>
                <p className="text-2xl font-bold text-white tabular-nums">
                  {metrics.total_alerts}
                </p>
              </div>
              <div className="p-3 rounded-xl bg-red-500/5 border border-red-500/10">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Risk</p>
                <p className={`text-2xl font-bold tabular-nums ${
                  metrics.risk_score >= 80 ? 'text-red-400' :
                  metrics.risk_score >= 50 ? 'text-amber-400' :
                  'text-emerald-400'
                }`}>
                  {metrics.risk_score}%
                </p>
              </div>
              <div className="p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/10">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Blocked</p>
                <p className="text-2xl font-bold text-white tabular-nums">{metrics.blocked_ips}</p>
              </div>
              <div className="p-3 rounded-xl bg-purple-500/5 border border-purple-500/10">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Mitigated</p>
                <p className="text-2xl font-bold text-white tabular-nums">{metrics.threats_mitigated}</p>
              </div>
            </div>

            {/* Live alert feed */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Activity size={12} className={phase === 'running' ? 'text-red-400 animate-pulse' : 'text-gray-600'} />
                  Live Detection Feed
                </p>
                {phase === 'running' && (
                  <span className="text-[10px] text-cyan-400/70">STREAMING</span>
                )}
              </div>

              <div
                ref={alertLogRef}
                className="space-y-2 max-h-[400px] overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-gray-700"
              >
                {demoAlerts.length === 0 && phase === 'idle' && (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <Shield size={32} className="text-gray-700 mb-3" />
                    <p className="text-sm text-gray-500">No alerts yet</p>
                    <p className="text-xs text-gray-600 mt-1">Click "Start Demo" to simulate an attack</p>
                  </div>
                )}

                {demoAlerts.map((alert) => {
                  const stage = ATTACK_STAGES.find(s => s.id === alert.stage_id);
                  const borderClass = stage?.borderColor || 'border-gray-700/30';
                  return (
                    <div
                      key={alert.id}
                      className={`p-3 rounded-xl border bg-black/30 animate-slide-in ${borderClass}`}
                    >
                      <div className="flex items-start gap-2">
                        <div className={`w-2 h-2 mt-1.5 rounded-full shrink-0 ${
                          alert.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                          alert.severity === 'high' ? 'bg-orange-500' :
                          alert.severity === 'medium' ? 'bg-amber-500' :
                          'bg-blue-500'
                        }`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className={`text-[10px] font-bold uppercase tracking-wider ${
                              alert.severity === 'critical' ? 'text-red-400' :
                              alert.severity === 'high' ? 'text-orange-400' :
                              alert.severity === 'medium' ? 'text-amber-400' :
                              'text-blue-400'
                            }`}>
                              {alert.severity}
                            </span>
                            <span className="text-[10px] font-mono text-cyan-400/70 truncate">
                              {alert.rule_name}
                            </span>
                          </div>
                          <p className="text-xs text-gray-300 mt-0.5 line-clamp-2">{alert.description}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <Globe size={10} className="text-gray-600" />
                            <span className="text-[10px] font-mono text-gray-500">{alert.source_ip}</span>
                            <span className="text-[10px] text-gray-600">
                              {new Date(alert.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}

                {phase === 'complete' && (
                  <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-center">
                    <ShieldCheck size={24} className="mx-auto text-emerald-400 mb-2" />
                    <p className="text-sm font-semibold text-emerald-400">Attack Contained</p>
                    <p className="text-xs text-emerald-400/70 mt-1">
                      All stages detected and mitigated by CyberNova
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ── Footer / Actions ──────────────────────────── */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-cyan-500/10 bg-black/30">
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <Terminal size={12} />
            <span>
              {phase === 'idle' && 'No actual malware used — attacks are simulated through the real detection pipeline'}
              {phase === 'running' && 'Processing through real pipeline: Normalize → Enrich → Detect → Respond'}
              {phase === 'complete' && 'Real pipeline verified — view alerts on the dashboard'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {phase === 'idle' && (
              <button
                onClick={handleStart}
                className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-red-600 to-red-500 text-white text-sm font-semibold hover:from-red-500 hover:to-red-400 transition-all shadow-lg shadow-red-500/25"
              >
                <Play size={16} />
                Start Demo
              </button>
            )}
            {phase === 'running' && (
              <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm">
                <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                Simulating...
              </div>
            )}
            {phase === 'complete' && (
              <div className="flex items-center gap-2">
                <span className="px-3 py-1.5 text-xs text-emerald-400 bg-emerald-500/10 rounded-lg">
                  ✓ Demo complete — {demoAlerts.length} attacks detected
                </span>
                <button
                  onClick={handleStart}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 text-sm font-medium hover:bg-cyan-500/30 transition-colors"
                >
                  <Play size={14} />
                  Replay
                </button>
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-white/5 text-gray-400 text-sm hover:bg-white/10 transition-colors"
                >
                  View Dashboard
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
