import { useState, useEffect } from 'react';
import { Crosshair, ExternalLink, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { useAuthStore } from '../stores/useAuthStore';

interface MitreTechnique {
  id: string;
  name: string;
  tactic_id: string;
  covered: boolean;
  rule_count: number;
  matching_rules: string[];
}

interface MitreTactic {
  id: string;
  name: string;
  description: string;
  total_techniques: number;
  covered_techniques: number;
  coverage_pct: number;
  techniques: MitreTechnique[];
}

const TACTIC_COLORS: Record<string, string> = {
  TA0001: 'bg-red-500/20 border-red-500/40 text-red-300',
  TA0002: 'bg-orange-500/20 border-orange-500/40 text-orange-300',
  TA0003: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
  TA0004: 'bg-amber-500/20 border-amber-500/40 text-amber-300',
  TA0005: 'bg-green-500/20 border-green-500/40 text-green-300',
  TA0006: 'bg-teal-500/20 border-teal-500/40 text-teal-300',
  TA0007: 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300',
  TA0008: 'bg-blue-500/20 border-blue-500/40 text-blue-300',
  TA0009: 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300',
  TA0010: 'bg-purple-500/20 border-purple-500/40 text-purple-300',
  TA0011: 'bg-violet-500/20 border-violet-500/40 text-violet-300',
  TA0040: 'bg-pink-500/20 border-pink-500/40 text-pink-300',
  TA0042: 'bg-rose-500/20 border-rose-500/40 text-rose-300',
  TA0043: 'bg-fuchsia-500/20 border-fuchsia-500/40 text-fuchsia-300',
};

export function MitrePage() {
  const [tactics, setTactics] = useState<MitreTactic[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [summary, setSummary] = useState<{ total_techniques: number; covered: number; coverage_pct: number } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    loadCoverage();
  }, []);

  const loadCoverage = async () => {
    try {
      const token = useAuthStore.getState().token;
      const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      const [coverageRes, summaryRes] = await Promise.allSettled([
        fetch('/api/v1/detect/mitre/coverage', { headers }).then(r => r.json()),
        fetch('/api/v1/detect/mitre/summary', { headers }).then(r => r.json()),
      ]);
      const coverageData = coverageRes.status === 'fulfilled' ? coverageRes.value : {};
      const summaryData = summaryRes.status === 'fulfilled' ? summaryRes.value : null;
      if (coverageRes.status === 'rejected' && summaryRes.status === 'rejected') {
        throw new Error('Both MITRE API calls failed');
      }
      
      // Coverage returns { tactics: { [id]: { name, total, covered, techniques } } }
      const tacticsMap = coverageData.tactics || coverageData;
      const tacticsList: MitreTactic[] = Object.entries(tacticsMap).map(([id, data]: [string, any]) => ({
        id,
        name: data.name || id,
        description: data.description || '',
        total_techniques: data.total || 0,
        covered_techniques: data.covered || 0,
        coverage_pct: data.total > 0 ? Math.round((data.covered / data.total) * 100) : 0,
        techniques: (data.techniques || []).map((t: any) => ({
          id: t.id,
          name: t.name,
          tactic_id: id,
          covered: t.covered || t.rule_count > 0,
          rule_count: t.rule_count || 0,
          matching_rules: t.matching_rules || [],
        })),
      }));
      
      setTactics(tacticsList.sort((a, b) => b.coverage_pct - a.coverage_pct));
      setSummary(summaryData);      } catch (err) {
      console.error('Failed to load MITRE coverage:', err);
      setLoadError('Failed to load MITRE ATT&CK coverage data. The detection API may be unavailable.');
    } finally {
      setLoading(false);
    }
  };

  const totalTechniques = summary?.total_techniques || tactics.reduce((s, t) => s + t.total_techniques, 0);
  const coveredTechniques = summary?.covered || tactics.reduce((s, t) => s + t.covered_techniques, 0);
  const overallCoverage = totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 100) : 0;

  const selected = tactics.find(t => t.id === selectedTactic);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-cyber-muted">Loading MITRE ATT&CK coverage...</span>
        </div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3 text-center max-w-md">
          <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center">
            <XCircle className="text-red-400" size={32} />
          </div>
          <h2 className="text-lg font-semibold text-cyber-text">Unable to Load MITRE Data</h2>
          <p className="text-sm text-cyber-muted">{loadError}</p>
          <button onClick={loadCoverage} className="mt-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 text-sm font-medium hover:bg-cyan-500/30 transition-colors">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-cyber-text flex items-center gap-2">
            <Crosshair className="text-cyan-400" size={28} />
            MITRE ATT&CK Matrix
          </h1>
          <p className="text-sm text-cyber-muted mt-1">Detection coverage across the Enterprise ATT&CK framework</p>
        </div>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-surface border border-cyber-border text-xs text-cyber-muted hover:text-cyber-text transition-colors"
        >
          <ExternalLink size={14} />
          MITRE ATT&CK
        </a>
      </div>

      {/* Overall Coverage Card */}
      <div className="bg-cyber-surface border border-cyber-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-cyber-text">Overall Coverage</h2>
          <span className={`text-3xl font-bold ${overallCoverage >= 70 ? 'text-green-400' : overallCoverage >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
            {overallCoverage}%
          </span>
        </div>
        <div className="w-full h-3 bg-cyber-border rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${overallCoverage >= 70 ? 'bg-gradient-to-r from-green-500 to-emerald-400' : overallCoverage >= 40 ? 'bg-gradient-to-r from-yellow-500 to-amber-400' : 'bg-gradient-to-r from-red-500 to-orange-400'}`}
            style={{ width: `${overallCoverage}%` }}
          />
        </div>
        <div className="flex justify-between mt-2 text-xs text-cyber-muted">
          <span>{coveredTechniques} techniques covered</span>
          <span>{totalTechniques - coveredTechniques} gaps remaining</span>
          <span>{totalTechniques} total techniques</span>
        </div>
      </div>

      {/* Tactics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {tactics.map(tactic => (
          <button
            key={tactic.id}
            onClick={() => setSelectedTactic(selectedTactic === tactic.id ? null : tactic.id)}
            className={`text-left p-4 rounded-xl border transition-all duration-200 hover:scale-[1.02] ${selectedTactic === tactic.id ? 'ring-2 ring-cyan-500/50' : ''} ${TACTIC_COLORS[tactic.id] || 'bg-cyber-surface border-cyber-border text-cyber-text'}`}
          >
            <div className="flex items-start justify-between mb-2">
              <span className="text-xs font-mono opacity-70">{tactic.id}</span>
              {tactic.coverage_pct === 100 ? (
                <CheckCircle size={16} className="text-green-400" />
              ) : tactic.coverage_pct > 0 ? (
                <AlertTriangle size={16} className="text-yellow-400" />
              ) : (
                <XCircle size={16} className="text-red-400 opacity-50" />
              )}
            </div>
            <h3 className="font-semibold text-sm mb-1 leading-tight">{tactic.name}</h3>
            <div className="flex items-center justify-between">
              <span className="text-xs opacity-70">{tactic.covered_techniques}/{tactic.total_techniques} techniques</span>
              <span className={`text-xs font-bold ${tactic.coverage_pct >= 70 ? 'text-green-300' : tactic.coverage_pct > 0 ? 'text-yellow-300' : 'text-red-300 opacity-50'}`}>
                {tactic.coverage_pct}%
              </span>
            </div>
            {/* Mini progress bar */}
            <div className="w-full h-1 bg-black/20 rounded-full mt-2 overflow-hidden">
              <div
                className="h-full rounded-full bg-current opacity-40"
                style={{ width: `${tactic.coverage_pct}%` }}
              />
            </div>
          </button>
        ))}
      </div>

      {/* Expanded Tactic Detail */}
      {selected && (
        <div className="bg-cyber-surface border border-cyber-border rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-bold text-cyber-text">{selected.name}</h3>
              <p className="text-xs text-cyber-muted mt-0.5">{selected.id} — {selected.covered_techniques}/{selected.total_techniques} techniques covered</p>
            </div>
            <button onClick={() => setSelectedTactic(null)} className="text-xs text-cyber-muted hover:text-cyber-text">✕ Close</button>
          </div>
          
          {selected.techniques.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {selected.techniques.map(tech => (
                <div
                  key={tech.id}
                  className={`p-3 rounded-lg border text-sm ${tech.covered ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/20'}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs opacity-60">{tech.id}</span>
                    {tech.covered ? (
                      <CheckCircle size={14} className="text-green-400" />
                    ) : (
                      <XCircle size={14} className="text-red-400 opacity-50" />
                    )}
                  </div>
                  <p className={`font-medium mt-1 ${tech.covered ? 'text-green-300' : 'text-cyber-muted'}`}>{tech.name}</p>
                  {tech.rule_count > 0 && (
                    <p className="text-xs text-cyber-muted mt-1">{tech.rule_count} rule{tech.rule_count !== 1 ? 's' : ''} — {tech.matching_rules.join(', ')}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-cyber-muted">No techniques defined for this tactic yet.</p>
          )}
        </div>
      )}

      {/* Legend */}
      <div className="flex items-center gap-6 text-xs text-cyber-muted">
        <span className="flex items-center gap-1.5"><CheckCircle size={12} className="text-green-400" /> Covered by detection rules</span>
        <span className="flex items-center gap-1.5"><XCircle size={12} className="text-red-400 opacity-50" /> Not covered (detection gap)</span>
        <span className="flex items-center gap-1.5"><AlertTriangle size={12} className="text-yellow-400" /> Partially covered</span>
      </div>
    </div>
  );
}
