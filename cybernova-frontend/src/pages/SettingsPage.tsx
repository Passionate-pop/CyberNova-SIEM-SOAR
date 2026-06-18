import { useState, useCallback, useEffect } from 'react';
import { Save, RotateCcw, Gauge, Shield, ShieldCheck, Lock, Terminal, Download, Play, CheckCircle, ExternalLink, ChevronRight, X, Key, Copy, Plus } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { useFetch } from '../hooks/useFetch';
import { useRBAC } from '../hooks/useRBAC';
import { useAuthStore } from '../stores/useAuthStore';
import { fetchRules, updateRule, generateOrgKey, listOrgKeys, fetchOrgSettings } from '../services/api';
import { config } from '../config';
import type { RuleConfig } from '../types';
import type { OrgKeyItem, OrgSettings } from '../services/api';

export function SettingsPage() {
  const currentUser = useAuthStore(s => s.user);
  const { isAdmin } = useRBAC();
  const { data: rules, loading, setData: setRules } = useFetch(useCallback(() => fetchRules(), []));
  const [thresholds, setThresholds] = useState(() => {
    try {
      const stored = localStorage.getItem('cybernova_thresholds');
      return stored ? JSON.parse(stored) : config.alertThresholds;
    } catch {
      return config.alertThresholds;
    }
  });
  const [saved, setSaved] = useState(false);
  const [quickStartDismissed, setQuickStartDismissed] = useState(() => {
    return localStorage.getItem('cybernova_quickstart_dismissed') === 'true';
  });

  // Org key management state (boss/admin only)
  const isOrgBoss = currentUser?.purpose === 'organization' && currentUser?.org_type === 'boss';
  const [orgKeys, setOrgKeys] = useState<OrgKeyItem[]>([]);
  const [orgSettings, setOrgSettings] = useState<OrgSettings | null>(null);
  const [orgKeyLoading, setOrgKeyLoading] = useState(false);
  const [newOrgKey, setNewOrgKey] = useState('');
  const [newKeyName, setNewKeyName] = useState('');
  const [orgKeyCopied, setOrgKeyCopied] = useState(false);
  const [orgKeyError, setOrgKeyError] = useState('');
  const [orgKeySuccess, setOrgKeySuccess] = useState('');

  useEffect(() => {
    if (isOrgBoss && isAdmin) {
      loadOrgData();
    }
  }, [isOrgBoss, isAdmin]);

  const loadOrgData = async () => {
    try {
      const [keys, settings] = await Promise.all([listOrgKeys(), fetchOrgSettings()]);
      setOrgKeys(keys);
      setOrgSettings(settings);
    } catch (e) {
      // Silently fail — org endpoints may not be available
    }
  };

  const handleGenerateOrgKey = async () => {
    setOrgKeyLoading(true);
    setOrgKeyError('');
    setOrgKeySuccess('');
    try {
      const result = await generateOrgKey(newKeyName || 'default');
      setNewOrgKey(result.org_key);
      setOrgKeySuccess('New organization key generated! Share it with your staff members.');
      setNewKeyName('');
      await loadOrgData();
    } catch (e) {
      setOrgKeyError(e instanceof Error ? e.message : 'Failed to generate key');
    } finally {
      setOrgKeyLoading(false);
    }
  };

  const copyOrgKey = () => {
    navigator.clipboard.writeText(newOrgKey);
    setOrgKeyCopied(true);
    setTimeout(() => setOrgKeyCopied(false), 2000);
  };

  const handleSave = async () => {
    try {
      localStorage.setItem('cybernova_thresholds', JSON.stringify(thresholds));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  const handleRuleToggle = async (rule: RuleConfig) => {
    try {
      await updateRule(rule.id, !rule.enabled);
      setRules((prev) =>
        prev?.map((r) => r.id === rule.id ? { ...r, enabled: !r.enabled } : r) || null
      );
    } catch (error) {
      if (config.debug) console.error('Failed to toggle rule:', error);
    }
  };

  const serverUrl = typeof window !== 'undefined' ? window.location.origin : '';

  const quickStartSteps = [
    {
      step: 1,
      title: 'Install the Agent',
      description: 'Copy and run this one-liner on the device you want to protect',
      command: `irm ${serverUrl}/agent.ps1 | iex`,
      icon: <Terminal size={18} className="text-cyan-400" />,
    },
    {
      step: 2,
      title: 'Verify Connection',
      description: 'Your device should appear in the Devices page within seconds',
      link: '/devices',
      linkLabel: 'View Devices',
      icon: <Play size={18} className="text-green-400" />,
    },
    {
      step: 3,
      title: 'Configure Detection Rules',
      description: 'Enable or disable rules based on your security needs',
      icon: <Shield size={18} className="text-purple-400" />,
    },
    {
      step: 4,
      title: 'Monitor Alerts',
      description: 'Real-time alerts will appear on the dashboard as threats are detected',
      link: '/alerts',
      linkLabel: 'View Alerts',
      icon: <CheckCircle size={18} className="text-amber-400" />,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Quick Start Guide */}
      {!quickStartDismissed && (
        <Card title="Quick Start" subtitle="Get CyberNova running in 4 steps">
          <div className="relative">
            <button
              onClick={() => {
                localStorage.setItem('cybernova_quickstart_dismissed', 'true');
                setQuickStartDismissed(true);
              }}
              className="absolute top-0 right-0 p-1 rounded-md text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/50 transition-colors"
              title="Dismiss"
            >
              <X size={16} />
            </button>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {quickStartSteps.map((item) => (
                <div
                  key={item.step}
                  className="relative rounded-xl border border-cyber-border bg-cyber-bg/50 p-4 hover:border-cyber-accent/30 transition-all group"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyber-accent/10 border border-cyber-accent/20">
                      {item.icon}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-cyber-muted">Step {item.step}</span>
                      </div>
                      <h3 className="text-sm font-semibold text-cyber-text mb-1">{item.title}</h3>
                      <p className="text-xs text-cyber-muted leading-relaxed">{item.description}</p>

                      {/* Command to copy */}
                      {item.command && (
                        <div className="mt-3 flex items-center gap-2 bg-black/30 rounded-lg px-3 py-2 border border-cyber-border/50">
                          <code className="flex-1 text-xs text-green-400 font-mono overflow-x-auto whitespace-nowrap">{item.command}</code>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(item.command!);
                            }}
                            className="shrink-0 p-1 rounded hover:bg-cyber-border/50 transition-colors"
                            title="Copy to clipboard"
                          >
                            <Download size={12} className="text-cyber-muted" />
                          </button>
                        </div>
                      )}

                      {/* Link */}
                      {item.link && (
                        <a
                          href={item.link}
                          className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-cyber-accent hover:text-cyan-400 transition-colors"
                        >
                          {item.linkLabel}
                          <ExternalLink size={10} />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
              <p className="text-xs text-cyber-muted flex items-center gap-2">
                <ChevronRight size={12} className="text-cyan-400" />
                <span>Need help? Visit the <a href="/docs" className="text-cyan-400 hover:text-cyan-300 underline">documentation</a> or check the <a href="http://localhost:8000/docs" className="text-cyan-400 hover:text-cyan-300 underline">API reference</a>.</span>
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Alert Thresholds */}
      <Card title="Alert Thresholds" subtitle="Configure severity levels for alerts">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {(Object.keys(thresholds) as Array<keyof typeof thresholds>).map((key) => {
            const colors = {
              low: 'border-blue-500/30 focus:border-blue-500',
              medium: 'border-amber-500/30 focus:border-amber-500',
              high: 'border-orange-500/30 focus:border-orange-500',
              critical: 'border-red-500/30 focus:border-red-500',
            };
            return (
              <div key={key as string}>
                <label className="flex items-center gap-2 mb-1.5">
                  <Gauge size={12} className="text-cyber-muted" />
                  <span className="text-xs font-medium text-cyber-muted uppercase tracking-wider">{key as string} Threshold</span>
                </label>
                <input
                  type="number"
                  value={thresholds[key]}
                  onChange={(e) => setThresholds({ ...thresholds, [key]: Number(e.target.value) })}
                  min={0}
                  max={100}
                  className={`w-full rounded-lg border bg-cyber-bg py-2.5 px-4 text-sm font-mono text-cyber-text focus:outline-none focus:ring-1 focus:ring-current/30 ${colors[key as keyof typeof colors]}`}
                />
              </div>
            );
          })}
        </div>
      </Card>

      {/* User Profile */}
      <Card title="User Profile" subtitle="Your account information">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyber-accent/20">
              <span className="text-xl font-bold text-cyber-accent">
                {currentUser?.username?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <div>
              <p className="text-sm font-semibold text-cyber-text">{currentUser?.username || 'Unknown'}</p>
              <p className="text-xs text-cyber-muted capitalize">{currentUser?.role || 'analyst'}</p>
            </div>
          </div>
          
          <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield size={14} className="text-cyber-muted" />
              <span className="text-xs font-medium text-cyber-muted uppercase tracking-wider">Security Notice</span>
            </div>
            <p className="text-xs text-cyber-muted">
              Connection settings, API keys, and webhook URLs are configured via environment variables on the server.
              Contact your administrator for changes.
            </p>
          </div>
        </div>
      </Card>

      {/* Save Button - Admin Only */}
      {isAdmin && (
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-purple-600 px-6 py-2.5 text-sm font-semibold text-white hover:from-cyan-500 hover:to-purple-500 transition-all shadow-lg shadow-cyan-500/20"
        >
          <Save size={16} />
          Save Settings
        </button>
        <button
          onClick={() => {
            setThresholds(config.alertThresholds);
          }}
          className="flex items-center gap-2 rounded-lg border border-cyber-border px-4 py-2.5 text-sm font-medium text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/50 transition-colors"
        >
          <RotateCcw size={14} />
          Reset
        </button>
        {saved && (
          <span className="text-xs font-medium text-emerald-400 animate-slide-in">Settings saved successfully</span>
        )}
      </div>
      )}

      {/* Organization Key Management - Boss/Admin Only */}
      {isAdmin && isOrgBoss && (
      <Card title="Organization Keys" subtitle="Manage staff invitation keys">
        <div className="space-y-4">
          {/* Org Settings Summary */}
          {orgSettings && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Organization</p>
                <p className="text-sm font-medium text-cyber-text">{orgSettings.name}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Devices</p>
                <p className="text-sm font-medium text-cyber-accent">{orgSettings.device_count}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Users</p>
                <p className="text-sm font-medium text-cyber-accent">{orgSettings.user_count}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-3 py-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Plan</p>
                <p className="text-sm font-medium text-cyber-text capitalize">{orgSettings.plan}</p>
              </div>
            </div>
          )}

          {/* Generate New Key */}
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="Key name (optional)"
              className="flex-1 rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2.5 text-sm text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
            <button
              onClick={handleGenerateOrgKey}
              disabled={orgKeyLoading}
              className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-purple-600 to-cyan-500 px-5 py-2.5 text-sm font-semibold text-white hover:from-purple-500 hover:to-cyan-400 transition-all disabled:opacity-50"
            >
              {orgKeyLoading ? (
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              ) : (
                <><Plus size={14} /> Generate Key</>
              )}
            </button>
          </div>

          {orgKeyError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {orgKeyError}
            </div>
          )}

          {orgKeySuccess && newOrgKey && (
            <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30 space-y-3">
              <p className="text-sm text-green-400 font-medium flex items-center gap-2">
                <CheckCircle size={14} /> {orgKeySuccess}
              </p>
              <div className="flex items-center gap-2">
                <div className="flex-1 p-3 rounded-lg bg-black/30 border border-cyber-border font-mono text-sm text-cyan-400 text-center tracking-wider select-all">
                  {newOrgKey}
                </div>
                <button
                  onClick={copyOrgKey}
                  className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-all"
                  title="Copy to clipboard"
                >
                  {orgKeyCopied ? <CheckCircle size={16} /> : <Copy size={16} />}
                </button>
              </div>
            </div>
          )}

          {/* Existing Keys */}
          {orgKeys.length > 0 && (
            <div>
              <p className="text-xs font-medium text-cyber-muted uppercase tracking-wider mb-2">Active Keys</p>
              <div className="space-y-2">
                {orgKeys.map((key) => (
                  <div key={key.id} className="flex items-center justify-between rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-2.5">
                    <div className="flex items-center gap-3">
                      <Key size={14} className="text-cyber-accent" />
                      <div>
                        <p className="text-sm text-cyber-text">{key.name}</p>
                        <p className="text-[10px] text-cyber-muted">Created {new Date(key.created_at).toLocaleDateString()}</p>
                      </div>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${key.is_active ? 'bg-green-500/10 text-green-400 border border-green-500/30' : 'bg-red-500/10 text-red-400 border border-red-500/30'}`}>
                      {key.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
            <p className="text-xs text-purple-300">
              <Key size={12} className="inline mr-1" />
              Share organization keys with staff members so they can register and connect their servers to your dashboard.
            </p>
          </div>
        </div>
      </Card>
      )}

      {/* Detection Rules - Admin Only */}
      {isAdmin && (
      <Card title="Detection Rules" subtitle="Enable or disable detection rules" noPadding>
        {loading ? (
          <LoadingSpinner size="sm" />
        ) : rules && rules.length > 0 ? (
          <div className="divide-y divide-cyber-border/50">
            {rules.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between gap-4 px-5 py-3.5 hover:bg-cyber-accent/5 transition-colors">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-xs text-cyber-accent">{rule.id}</span>
                    <SeverityBadge severity={rule.severity} />
                    <span className="rounded bg-cyber-border px-1.5 py-0.5 text-[10px] text-cyber-muted">{rule.category}</span>
                  </div>
                  <p className="text-sm font-medium text-cyber-text">{rule.name}</p>
                  <p className="text-xs text-cyber-muted">{rule.description}</p>
                </div>
                {/* Toggle */}
                <button
                  onClick={() => handleRuleToggle(rule)}
                  className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${
                    rule.enabled ? 'bg-cyber-accent' : 'bg-cyber-border'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform shadow-sm ${
                      rule.enabled ? 'left-[22px]' : 'left-0.5'
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-16 px-6">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyber-accent/10 mb-4">
              <ShieldCheck size={32} className="text-cyber-accent" />
            </div>
            <p className="text-sm font-medium text-cyber-text mb-1">No detection rules configured</p>
            <p className="text-xs text-cyber-muted text-center">Detection rules will be loaded from the backend</p>
          </div>
        )}
      </Card>
      )}

      {/* Hidden for non-admins */}
      {!isAdmin && (
        <Card title="Detection Rules" subtitle="Admin only">
          <div className="flex items-center gap-2 text-cyber-muted">
            <Lock size={16} />
            <span className="text-sm">Contact your administrator to manage detection rules</span>
          </div>
        </Card>
      )}
    </div>
  );
}