import { useState } from 'react';
import { CheckCircle } from 'lucide-react';
import { createFirstAdmin, checkSetupStatus } from '../services/api';
import type { User } from '../types';

export function SetupPage({ onSetupComplete }: { onSetupComplete: (user: User) => void }) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [company, setCompany] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [envCheck, setEnvCheck] = useState<{ db_connected: boolean; redis_connected: boolean } | null>(null);

  const handleAdminCreate = async () => {
    if (!email || !password || !company) {
      setError('All fields are required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const user = await createFirstAdmin(email, password, company);
      setStep(2);
      // Check environment
      const status = await checkSetupStatus();
      setEnvCheck({ db_connected: status.db_connected, redis_connected: status.redis_connected });
      setStep(3);
      onSetupComplete(user);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-6">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <div className="mx-auto w-16 h-16 rounded-full overflow-hidden border border-cyan-500/40 mb-4">
            <img src="/logo.png" alt="CyberNova Logo" width={64} height={64} className="h-full w-full object-cover" />
          </div>
          <h1 className="text-2xl font-bold text-cyber-text">Welcome to CyberNova</h1>
          <p className="text-cyber-muted text-sm mt-2">Set up your security platform in 3 steps</p>
        </div>

        {/* Progress */}
        <div className="flex items-center gap-2">
          {[1, 2, 3].map((s) => (
            <div key={s} className={`flex-1 h-1 rounded-full ${s <= step ? 'bg-cyan-500' : 'bg-cyber-border'}`} />
          ))}
        </div>

        {step === 1 && (
          <div className="space-y-6 bg-cyber-card border border-cyber-border rounded-2xl p-6">
            <h2 className="text-lg font-semibold text-cyber-text">Create Admin Account</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-cyber-muted mb-1">Company Name</label>
                <input
                  type="text" value={company} onChange={e => setCompany(e.target.value)}
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2.5 text-sm text-cyber-text focus:border-cyan-500 focus:outline-none"
                  placeholder="Acme Corp"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-cyber-muted mb-1">Admin Email</label>
                <input
                  type="email" value={email} onChange={e => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2.5 text-sm text-cyber-text focus:border-cyan-500 focus:outline-none"
                  placeholder="admin@company.com"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-cyber-muted mb-1">Password</label>
                <input
                  type="password" value={password} onChange={e => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2.5 text-sm text-cyber-text focus:border-cyan-500 focus:outline-none"
                  placeholder="········"
                />
              </div>
            </div>
            {error && <p className="text-red-400 text-xs">{error}</p>}
            <button
              onClick={handleAdminCreate}
              disabled={loading}
              className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white py-2.5 text-sm font-medium transition-colors"
            >
              {loading ? 'Creating...' : 'Create Admin & Continue'}
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="text-center space-y-4 bg-cyber-card border border-cyber-border rounded-2xl p-8">
            <div className="w-12 h-12 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin mx-auto" />
            <p className="text-cyber-text">Checking environment...</p>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6 bg-cyber-card border border-cyber-border rounded-2xl p-6">
            <div className="flex items-center gap-3">
              <CheckCircle size={24} className="text-emerald-400" />
              <h2 className="text-lg font-semibold text-cyber-text">System Ready</h2>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-cyber-border/50">
                <span className="text-sm text-cyber-muted">Backend</span>
                <span className="text-emerald-400 text-sm">✓ Online</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-cyber-border/50">
                <span className="text-sm text-cyber-muted">Database</span>
                <span className={`text-sm ${envCheck?.db_connected ? 'text-emerald-400' : 'text-red-400'}`}>
                  {envCheck?.db_connected ? '✓ Connected' : '✗ Failed'}
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-cyber-border/50">
                <span className="text-sm text-cyber-muted">Redis</span>
                <span className={`text-sm ${envCheck?.redis_connected ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {envCheck?.redis_connected ? '✓ Connected' : '○ Optional'}
                </span>
              </div>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white py-2.5 text-sm font-medium transition-colors"
            >
              Go to Dashboard →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
