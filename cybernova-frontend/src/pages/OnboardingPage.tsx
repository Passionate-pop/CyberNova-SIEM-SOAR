import { useState, useEffect, useCallback, useRef } from 'react';
import { ArrowRight, Check, Loader2, Copy, Shield, Terminal, AlertCircle, Play, FileText, Cookie } from 'lucide-react';
import { useAuthStore } from '../stores/useAuthStore';
import { trackOnboardingEvent, trackConversionEvent } from '../lib/analytics';

type OnboardingStep = 'terms' | 'agent' | 'waiting' | 'connected';

interface OnboardingPageProps {
  onComplete: () => void;
}

const TOTAL_STEPS = 4;

export function OnboardingPage({ onComplete }: OnboardingPageProps) {
  const authUser = useAuthStore(s => s.user);
  const [step, setStep] = useState<OnboardingStep>('terms');
  // Form data
  const [copied, setCopied] = useState(false);
  const [selectedOS, setSelectedOS] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [waitingTime, setWaitingTime] = useState(0);
  const [agentStarted, setAgentStarted] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [cookiesAccepted, setCookiesAccepted] = useState(false);
  const [termsError, setTermsError] = useState('');

  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  const getCurrentStep = () => {
    const steps: OnboardingStep[] = ['terms', 'agent', 'waiting', 'connected'];
    return steps.indexOf(step) + 1;
  };

  const isOrgUser = authUser?.purpose === 'organization' || authUser?.org_type === 'boss' || authUser?.org_type === 'staff' || !!(authUser?.org_key);

  const getAgentToken = () => {
    // Org users get their org key, individual users get their tenant_id as personal identifier
    return authUser?.org_key || authUser?.tenant_id || '';
  };

  const copyToClipboard = (text: string, event: 'org_key_copied' | 'agent_command_copied') => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    trackOnboardingEvent(event);
    setTimeout(() => setCopied(false), 2000);
  };

  const getAgentCommand = () => {
    const token = getAgentToken();
    switch (selectedOS) {
      case 'windows':
        return `python cybernova_agent.py ${token}`;
      case 'linux':
        return `python3 cybernova_agent.py ${token}`;
      case 'macos':
        return `python3 cybernova_agent.py ${token}`;
    }
  };

  const proceedToWaiting = () => {
    setAgentStarted(true);
    trackOnboardingEvent('agent_started');
    setStep('waiting');
    setWaitingTime(0);
  };

  // Polling fallback - check for device connection
  const checkForDevice = useCallback(async () => {
    if (!authUser?.token) return;

    try {
      const response = await fetch('/api/v1/admin/devices', {
        headers: { 'Authorization': `Bearer ${authUser.token}` },
      });

      if (response.ok) {
        const data = await response.json();
        // Backend returns { devices: [...], total: N }
        const devices = Array.isArray(data) ? data : (data.devices || []);
        if (devices.length > 0) {
          trackOnboardingEvent('device_connected', { deviceCount: devices.length });
          setStep('connected');
          if (pollingRef.current) {
            clearInterval(pollingRef.current);
          }
        }
      }
    } catch (err) {
      // Silent fail - WebSocket will catch real connection
    }
  }, [authUser?.token]);

  // Track waiting time and poll for device registration
  useEffect(() => {
    if (step === 'waiting') {
      const interval = setInterval(() => {
        setWaitingTime(prev => prev + 1);
      }, 1000);

      pollingRef.current = setInterval(checkForDevice, 3000);

      return () => {
        clearInterval(interval);
        if (pollingRef.current) {
          clearInterval(pollingRef.current);
        }
      };
    }
  }, [step, checkForDevice]);

  const renderStep = () => {
    switch (step) {
      case 'terms':
        return (
          <div className="w-full max-w-md">
            <div className="text-center mb-6">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-600 mb-4">
                <FileText size={32} className="text-white" />
              </div>
              <h1 className="text-2xl font-bold text-cyber-text">Terms & Cookies</h1>
              <p className="text-cyber-muted mt-2">Please review and accept before installing the agent</p>
            </div>

            {/* Terms of Service */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <FileText size={16} className="text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Terms of Service</h3>
              </div>
              <div className="text-xs text-cyber-muted space-y-2 max-h-32 overflow-y-auto pr-2">
                <p>By using CyberNova, you agree to the following:</p>
                <ul className="list-disc list-inside space-y-1 ml-1">
                  <li>CyberNova collects system telemetry, process data, and security events from devices with the agent installed.</li>
                  <li>Data is processed and stored on your self-hosted server — not on external servers.</li>
                  <li>You are responsible for the security of your server and agent credentials.</li>
                  <li>CyberNova is provided as-is for security monitoring purposes.</li>
                  <li>You may not use CyberNova to monitor devices without the owner's consent.</li>
                  <li>Free tier includes up to 3 devices. Additional devices require a paid plan.</li>
                </ul>
              </div>
            </div>

            {/* Cookie Policy */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <Cookie size={16} className="text-purple-400" />
                <h3 className="text-sm font-semibold text-white">Cookie & Storage Policy</h3>
              </div>
              <div className="text-xs text-cyber-muted space-y-2 max-h-32 overflow-y-auto pr-2">
                <p>CyberNova uses local storage for the following:</p>
                <ul className="list-disc list-inside space-y-1 ml-1">
                  <li><strong className="text-white">Authentication tokens</strong> — to keep you logged in securely.</li>
                  <li><strong className="text-white">Session preferences</strong> — your role, organization, and UI settings.</li>
                  <li><strong className="text-white">Onboarding state</strong> — to remember where you left off during setup.</li>
                  <li>No third-party tracking cookies are used.</li>
                  <li>No data is sent to external analytics or advertising services.</li>
                </ul>
              </div>
            </div>

            {/* Acceptance checkboxes */}
            <div className="space-y-3 mb-6">
              <label className="flex items-start gap-3 cursor-pointer group">
                <div className="mt-0.5">
                  <input
                    type="checkbox"
                    checked={termsAccepted}
                    onChange={(e) => { setTermsAccepted(e.target.checked); setTermsError(''); }}
                    className="w-4 h-4 rounded border-cyber-border bg-cyber-bg text-cyan-500 focus:ring-cyan-500/30 focus:ring-offset-0"
                  />
                </div>
                <span className="text-sm text-cyber-muted group-hover:text-white transition-colors">
                  I have read and agree to the <span className="text-cyan-400">Terms of Service</span>
                </span>
              </label>

              <label className="flex items-start gap-3 cursor-pointer group">
                <div className="mt-0.5">
                  <input
                    type="checkbox"
                    checked={cookiesAccepted}
                    onChange={(e) => { setCookiesAccepted(e.target.checked); setTermsError(''); }}
                    className="w-4 h-4 rounded border-cyber-border bg-cyber-bg text-cyan-500 focus:ring-cyan-500/30 focus:ring-offset-0"
                  />
                </div>
                <span className="text-sm text-cyber-muted group-hover:text-white transition-colors">
                  I consent to the use of <span className="text-purple-400">local storage & cookies</span> for session management
                </span>
              </label>
            </div>

            {termsError && (
              <div className="flex items-center gap-2 text-red-400 text-sm mb-4">
                <AlertCircle size={14} />
                {termsError}
              </div>
            )}

            <button
              onClick={() => {
                if (!termsAccepted || !cookiesAccepted) {
                  setTermsError('Please accept both the Terms of Service and Cookie Policy to continue.');
                  return;
                }
                localStorage.setItem('cybernova_terms_accepted', 'true');
                localStorage.setItem('cybernova_cookies_accepted', 'true');
                trackOnboardingEvent('terms_accepted');
                setTermsError('');
                setStep('agent');
              }}
              className="w-full py-3 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 text-white font-medium hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
            >
              Accept & Continue
              <ArrowRight size={20} />
            </button>

            <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
              <p className="text-xs text-amber-400 text-center">
                <Shield size={12} className="inline mr-1" />
                Your data stays on your server. CyberNova is self-hosted — no data leaves your infrastructure.
              </p>
            </div>
          </div>
        );

      case 'agent':
        return (
          <div className="w-full max-w-md">
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold text-cyber-text">Install CyberNova Agent</h1>
              <p className="text-cyber-muted mt-2">Connect your first device in seconds</p>
            </div>

            {/* OS Selection */}
            <div className="flex gap-2 mb-6">
              {(['windows', 'linux', 'macos'] as const).map((os) => (
                <button
                  key={os}
                  onClick={() => setSelectedOS(os)}
                  className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium transition-all ${
                    selectedOS === os
                      ? 'bg-cyan-600 text-white'
                      : 'bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-white'
                  }`}
                >
                  {os.charAt(0).toUpperCase() + os.slice(1)}
                </button>
              ))}
            </div>

            {/* Step 1 - Download */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4 mb-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-7 h-7 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm font-bold">1</div>
                <span className="text-white font-medium">Download the agent</span>
              </div>
              <button
                onClick={proceedToWaiting}
                className="w-full py-2.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-500 transition-colors flex items-center justify-center gap-2"
              >
                Download for {selectedOS.charAt(0).toUpperCase() + selectedOS.slice(1)}
              </button>
            </div>

            {/* Step 2 - Run Command */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4 mb-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-7 h-7 rounded-full bg-green-500/20 text-green-400 flex items-center justify-center text-sm font-bold">2</div>
                <span className="text-white font-medium">Run this command</span>
              </div>
              {isOrgUser ? (
                <div className="bg-black/40 rounded-lg p-3 flex items-center gap-2">
                  <Terminal size={16} className="text-cyber-muted" />
                  <code className="flex-1 text-sm text-green-400 font-mono overflow-x-auto">
                    {getAgentCommand()}
                  </code>
                  <button
                    onClick={() => copyToClipboard(getAgentCommand(), 'agent_command_copied')}
                    className="p-1.5 rounded hover:bg-cyber-border/50 transition-colors"
                  >
                    {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} className="text-cyber-muted" />}
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="bg-black/40 rounded-lg p-3 flex items-center gap-2">
                    <Terminal size={16} className="text-cyber-muted" />
                    <code className="flex-1 text-sm text-green-400 font-mono overflow-x-auto">
                      {getAgentCommand()}
                    </code>
                    <button
                      onClick={() => copyToClipboard(getAgentCommand(), 'agent_command_copied')}
                      className="p-1.5 rounded hover:bg-cyber-border/50 transition-colors"
                    >
                      {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} className="text-cyber-muted" />}
                    </button>
                  </div>
                  <p className="text-xs text-amber-400">
                    <AlertCircle size={12} className="inline mr-1" />
                    Individual mode — agent connects with your personal tenant ID.
                  </p>
                </div>
              )}
            </div>

            {/* Verify install */}
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 mb-4">
              <button
                onClick={proceedToWaiting}
                className="w-full flex items-center gap-2 text-green-400 hover:text-green-300"
              >
                <Play size={16} />
                <span className="text-sm">I ran the command - verify it started</span>
              </button>
            </div>

            <details className="mt-4">
              <summary className="text-sm text-cyan-400 cursor-pointer hover:text-cyan-300">
                Need help with installation?
              </summary>
              <div className="mt-3 p-3 bg-cyber-bg rounded-lg text-sm text-cyber-muted space-y-2">
                <p>1. Make sure Python is installed (python --version)</p>
                <p>2. Check your firewall allows outbound connections</p>
                <p>3. Ensure you have an internet connection</p>
              </div>
            </details>

            <div className="text-center mt-6">
              <button
                onClick={() => {
                  trackOnboardingEvent('agent_started');
                  setStep('connected');
                }}
                className="text-cyan-400 hover:text-cyan-300 text-sm"
              >
                Skip for now - I'll do this later →
              </button>
            </div>
          </div>
        );

      case 'waiting':
        return (
          <div className="w-full max-w-md text-center">
            <div className="mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyan-500/20 mb-4">
                <Loader2 size={32} className="text-cyan-400 animate-spin" />
              </div>
              <h1 className="text-2xl font-bold text-cyber-text">Connecting Your Device...</h1>
              <p className="text-cyber-muted mt-2">Agent is establishing secure connection</p>
            </div>

            {/* Active progress steps */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4 mb-6 text-left">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-5 h-5 rounded-full bg-green-500 flex items-center justify-center">
                  <Check size={12} className="text-white" />
                </div>
                <span className="text-green-400">Agent started</span>
              </div>

              <div className="flex items-center gap-3 mb-4">
                <div className="w-5 h-5 rounded-full bg-cyan-500 animate-pulse flex items-center justify-center">
                  <Loader2 size={12} className="text-white" />
                </div>
                <span className="text-cyan-400">Establishing secure connection...</span>
              </div>

              <div className={`flex items-center gap-3 ${agentStarted ? '' : 'opacity-50'}`}>
                <div className="w-5 h-5 rounded-full border-2 border-cyber-border" />
                <span className="text-cyber-muted">Registering device</span>
              </div>
            </div>

            {/* Polling status */}
            <div className="text-xs text-cyber-muted mb-4">
              {waitingTime < 10 ? 'This usually takes under 30 seconds' : 'Still connecting...'}
            </div>

            {/* Fallback after 30 seconds */}
            {waitingTime > 30 && (
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-6 text-left">
                <p className="text-yellow-400 font-medium mb-2">Having trouble?</p>
                <div className="space-y-2 text-sm">
                  <button
                    onClick={() => { setStep('agent'); setAgentStarted(false); setWaitingTime(0); }}
                    className="block text-cyan-400 hover:text-cyan-300"
                  >
                    → Re-run the install command
                  </button>
                  <button className="block text-cyan-400 hover:text-cyan-300">
                    → Check firewall settings
                  </button>
                  <button className="block text-cyan-400 hover:text-cyan-300">
                    → View troubleshooting guide
                  </button>
                </div>
              </div>
            )}
          </div>
        );

      case 'connected':
        return (
          <div className="w-full max-w-md text-center">
            <div className="mb-8">
              <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-green-500/20 mb-4">
                <Shield size={40} className="text-green-400" />
              </div>
              <h1 className="text-2xl font-bold text-cyber-text">Protection Active!</h1>
              <p className="text-cyber-muted mt-2">Your device is now being monitored in real-time</p>
            </div>

            <div className="bg-cyber-bg border border-green-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse" />
                <div className="text-left">
                  <p className="text-white font-medium">Device Connected</p>
                  <p className="text-sm text-green-400">Real-time monitoring active</p>
                </div>
              </div>
            </div>

            <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4 mb-6 text-left">
              <p className="text-cyan-400 text-sm">
                <strong>Your device is being monitored.</strong> Any suspicious activity will trigger an immediate alert.
              </p>
            </div>

            <button
              onClick={() => {
                trackOnboardingEvent('onboarding_completed');
                trackConversionEvent('device_added');
                localStorage.setItem('cybernova_device_added', 'true');
                // Persist org_name for Sidebar display (staff members need this)
                if (authUser?.org_name) {
                  localStorage.setItem('cybernova_org_name', authUser.org_name);
                }
                onComplete();
              }}
              className="w-full py-3 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 text-white font-medium hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
            >
              Go to Dashboard
              <ArrowRight size={20} />
            </button>

            <button
              onClick={() => { setStep('agent'); setAgentStarted(false); }}
              className="w-full py-2 mt-3 text-cyan-400 hover:text-cyan-300 text-sm"
            >
              + Add another device
            </button>
          </div>
        );

      default:
        return null;
    }
  };

  const currentStepIndex = getCurrentStep();

  return (
    <div className="min-h-screen bg-cyber-bg flex flex-col">
      {/* Header */}
      <header className="p-4 border-b border-cyber-border">
        <div className="flex items-center justify-between max-w-md mx-auto">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full overflow-hidden border border-cyan-500/40">
              <img src="/logo.png" alt="CyberNova Logo" width={32} height={32} className="h-full w-full object-cover" />
            </div>
            <span className="text-white font-bold">CyberNova</span>
          </div>

          {/* Step indicator */}
          <span className="text-sm text-cyber-muted">
            Step {currentStepIndex} of {TOTAL_STEPS}
          </span>
        </div>
      </header>

      {/* Progress bar */}
      <div className="h-1 bg-cyber-border">
        <div
          className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all duration-500"
          style={{ width: `${(currentStepIndex / TOTAL_STEPS) * 100}%` }}
        />
      </div>

      {/* Content */}
      <main className="flex-1 flex items-center justify-center p-6">
        {renderStep()}
      </main>

      {/* Footer */}
      <footer className="p-4 border-t border-cyber-border text-center">
        <div className="flex items-center justify-center gap-4 text-xs text-cyber-muted">
          <span className="flex items-center gap-1">
            <Check size={12} className="text-green-400" /> Free tier
          </span>
          <span>•</span>
          <span>No credit card</span>
          <span>•</span>
          <span>Setup in 2 min</span>
        </div>
      </footer>
    </div>
  );
}
