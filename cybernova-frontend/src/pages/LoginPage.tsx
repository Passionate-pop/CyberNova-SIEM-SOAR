import { useState, useMemo } from 'react';
import { User as UserIcon, Building2, Shield, Lock, Mail, Eye, EyeOff, ArrowLeft, CheckCircle2, Key, Users, Briefcase, Cpu, XCircle } from 'lucide-react';
import { login, registerUser } from '../services/api';
import type { User, UserPurpose, OrgType, UserRole } from '../types';

type AuthStep = 'intent' | 'org-type' | 'auth-form' | 'success';

interface LoginPageProps {
  onLogin: (user: User) => void;
}

const COMPANY_SIZES = [
  { value: '1-10', label: '1-10 employees' },
  { value: '11-50', label: '11-50 employees' },
  { value: '51-200', label: '51-200 employees' },
  { value: '201-500', label: '201-500 employees' },
  { value: '500+', label: '500+ employees' },
];

export function LoginPage({ onLogin }: LoginPageProps) {
  const [step, setStep] = useState<AuthStep>('intent');
  const [purpose, setPurpose] = useState<UserPurpose | null>(null);
  const [orgType, setOrgType] = useState<OrgType | null>(null);
  const [isRegister, setIsRegister] = useState(false);
  
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const passwordStrength = useMemo(() => {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      digit: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>_\-+]/.test(password),
    };
    const met = Object.values(checks).filter(Boolean).length;
    let level: 'none' | 'weak' | 'medium' | 'strong' = 'none';
    let score = 0;
    if (password.length > 0) {
      if (met <= 2) { level = 'weak'; score = 25; }
      else if (met <= 3) { level = 'medium'; score = 50; }
      else if (met <= 4) { level = 'medium'; score = 75; }
      else { level = 'strong'; score = 100; }
    }
    return { checks, met, total: 5, level, score };
  }, [password]);
  
  const [companyName, setCompanyName] = useState('');
  const [companyDomain, setCompanyDomain] = useState('');
  const [companySize, setCompanySize] = useState('');
  const [orgKey, setOrgKey] = useState('');
  
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [generatedOrgKey, setGeneratedOrgKey] = useState('');
  const [copied, setCopied] = useState(false);

  const isIndividual = purpose === 'individual';
  const isOrgBoss = purpose === 'organization' && orgType === 'boss';
  const isOrgStaff = purpose === 'organization' && orgType === 'staff';

  const resetForm = () => {
    setUsername('');
    setEmail('');
    setPassword('');
    setCompanyName('');
    setCompanyDomain('');
    setCompanySize('');
    setOrgKey('');
    setError('');
  };

  const goBack = () => {
    if (step === 'auth-form') {
      if (purpose === 'organization') {
        setStep('org-type');
      } else {
        setStep('intent');
      }
      setOrgType(null);
      resetForm();
    } else if (step === 'org-type') {
      setStep('intent');
      setPurpose(null);
    }
  };

  const handleIntentSelect = (selected: UserPurpose) => {
    setPurpose(selected);
    if (selected === 'individual') {
      // Individual users skip the org-type step — go straight to auth
      setStep('auth-form');
    } else {
      setStep('org-type');
    }
  };

  const handleOrgTypeSelect = (selected: OrgType) => {
    setOrgType(selected);
    setStep('auth-form');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      let userData: User;
      let role: UserRole;

      if (purpose === 'individual') {
        role = 'admin';
      } else if (purpose === 'organization') {
        role = orgType === 'boss' ? 'admin' : 'viewer';
      } else {
        throw new Error('Invalid purpose');
      }

      if (isRegister) {
        if (!username || !password || !email) {
          setError('All fields are required');
          setLoading(false);
          return;
        }
        if (purpose === 'organization' && orgType === 'boss' && !companyName) {
          setError('Company name is required');
          setLoading(false);
          return;
        }
        if (purpose === 'organization' && orgType === 'staff' && !orgKey) {
          setError('Organization key is required');
          setLoading(false);
          return;
        }

        const tenantName = purpose === 'individual' ? 'personal' : (companyName || 'default');
        
        // Clear stale onboarding/purpose from any previous session so App.tsx shows onboarding for this new user
        // Only for NEW registrations, not returning users logging in
        localStorage.removeItem('cybernova_onboarding_complete');
        localStorage.removeItem('cybernova_purpose');
        
        userData = await registerUser(
          username, 
          email, 
          password, 
          role, 
          orgType === 'staff' ? orgKey : undefined,
          undefined,
          tenantName
        );
      } else {
        if (!username || !password) {
          setError('Username and password are required');
          setLoading(false);
          return;
        }
        if (isOrgStaff && !orgKey) {
          setError('Organization key is required for staff login');
          setLoading(false);
          return;
        }
        userData = await login({ username, password, org_key: isOrgStaff ? orgKey : undefined });
      }

      if (!userData || !userData.token) {
        throw new Error('Invalid response from server');
      }

      // Set purpose and org_type on the user object so downstream components
      // (e.g. Sidebar, App) can access them via user.purpose
      userData.purpose = userData.purpose || purpose || 'individual';
      userData.org_type = userData.org_type || (purpose === 'organization' ? (orgType || undefined) : undefined);
      userData.org_name = userData.org_name || (companyName || undefined);
      userData.company_size = userData.company_size || (companySize || undefined);

      // Store org context for Sidebar (purpose is set by OnboardingPage when completed)
      if (purpose === 'organization') {
        localStorage.setItem('cybernova_org_type', orgType || '');
        localStorage.setItem('cybernova_org_name', userData.org_name || companyName || '');
        // Persist org_key in dedicated localStorage key so the Settings page can show it anytime
        if (userData.org_key) {
          localStorage.setItem('cybernova_org_key', userData.org_key);
        }
      }
      // Store user for success step
      localStorage.setItem('cybernova_last_user', JSON.stringify(userData));
      
      // If org admin just registered and got an org_key, show it before proceeding
      if (userData.org_key && purpose === 'organization' && orgType === 'boss') {
        setGeneratedOrgKey(userData.org_key);
        setStep('success');
        setLoading(false);
        return;
      }
      
      onLogin(userData);
    } catch (err: any) {
      const msg = err?.message || 'Authentication failed';
      if (msg.includes('fetch') || msg.includes('Network') || msg.includes('Failed')) {
        setError('Backend not reachable. Is the server running on port 8000?');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  const getTitle = () => {
    if (step === 'intent') return 'CyberNova';
    if (step === 'org-type') return purpose === 'organization' ? 'Organization' : 'Personal';
    if (step === 'auth-form') {
      if (isIndividual) return isRegister ? 'Create Account' : 'Welcome Back';
      if (isOrgBoss) return isRegister ? 'Create Organization' : 'Organization Login';
      if (isOrgStaff) return isRegister ? 'Join Organization' : 'Staff Login';
    }
    return 'CyberNova';
  };

  const getSubtitle = () => {
    if (step === 'intent') return 'What are you using CyberNova for?';
    if (step === 'org-type') {
      if (purpose === 'organization') return 'How are you joining CyberNova?';
      return 'Set up your personal protection';
    }
    if (step === 'auth-form') {
      if (isIndividual) return isRegister ? 'Start protecting your device' : 'Sign in to your account';
      if (isOrgBoss) return isRegister ? 'Set up your company dashboard' : 'Manage your organization';
      if (isOrgStaff) return isRegister ? 'Connect to your organization' : 'Access your organization';
    }
    return '';
  };

  return (
    <div className="min-h-screen bg-[#0a0e1a] flex">
      {/* Left Panel - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-[#0f1629] to-[#0a0e1a] border-r border-[#1e293b] flex-col justify-between p-12">
        <div>
          <a href="/" className="flex items-center gap-3 mb-2 group">
            <div className="w-10 h-10 rounded-full overflow-hidden border border-cyan-500/40 shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              <img src="/logo.png" alt="CyberNova Logo" width={40} height={40} className="h-full w-full object-cover" />
            </div>
            <span className="text-xl font-bold text-white tracking-tight group-hover:text-cyan-400 transition-colors">CyberNova</span>
          </a>
          <p className="text-gray-500 text-sm">AI-Powered Security Platform</p>
          <a href="/" id="back-to-website" onClick={(e) => {
            e.preventDefault();
            const { hostname, protocol } = window.location;
            const port = window.location.port;
            // When running under /app/ via nginx (port 8888 or 443), root serves the marketing site
            // When running on direct port 8080 or 5173 (dev), redirect to nginx port
            if (port === '8080' || port === '5173') {
              window.location.href = `${protocol}//${hostname}:8888/`;
            } else if (window.location.pathname.startsWith('/app/')) {
              // Through nginx proxy at /app/ — go to root (marketing site)
              window.location.href = '/';
            } else {
              // Direct access — try root first, fall back to nginx port
              window.location.href = `${protocol}//${hostname}:8888/`;
            }
          }} className="inline-flex items-center gap-1 mt-3 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
            ← Back to website
          </a>
        </div>

        <div className="space-y-8">
          <div className="space-y-4">
            <h2 className="text-3xl font-bold text-white leading-tight">
              Enterprise-grade security<br />
              <span className="text-cyan-400">for everyone</span>
            </h2>
            <p className="text-gray-400 text-sm leading-relaxed">
              From personal devices to Fortune 500 fleets — unified threat detection, 
              automated response, and real-time intelligence.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {[
              { icon: <Shield size={16} />, label: 'Real-time Detection' },
              { icon: <Users size={16} />, label: 'Team Management' },
              { icon: <Cpu size={16} />, label: 'Endpoint Visibility' },
              { icon: <Key size={16} />, label: 'Zero Trust Ready' },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-2 text-gray-400 text-sm">
                <span className="text-cyan-400">{item.icon}</span>
                {item.label}
              </div>
            ))}
          </div>
        </div>

        <div className="text-xs text-gray-600">
          © 2026 CyberNova. All rights reserved.
        </div>
      </div>

      {/* Right Panel - Auth Forms */}
      <div className="flex-1 flex items-center justify-center p-6 lg:p-12">
        <div className="w-full max-w-md">
          {/* Mobile Logo */}
          <div className="lg:hidden mb-8">
            <a href="/" className="flex items-center gap-2 group">
              <div className="w-8 h-8 rounded-full overflow-hidden border border-cyan-500/40 group-hover:scale-105 transition-transform">
                <img src="/logo.png" alt="CyberNova Logo" width={32} height={32} className="h-full w-full object-cover" />
              </div>
              <span className="text-lg font-bold text-white group-hover:text-cyan-400 transition-colors">CyberNova</span>
            </a>
            <a href="/" id="back-to-website-mobile" onClick={(e) => {
              e.preventDefault();
              const { hostname, protocol } = window.location;
              const port = window.location.port;
              if (port === '8080' || port === '5173') {
                window.location.href = `${protocol}//${hostname}:8888/`;
              } else if (window.location.pathname.startsWith('/app/')) {
                window.location.href = '/';
              } else {
                window.location.href = `${protocol}//${hostname}:8888/`;
              }
            }} className="inline-flex items-center gap-1 mt-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
              ← Back to website
            </a>
          </div>

          {/* Step 1: Intent Screen */}
          {step === 'intent' && (
            <div className="space-y-8 animate-in">
              <div className="text-center lg:text-left">
                <h1 className="text-2xl font-bold text-white mb-2">{getTitle()}</h1>
                <p className="text-gray-400">{getSubtitle()}</p>
              </div>

              <div className="space-y-3">
                <button
                  onClick={() => handleIntentSelect('individual')}
                  className="group w-full flex items-center gap-4 p-4 rounded-xl bg-[#111827] border border-[#1e293b] hover:border-cyan-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5"
                >
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-600/20 border border-cyan-500/30 flex items-center justify-center group-hover:scale-105 transition-transform">
                    <UserIcon size={24} className="text-cyan-400" />
                  </div>
                  <div className="flex-1 text-left">
                    <h3 className="text-base font-semibold text-white">Individual</h3>
                    <p className="text-xs text-gray-500">Personal cybersecurity protection</p>
                  </div>
                  <div className="w-6 h-6 rounded-full border-2 border-gray-600 group-hover:border-cyan-500 group-hover:bg-cyan-500/20 transition-all flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                </button>

                <button
                  onClick={() => handleIntentSelect('organization')}
                  className="group w-full flex items-center gap-4 p-4 rounded-xl bg-[#111827] border border-[#1e293b] hover:border-purple-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/5"
                >
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500/20 to-purple-600/20 border border-purple-500/30 flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Building2 size={24} className="text-purple-400" />
                  </div>
                  <div className="flex-1 text-left">
                    <h3 className="text-base font-semibold text-white">Organization</h3>
                    <p className="text-xs text-gray-500">Team & enterprise security</p>
                  </div>
                  <div className="w-6 h-6 rounded-full border-2 border-gray-600 group-hover:border-purple-500 group-hover:bg-purple-500/20 transition-all flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-purple-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                </button>
              </div>
            </div>
          )}

          {/* Step 2: Org Type Selection */}
          {step === 'org-type' && (
            <div className="space-y-8 animate-in">
              <button 
                onClick={goBack}
                className="flex items-center gap-1 text-sm text-gray-500 hover:text-white transition-colors"
              >
                <ArrowLeft size={16} />
                <span>Back</span>
              </button>

              <div className="text-center lg:text-left">
                <h1 className="text-2xl font-bold text-white mb-2">{getTitle()}</h1>
                <p className="text-gray-400">{getSubtitle()}</p>
              </div>

              {purpose === 'organization' && (
                <div className="space-y-3">
                  <button
                    onClick={() => handleOrgTypeSelect('boss')}
                    className="group w-full flex items-center gap-4 p-4 rounded-xl bg-[#111827] border border-[#1e293b] hover:border-purple-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/5"
                  >
                    <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center group-hover:scale-105 transition-transform">
                      <Shield size={24} className="text-purple-400" />
                    </div>
                    <div className="flex-1 text-left">
                      <h3 className="text-base font-semibold text-white">Admin / Boss</h3>
                      <p className="text-xs text-gray-500">Create and manage organization</p>
                    </div>
                    <div className="w-6 h-6 rounded-full border-2 border-gray-600 group-hover:border-purple-500 transition-all flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-purple-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </button>

                  <button
                    onClick={() => handleOrgTypeSelect('staff')}
                    className="group w-full flex items-center gap-4 p-4 rounded-xl bg-[#111827] border border-[#1e293b] hover:border-cyan-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5"
                  >
                    <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center group-hover:scale-105 transition-transform">
                      <Users size={24} className="text-cyan-400" />
                    </div>
                    <div className="flex-1 text-left">
                      <h3 className="text-base font-semibold text-white">Staff Member</h3>
                      <p className="text-xs text-gray-500">Join existing organization</p>
                    </div>
                    <div className="w-6 h-6 rounded-full border-2 border-gray-600 group-hover:border-cyan-500 transition-all flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </button>
                </div>
              )}

              {purpose === 'individual' && (
                <div className="space-y-4">
                  <button
                    onClick={() => { setStep('auth-form'); }}
                    className="w-full py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 text-white font-semibold hover:opacity-90 transition-opacity shadow-lg shadow-cyan-500/20"
                  >
                    Continue
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Success - Show org key to admin */}
          {step === 'success' && (
            <div className="space-y-8 animate-in">
              <div className="text-center">
                <div className="mx-auto w-16 h-16 rounded-full bg-green-500/20 border border-green-500/40 flex items-center justify-center mb-4">
                  <CheckCircle2 size={32} className="text-green-400" />
                </div>
                <h1 className="text-2xl font-bold text-white mb-2">Organization Created!</h1>
                <p className="text-gray-400 mb-6">
                  Your organization has been created. Share this key with your staff members
                  so they can join your organization.
                </p>
              </div>

              <div className="p-6 rounded-xl bg-[#111827] border border-[#1e293b] space-y-4">
                <label className="text-sm text-gray-400 font-medium">Organization Key</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 p-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b] font-mono text-lg text-cyan-400 text-center tracking-wider select-all">
                    {generatedOrgKey}
                  </div>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(generatedOrgKey);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-all"
                    title="Copy to clipboard"
                  >
                    {copied ? (
                      <CheckCircle2 size={20} />
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                    )}
                  </button>
                </div>
                <p className="text-xs text-yellow-500/80 flex items-center gap-1">
                  <Key size={12} />
                  Save this key — it won't be shown again after you proceed
                </p>
              </div>

              <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/30">
                <div className="flex items-start gap-3">
                  <Shield size={18} className="text-purple-400 mt-0.5 shrink-0" />
                  <div className="text-sm text-purple-300">
                    <p className="font-medium mb-1">What happens next?</p>
                    <ul className="text-purple-400/70 space-y-1 list-disc list-inside">
                      <li>Staff members use this key to register & login</li>
                      <li>You'll manage everything from the admin dashboard</li>
                      <li>You can generate more keys later in Settings</li>
                    </ul>
                  </div>
                </div>
              </div>

              <button
                onClick={() => {
                  // Retrieve userData from state since we stored org_key
                  onLogin({
                    ...JSON.parse(localStorage.getItem('cybernova_last_user') || '{}'),
                    org_key: generatedOrgKey,
                  } as User);
                }}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-500 text-white font-semibold hover:opacity-90 transition-opacity shadow-lg shadow-purple-500/20"
              >
                Go to Dashboard
              </button>
            </div>
          )}

          {/* Step 3: Auth Form */}
          {step === 'auth-form' && (
            <div className="space-y-8 animate-in">
              <button 
                onClick={goBack}
                className="flex items-center gap-1 text-sm text-gray-500 hover:text-white transition-colors"
              >
                <ArrowLeft size={16} />
                <span>Back</span>
              </button>

              <div className="text-center lg:text-left">
                <h1 className="text-2xl font-bold text-white mb-2">{getTitle()}</h1>
                <p className="text-gray-400">{getSubtitle()}</p>
              </div>

              {/* Success Indicator */}
              <div className={`p-3 rounded-lg border ${
                isIndividual ? 'bg-cyan-500/10 border-cyan-500/30' :
                isOrgBoss ? 'bg-purple-500/10 border-purple-500/30' :
                'bg-cyan-500/10 border-cyan-500/30'
              }`}>
                <div className={`flex items-center gap-2 text-sm ${
                  isIndividual ? 'text-cyan-400' :
                  isOrgBoss ? 'text-purple-400' :
                  'text-cyan-400'
                }`}>
                  <CheckCircle2 size={16} />
                  <span>
                    {isIndividual && 'Admin + Viewer access (full control)'}
                    {isOrgBoss && 'Organization Admin - Full control'}
                    {isOrgStaff && 'Staff Member - Limited access'}
                  </span>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                    {error}
                  </div>
                )}

                <div className="space-y-3">
                  <div className="relative">
                    <UserIcon size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                      type="text"
                      id="username"
                      name="username"
                      autoComplete="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Username"
                      className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                    />
                  </div>

                  {isRegister && (
                    <div className="relative">
                      <Mail size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <input
                        type="email"
                        id="email"
                        name="email"
                        autoComplete="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Email address"
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                      />
                    </div>
                  )}

                  <div className="relative">
                    <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      id="password"
                      name="password"
                      autoComplete={isRegister ? 'new-password' : 'current-password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Password"
                      className="w-full pl-10 pr-12 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white transition-colors"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>

                  {/* Password Strength Indicator */}
                  {isRegister && password.length > 0 && (
                    <div className="space-y-2 animate-in">
                      {/* Strength Bar */}
                      <div className="h-1.5 w-full bg-[#1e293b] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ease-out ${
                            passwordStrength.level === 'weak' ? 'bg-red-500 w-1/4' :
                            passwordStrength.level === 'medium' ? 'bg-yellow-500 w-2/4' :
                            passwordStrength.level === 'strong' ? 'bg-green-500 w-full' : ''
                          }`}
                        />
                      </div>
                      {/* Requirements Checklist */}
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
                        {[
                          { key: 'length', label: '8+ characters' },
                          { key: 'uppercase', label: 'Uppercase letter' },
                          { key: 'lowercase', label: 'Lowercase letter' },
                          { key: 'digit', label: 'One number' },
                          { key: 'special', label: 'Special character' },
                        ].map((req) => {
                          const met = passwordStrength.checks[req.key as keyof typeof passwordStrength.checks];
                          return (
                            <div
                              key={req.key}
                              className={`flex items-center gap-1.5 transition-colors duration-200 ${
                                met ? 'text-green-400' : 'text-gray-500'
                              }`}
                            >
                              {met ? (
                                <CheckCircle2 size={11} className="shrink-0" />
                              ) : (
                                <XCircle size={11} className="shrink-0" />
                              )}
                              <span>{req.label}</span>
                            </div>
                          );
                        })}
                      </div>
                      {/* Strength Label */}
                      <div className="flex justify-end">
                        <span className={`text-[10px] uppercase tracking-wider font-semibold ${
                          passwordStrength.level === 'weak' ? 'text-red-400' :
                          passwordStrength.level === 'medium' ? 'text-yellow-400' :
                          passwordStrength.level === 'strong' ? 'text-green-400' : ''
                        }`}>
                          {passwordStrength.level === 'weak' ? 'Weak' :
                           passwordStrength.level === 'medium' ? 'Medium' :
                           passwordStrength.level === 'strong' ? 'Strong' : ''}
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Org Admin fields */}
                {isOrgBoss && isRegister && (
                  <div className="space-y-3 pt-2 border-t border-[#1e293b]">
                    <div className="relative">
                      <Briefcase size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <input
                        type="text"
                        id="companyName"
                        name="companyName"
                        autoComplete="organization"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                        placeholder="Company name *"
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                      />
                    </div>

                    <div className="relative">
                      <Mail size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <input
                        type="text"
                        id="companyDomain"
                        name="companyDomain"
                        autoComplete="off"
                        value={companyDomain}
                        onChange={(e) => setCompanyDomain(e.target.value)}
                        placeholder="Company domain (optional)"
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                      />
                    </div>

                    <div className="relative">
                      <Users size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <select
                        id="companySize"
                        name="companySize"
                        aria-label="Company size"
                        value={companySize}
                        onChange={(e) => setCompanySize(e.target.value)}
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white appearance-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                      >
                        <option value="" className="text-gray-500">Company size</option>
                        {COMPANY_SIZES.map(size => (
                          <option key={size.value} value={size.value}>{size.label}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                )}

                {/* Org Staff fields — shown for both register AND login */}
                {isOrgStaff && (
                  <div className="space-y-3 pt-2 border-t border-[#1e293b]">
                    <p className="text-xs text-cyan-400/80 px-1 font-medium">
                      {isRegister ? 'Enter the organization key from your admin to join' : 'Enter your organization key to sign in'}
                    </p>
                    <div className="relative">
                      <Key size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <input
                        type="text"
                        id="orgKey"
                        name="orgKey"
                        autoComplete="off"
                        value={orgKey}
                        onChange={(e) => setOrgKey(e.target.value)}
                        placeholder="Organization key *"
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#111827] border border-[#1e293b] text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 outline-none transition-all"
                      />
                    </div>
                    <p className="text-xs text-gray-500 px-1">
                      Get the organization key from your admin
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 text-white font-semibold hover:opacity-90 transition-opacity disabled:opacity-50 shadow-lg shadow-cyan-500/20"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      Processing...
                    </span>
                  ) : (
                    isRegister 
                      ? (isIndividual ? 'Start Protecting' : isOrgBoss ? 'Create Organization' : 'Join Organization')
                      : 'Sign In'
                  )}
                </button>
              </form>

              <div className="pt-4 border-t border-[#1e293b] text-center">
                <button
                  onClick={() => setIsRegister(!isRegister)}
                  className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  {isRegister 
                    ? 'Already have an account? Sign in' 
                    : "Don't have an account? Register"
                  }
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}