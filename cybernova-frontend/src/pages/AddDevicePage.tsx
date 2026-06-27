import { useState, useEffect } from 'react';
import { Copy, Check, Monitor, Server, ExternalLink, Shield, ArrowRight } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { fetchDevices } from '../services/api';
import { useAuthStore } from '../stores/useAuthStore';

export function AddDevicePage() {
  const authToken = useAuthStore(s => s.user?.token);
  const [copied, setCopied] = useState<string | null>(null);
  const [deviceCount, setDeviceCount] = useState(0);
  // Use the SAME URL the browser uses — agent goes through nginx, not direct port 8000
  const apiUrl = window.location.origin;

  useEffect(() => {
    fetchDevices().then(devices => setDeviceCount(devices.length)).catch(() => {});
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const token = authToken || '';
  const linuxCmd = `CYBERNOVA_API_URL=${apiUrl} CYBERNOVA_TOKEN=${token} curl -s ${apiUrl}/agent.sh | python3`;
  const windowsInstallCmd = `$env:CYBERNOVA_API_URL=\"${apiUrl}\"; $env:CYBERNOVA_TOKEN=\"${token}\"; irm ${apiUrl}/agent.ps1 | iex`;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-cyber-text">Add Device</h1>
        <p className="text-sm text-cyber-muted mt-1">
          Install the CyberNova agent to start ingesting real security events. {deviceCount > 0 && `(${deviceCount} device${deviceCount > 1 ? 's' : ''} connected)`}
        </p>
      </div>

      {/* Steps */}
      <div className="grid gap-3 sm:grid-cols-3">
        {[          {step: '1', title: 'Install Agent', desc: 'One command installs the agent permanently' },
          { step: '2', title: 'Auto-Detection', desc: 'Device appears in CyberNova within seconds' },
          { step: '3', title: 'See Alerts', desc: 'Security events are analyzed in real-time' },
        ].map((s) => (
          <div key={s.step} className="flex items-start gap-3 rounded-xl border border-cyber-border bg-cyber-card p-4">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-xs font-bold text-cyan-400">
              {s.step}
            </div>
            <div>
              <p className="text-sm font-medium text-cyber-text">{s.title}</p>
              <p className="text-xs text-cyber-muted">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Windows — Persistent Installer (Recommended) */}
        <Card>
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-blue-500/20 flex items-center justify-center">
              <Monitor size={20} className="text-blue-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-cyber-text">Windows Agent</h3>
              <p className="text-xs text-cyber-muted">Installs as a real app — runs 24/7</p>
            </div>
          </div>
          <div className="mb-3 p-2 rounded-lg bg-green-500/10 border border-green-500/30">
            <p className="text-[11px] text-green-400 flex items-center gap-1">
              <Shield size={11} /> Recommended — runs in background, starts on boot, no terminal needed
            </p>
          </div>
          <p className="text-xs text-cyber-muted mb-3">Run in PowerShell (Admin):</p>
          <div className="relative">
            <pre className="rounded-lg bg-cyber-bg border border-cyber-border p-4 pr-12 overflow-x-auto text-xs text-cyber-text font-mono whitespace-pre-wrap">
              {windowsInstallCmd}
            </pre>
            <button
              onClick={() => copyToClipboard(windowsInstallCmd, 'windows')}
              className="absolute right-3 top-3 rounded-md p-1.5 text-cyber-muted hover:bg-cyber-border hover:text-cyber-text transition-colors"
            >
              {copied === 'windows' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
            </button>
          </div>
          <div className="mt-4 p-3 rounded-lg bg-cyber-bg/50 border border-cyber-border/50">
            <p className="text-[11px] text-cyber-muted">
              Installs to Program Files. Creates desktop icon, auto-starts on boot. No terminal window needed.
            </p>
          </div>
        </Card>

        {/* Linux — Persistent Installer */}
        <Card>
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-orange-500/20 flex items-center justify-center">
              <Server size={20} className="text-orange-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-cyber-text">Linux Agent</h3>
              <p className="text-xs text-cyber-muted">Systemd service — runs 24/7</p>
            </div>
          </div>
          <div className="mb-3 p-2 rounded-lg bg-green-500/10 border border-green-500/30">
            <p className="text-[11px] text-green-400 flex items-center gap-1">
              <Shield size={11} /> Installs as systemd service — auto-starts on boot
            </p>
          </div>
          <p className="text-xs text-cyber-muted mb-3">Run in terminal:</p>
          <div className="relative">
            <pre className="rounded-lg bg-cyber-bg border border-cyber-border p-4 pr-12 overflow-x-auto text-xs text-cyber-text font-mono whitespace-pre-wrap">
              {linuxCmd}
            </pre>
            <button
              onClick={() => copyToClipboard(linuxCmd, 'linux')}
              className="absolute right-3 top-3 rounded-md p-1.5 text-cyber-muted hover:bg-cyber-border hover:text-cyber-text transition-colors"
            >
              {copied === 'linux' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
            </button>
          </div>
          <div className="mt-4 p-3 rounded-lg bg-cyber-bg/50 border border-cyber-border/50">
            <p className="text-[11px] text-cyber-muted">
              Reads: /var/log/auth.log, /var/log/syslog. Registers as systemd service for persistence.
            </p>
          </div>
        </Card>
      </div>

      {/* Manual Download */}
      <Card>
        <h3 className="text-sm font-semibold text-cyber-text mb-3">Manual Download</h3>
        <div className="flex flex-wrap gap-3">
          <a
            href={`${apiUrl}/agent.ps1`}
            download
            className="flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2 text-xs text-cyber-text hover:bg-cyber-border/50 transition-colors"
          >
            <ExternalLink size={12} /> Download agent.ps1
          </a>
          <a
            href={`${apiUrl}/agent.sh`}
            download
            className="flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-bg px-4 py-2 text-xs text-cyber-text hover:bg-cyber-border/50 transition-colors"
          >
            <ExternalLink size={12} /> Download agent.sh
          </a>
        </div>
      </Card>

      {/* What happens after install */}
      <Card>
        <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
          <Shield size={16} className="text-cyan-400" />
          What Happens After Install
        </h3>
        <div className="space-y-2">
          {[
            'Device auto-registers with CyberNova',
            'System logs are collected every 5 seconds',
            'Events are normalized and enriched',
            'Detection rules evaluate for threats',
            'Alerts appear here automatically',
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-3 text-sm text-cyber-muted">
              <ArrowRight size={14} className="text-cyan-400 shrink-0" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
