/**
 * CyberNova — Demo Data Generators
 * Provides realistic mock data for all frontend pages when backend is empty.
 * This prevents "blank page" syndrome and allows the UI to be fully demonstrable.
 */
import type {
  Alert, Incident, DashboardMetrics, SystemLog, NetworkConnection, ProcessInfo,
  ResponseAction, ThreatIntelItem, GlobalThreatFeed, AIAnalysis, Device,
  AuditLog, Playbook,
} from '../types';

let seeded = false;

// ── IP pools for realistic data ───────────────────────────────────────────
const MALICIOUS_IPS = [
  '45.33.32.156', '185.220.101.42', '91.121.87.34', '103.235.46.95',
  '5.188.62.14', '194.26.29.132', '51.75.64.193', '89.248.165.58',
  '162.247.74.203', '198.98.54.100', '23.129.64.214', '107.189.8.77',
];

const SAFE_IPS = [
  '10.0.0.1', '10.0.0.2', '10.0.1.50', '192.168.1.1',
  '192.168.1.100', '172.16.0.1', '172.16.0.50',
];

const HOSTNAMES = [
  'SRV-DC01',        // Domain Controller — Windows Server 2022
  'SRV-WEB01',       // Web Server — Ubuntu 22.04
  'WKS-042',         // Engineer Workstation — Windows 11
  'LAPTOP-MARK',     // Sales Laptop — macOS Sonoma
  'SRV-DB01',        // Database Server — Ubuntu 22.04
];

const USERS = ['admin', 'analyst1', 'engineer1', 'soc_lead'];

const ATTACK_TYPES = [
  { type: 'port_scan', desc: 'Port scan detected from external IP', rule: 'R101' },
  { type: 'brute_force', desc: 'Multiple failed SSH authentication attempts', rule: 'R204' },
  { type: 'malware', desc: 'Suspicious executable download detected', rule: 'R307' },
  { type: 'data_exfil', desc: 'Large outbound data transfer to unknown IP', rule: 'R412' },
  { type: 'dns_tunnel', desc: 'Suspicious DNS query pattern detected', rule: 'R518' },
  { type: 'web_attack', desc: 'SQL injection attempt on web application', rule: 'R623' },
  { type: 'lateral_movement', desc: 'Pass-the-hash attack detected between workstations', rule: 'R731' },
  { type: 'ransomware', desc: 'File encryption activity detected on endpoint', rule: 'R845' },
];

const SEVERITIES: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];

const SAMPLE_LOGS = [
  { source: 'kernel', message: 'iptables: IN=eth0 OUT= MAC=... SRC=45.33.32.156' },
  { source: 'sshd', message: 'Failed password for root from 185.220.101.42 port 22 ssh2' },
  { source: 'nginx', message: '403 GET /wp-admin/admin-ajax.php' },
  { source: 'suricata', message: 'ET POLICY curl User-Agent Outbound' },
  { source: 'syslog', message: 'CRON[1234]: (root) CMD /usr/bin/security_check' },
  { source: 'auth', message: 'pam_unix(sudo:auth): authentication failure' },
  { source: 'docker', message: 'Container cybernova-worker-1 exited with code 137' },
  { source: 'postgres', message: 'LOG: checkpoint starting: time' },
];

const PROCESS_NAMES = [
  { name: 'svchost.exe', user: 'SYSTEM', cpu: 2.3, memory: 1.2 },
  { name: 'explorer.exe', user: 'admin', cpu: 0.8, memory: 3.5 },
  { name: 'chrome.exe', user: 'admin', cpu: 15.2, memory: 22.4 },
  { name: 'powershell.exe', user: 'admin', cpu: 0.5, memory: 1.8 },
  { name: 'cybernova_agent.exe', user: 'SYSTEM', cpu: 1.1, memory: 0.9 },
  { name: 'python.exe', user: 'admin', cpu: 4.2, memory: 6.7 },
  { name: 'msedge.exe', user: 'admin', cpu: 8.9, memory: 14.2 },
  { name: 'windefend.exe', user: 'SYSTEM', cpu: 3.4, memory: 5.1 },
];

const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'];

// ── Helpers ───────────────────────────────────────────────────────────────
function rand(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pick<T>(arr: T[]): T {
  return arr[rand(0, arr.length - 1)];
}

function pickN<T>(arr: T[], n: number): T[] {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

function recentDate(hoursAgo: number): string {
  return new Date(Date.now() - hoursAgo * 3600000).toISOString();
}

// ── Alert Generator ───────────────────────────────────────────────────────
function generateAlert(index: number): Alert {
  const attack = pick(ATTACK_TYPES);
  const severity = SEVERITIES[index % 4];
  const hoursAgo = rand(0, 48);
  const maliciousIp = pick(MALICIOUS_IPS);
  return {
    alert_id: `ALT-${String(1000 + index)}`,
    type: attack.type,
    risk_score: severity === 'critical' ? rand(85, 99) : severity === 'high' ? rand(70, 84) : severity === 'medium' ? rand(40, 69) : rand(10, 39),
    severity,
    timestamp: recentDate(hoursAgo),
    status: index < 3 ? 'open' : index < 6 ? 'investigating' : 'closed',
    source_ip: maliciousIp,
    destination_ip: pick(SAFE_IPS),
    description: attack.desc,
    rule_id: attack.rule,
    affected_system: pick(HOSTNAMES),
    investigation: {
      threat_intel: {
        verified: true,
        verdict: 'Malicious',
        sources: ['VirusTotal', 'AbuseIPDB', 'OTX'],
        risk_level: severity.toUpperCase(),
        virustotal: { malicious: true, detections: rand(3, 18) },
        abuseipdb: { confidence_score: rand(60, 100), country_code: pick(['RU', 'CN', 'US', 'NL', 'DE']) },
        otx: { pulses: rand(2, 12), is_malicious: true },
      },
      geo_location: {
        country: pick(['Russia', 'China', 'Netherlands', 'Germany', 'United States']),
        city: pick(['Moscow', 'Beijing', 'Amsterdam', 'Frankfurt', 'Los Angeles']),
        isp: pick(['DigitalOcean', 'Hetzner', 'OVH', 'Linode', 'Contabo']),
      },
      enrichment_sources: ['GeoIP', 'WHOIS', 'ThreatFox'],
    },
  };
}

// ── Incident Generator ────────────────────────────────────────────────────
function generateIncident(index: number): Incident {
  const severities: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];
  const severity = severities[index % 4];
  const hoursAgo = rand(1, 72);

  return {
    incident_id: `INC-${String(2000 + index)}`,
    title: pick([
      'Multi-stage ransomware campaign targeting file servers',
      'Lateral movement detected across engineering workstations',
      'Data exfiltration via encrypted DNS tunneling',
      'Supply chain attack — compromised package in CI/CD pipeline',
      'Credential harvesting campaign targeting VPN credentials',
      'DDoS amplification attack using misconfigured memcached servers',
    ]),
    severity,
    status: index < 2 ? 'open' : index < 4 ? 'investigating' : index < 6 ? 'contained' : 'resolved',
    created_at: recentDate(hoursAgo),
    updated_at: recentDate(rand(0, hoursAgo)),
    related_alerts: Array.from({ length: rand(2, 5) }, () => `ALT-${rand(1000, 1010)}`),
    affected_systems: pickN(HOSTNAMES, rand(1, 4)),
    description: `Investigation ongoing: ${pick(['multiple hosts affected', 'indicator of compromise confirmed', 'containment in progress', 'root cause analysis pending'])}. Priority: ${severity === 'critical' ? 'Immediate containment required' : severity === 'high' ? 'Escalate to SOC lead' : 'Standard investigation procedure'}.`,
    attack_chain: [
      { phase: 'Initial Access', technique: pick(['Phishing', 'Exploit Public-Facing Application', 'Valid Accounts']), status: 'completed', timestamp: recentDate(hoursAgo + 2) },
      { phase: 'Execution', technique: pick(['PowerShell', 'Windows Management Instrumentation', 'Scheduled Task']), status: 'completed', timestamp: recentDate(hoursAgo + 1) },
      { phase: 'Persistence', technique: pick(['Registry Run Keys', 'Scheduled Task', 'Service Installation']), status: index < 3 ? 'in_progress' : 'completed', timestamp: recentDate(rand(0, hoursAgo)) },
      { phase: 'Lateral Movement', technique: pick(['Pass-the-Hash', 'Remote Desktop Protocol', 'SMB/Windows Admin Shares']), status: index < 5 ? 'in_progress' : 'blocked', timestamp: recentDate(rand(0, Math.max(0, hoursAgo - 1))) },
      { phase: 'Exfiltration', technique: pick(['DNS Tunneling', 'HTTPS', 'FTP']), status: index < 5 ? 'in_progress' : 'blocked', timestamp: recentDate(rand(0, Math.max(0, hoursAgo - 2))) },
    ],
    timeline: Array.from({ length: rand(3, 6) }, (_, i) => ({
      id: uuid(),
      timestamp: recentDate(rand(0, hoursAgo)),
      type: pick(['alert', 'detection', 'action', 'response'] as const),
      title: pick(['Alert triggered', 'Incident created', 'SOAR action executed', 'Analyst assigned', 'Containment initiated']),
      description: pick(['Automatic detection', 'Analyst review pending', 'Block action completed', 'Evidence collected']),
      severity: i === 0 ? severity : undefined,
    })),
    assigned_to: pick(USERS),
  };
}

// ── Metric Generator ──────────────────────────────────────────────────────
function generateMetrics(): DashboardMetrics {
  return {
    total_alerts: rand(25, 150),
    active_incidents: rand(2, 8),
    risk_score: rand(15, 45),
    system_health: rand(88, 99),
    alerts_today: rand(5, 30),
    blocked_ips: rand(8, 45),
    threats_mitigated: rand(12, 60),
    uptime: 99.9,
    total_devices: rand(3, 25),
    active_devices: rand(2, 20),
    critical_alerts: rand(1, 5),
    incidents_open: rand(1, 4),
    active_threats: rand(1, 8),
    devices_at_risk: rand(0, 3),
    severity_counts: {
      critical: rand(1, 5),
      high: rand(3, 10),
      medium: rand(5, 20),
      low: rand(10, 40),
    },
  };
}

// ── Response Action Generator ─────────────────────────────────────────────
function generateResponseActions(): ResponseAction[] {
  const actionTypes: Array<ResponseAction['action_type']> = ['block_ip', 'isolate_device', 'kill_process', 'trigger_automation'];
  return Array.from({ length: rand(5, 12) }, (_, i) => ({
    id: uuid(),
    action_type: actionTypes[i % 4],
    target: i % 2 === 0 ? pick(MALICIOUS_IPS) : pick(HOSTNAMES),
    status: pick(['completed', 'completed', 'completed', 'failed', 'pending'] as const),
    initiated_by: pick(USERS),
    timestamp: recentDate(rand(0, 72)),
    result: pick(['Success', 'Target blocked at firewall', 'Device isolated from network', 'Process terminated', 'Automation triggered successfully', 'Failed: target unreachable']),
  }));
}

// ── Device Generator ──────────────────────────────────────────────────────
function generateDevices(): Device[] {
  // 5 realistic servers with varied statuses for boss dashboard
  const deviceConfigs = [
    { hostname: 'SRV-DC01', ip: '10.0.0.10', os: 'Windows Server 2022', status: 'active' as const, risk: 8, active: true },
    { hostname: 'SRV-WEB01', ip: '10.0.0.20', os: 'Ubuntu 22.04', status: 'active' as const, risk: 15, active: true },
    { hostname: 'WKS-042', ip: '10.0.1.42', os: 'Windows 11', status: 'active' as const, risk: 22, active: true },
    { hostname: 'LAPTOP-MARK', ip: '10.0.1.55', os: 'macOS Sonoma', status: 'error' as const, risk: 65, active: true },
    { hostname: 'SRV-DB01', ip: '10.0.0.30', os: 'Ubuntu 22.04', status: 'active' as const, risk: 5, active: true },
  ];
  return deviceConfigs.map((cfg, i) => ({
    id: `DEV-${String(3000 + i)}`,
    hostname: cfg.hostname,
    ip_address: cfg.ip,
    os_type: cfg.os,
    status: cfg.status,
    last_heartbeat: recentDate(rand(0, 2)),
    tenant_id: 'default',
    is_active: cfg.active,
    risk_score: cfg.risk,
  }));
}

// ── Log Generator ─────────────────────────────────────────────────────────
function generateLogs(): SystemLog[] {
  return Array.from({ length: rand(20, 40) }, () => {
    const log = pick(SAMPLE_LOGS);
    return {
      id: uuid(),
      timestamp: recentDate(rand(0, 24)),
      level: pick(['info', 'info', 'info', 'warn', 'error'] as const),
      source: log.source,
      message: log.message,
      host: pick(HOSTNAMES),
    };
  });
}

// ── Network Connection Generator ──────────────────────────────────────────
function generateConnections(): NetworkConnection[] {
  return Array.from({ length: rand(8, 20) }, (_, i) => {
    const isMalicious = i % 5 === 0;
    return {
      id: uuid(),
      source_ip: isMalicious ? pick(MALICIOUS_IPS) : pick(SAFE_IPS),
      destination_ip: isMalicious ? pick(SAFE_IPS) : pick(SAFE_IPS),
      protocol: pick(PROTOCOLS),
      port: isMalicious ? pick([22, 4444, 8443, 3389, 445]) : pick([80, 443, 53, 8080]),
      status: isMalicious ? 'blocked' : pick(['active', 'active', 'closed'] as const),
      bytes_sent: rand(100, 100000),
      bytes_received: rand(200, 500000),
      timestamp: recentDate(rand(0, 12)),
    };
  });
}

// ── Process Generator ─────────────────────────────────────────────────────
function generateProcesses(): ProcessInfo[] {
  return PROCESS_NAMES.map((p, idx) => ({
    pid: 1000 + idx * 123 + rand(0, 100),
    name: p.name,
    cpu: p.cpu + (Math.random() * 2 - 1),
    memory: p.memory + (Math.random() * 2 - 1),
    user: p.user,
    status: pick(['running', 'running', 'running', 'sleeping'] as const),
    started_at: recentDate(rand(0, 72)),
    command: p.name,
    risk_score: p.name === 'powershell.exe' ? rand(30, 60) : rand(1, 20),
  }));
}

// ── Threat Intel Generator ────────────────────────────────────────────────
function generateThreatIntel(): ThreatIntelItem[] {
  return MALICIOUS_IPS.slice(0, rand(4, 8)).map((ip, i) => ({
    id: uuid(),
    indicator: ip,
    type: 'ip',
    risk_score: i < 2 ? rand(85, 98) : i < 4 ? rand(60, 84) : rand(30, 59),
    source: pick(['VirusTotal', 'AbuseIPDB', 'OTX', 'ThreatFox']),
    last_seen: recentDate(rand(0, 72)),
    tags: pickN(['malware', 'c2', 'scanner', 'brute-force', 'phishing', 'ransomware', 'proxy', 'tor'], rand(2, 4)),
    description: pick([
      'Known C2 server for multiple malware families',
      'Active SSH brute-force scanner',
      'Reported phishing infrastructure',
      'Mirai variant command server',
      'Dark web marketplace node',
    ]),
    country: pick(['RU', 'CN', 'NL', 'US', 'DE', 'UA']),
  }));
}

// ── Global Feed Generator ─────────────────────────────────────────────────
function generateGlobalFeed(): GlobalThreatFeed[] {
  return [
    {
      id: uuid(), title: 'Critical: New Ransomware Variant "CyberLocker" Spreading Rapidly',
      description: 'A new ransomware variant is targeting unpatched RDP servers globally. Includes worm-like propagation capabilities.',
      severity: 'critical', source: 'CISA Alert (AA24-XXX)',
      published_at: recentDate(rand(0, 8)), iocs: pickN(MALICIOUS_IPS, 3),
    },
    {
      id: uuid(), title: 'APT Group "NovaStorm" Observed Targeting Cloud Infrastructure',
      description: 'Advanced persistent threat group exploiting misconfigured Kubernetes clusters for cryptomining and data exfiltration.',
      severity: 'high', source: 'Microsoft Threat Intelligence',
      published_at: recentDate(rand(8, 24)), iocs: pickN(MALICIOUS_IPS, 3),
    },
    {
      id: uuid(), title: 'Zero-Day Exploit in Widely Used VPN Appliance',
      description: 'Proof-of-concept exploit published for CVE-2024-XXX. Affects major VPN gateway products. Patch immediately.',
      severity: 'critical', source: 'NVD / MITRE',
      published_at: recentDate(rand(24, 48)), iocs: pickN(MALICIOUS_IPS, 2),
    },
    {
      id: uuid(), title: 'Phishing Campaign Targeting Security Researchers',
      description: 'Sophisticated spear-phishing campaign using fake vulnerability reports to deliver info-stealer malware.',
      severity: 'medium', source: 'Google TAG',
      published_at: recentDate(rand(48, 72)), iocs: pickN(MALICIOUS_IPS, 2),
    },
  ];
}

// ── AI Analysis Generator ─────────────────────────────────────────────────
function generateAIAnalysis(incidentId?: string): AIAnalysis {
  const confidence = rand(65, 95);
  return {
    incident_id: incidentId || `INC-${rand(2000, 2010)}`,
    summary: `AI investigation completed with ${confidence}% confidence. Analysis of ${rand(3, 8)} correlated alerts indicates an ongoing ${pick(['ransomware', 'data exfiltration', 'lateral movement', 'credential harvesting'])} campaign. The attack pattern matches known threat actor group ${pick(['TA577', 'APT29', 'FIN7', 'SilentLynx'])}.`,
    attack_narrative: `The attack began with a spear-phishing email containing a malicious attachment.\n\nStage 1 (Initial Access): User executed a malicious macro that established a C2 connection to ${pick(MALICIOUS_IPS)}.\n\nStage 2 (Execution): PowerShell was used to download and execute additional payloads, including a keylogger and credential dumper.\n\nStage 3 (Lateral Movement): Using harvested credentials, the attacker moved laterally to ${pickN(HOSTNAMES, 2).join(' and ')} via RDP.\n\nStage 4 (Goal): ${pick(['Files were encrypted with ransomware demands', 'Sensitive data was exfiltrated via encrypted channels', 'Persistence mechanisms were installed for long-term access'])}.`,
    risk_assessment: `CRITICAL — Active threat with confirmed data access. Multiple hosts compromised. Immediate containment and eradication required. Patching vulnerabilities, rotating all credentials, and initiating incident response procedures are strongly recommended. Estimated recovery time: ${rand(24, 72)} hours.`,
    recommended_actions: [
      `Isolate affected hosts: ${pickN(HOSTNAMES, 2).join(', ')}`,
      'Reset all domain account passwords and revoke Kerberos tickets',
      'Block C2 communication channels at perimeter firewall',
      'Deploy updated EDR signatures across all endpoints',
      `Conduct forensic analysis on ${pick(HOSTNAMES)}`,
      'Enable enhanced logging for all critical systems',
      'Review and revoke any suspicious privileged access',
    ],
    confidence,
    timeline_reconstruction: Array.from({ length: rand(3, 6) }, (_, i) => ({
      id: uuid(),
      timestamp: recentDate(rand(0, 48)),
      type: i === 0 ? 'alert' : i === 1 ? 'detection' : i === 2 ? 'action' : i === 3 ? 'response' : 'note',
      title: pick(['First alert triggered', 'Correlation identified', 'SOAR action dispatched', 'Incident escalated', 'Forensic acquisition started']),
      description: pick(['Pattern matched known IOCs', 'Threat intelligence confirmation received', 'Automated block action executed']),
      severity: i === 0 ? 'critical' : i < 3 ? 'high' : undefined,
    })),
    mitre_techniques: pickN(['T1566.001', 'T1059.001', 'T1003.001', 'T1021.001', 'T1486', 'T1041', 'T1098', 'T1071.001'], rand(3, 6)),
    affected_assets: pickN(HOSTNAMES, rand(2, 4)).map(h => `${h}.cybernova.internal`),
    threat_profile: {
      'Persistence': rand(40, 90),
      'Lateral Movement': rand(50, 95),
      'Exfiltration': rand(30, 85),
      'Privilege Escalation': rand(45, 80),
      'Evasion': rand(35, 75),
      'Impact': rand(60, 100),
    },
  };
}

// ── Audit Log Generator ───────────────────────────────────────────────────
function generateAuditLogs(): AuditLog[] {
  const actions = ['user.login', 'user.logout', 'settings.update', 'policy.create', 'alert.acknowledge', 'incident.update', 'device.isolate', 'rule.toggle', 'user.role_change', 'backup.start', 'backup.complete'];
  return Array.from({ length: rand(15, 30) }, () => ({
    id: uuid(),
    timestamp: recentDate(rand(0, 168)),
    user_id: pick(USERS),
    action: pick(actions),
    resource_type: pick(['alert', 'incident', 'device', 'user', 'rule', 'settings']),
    resource_id: uuid(),
    details: { description: pick(['Action performed via UI', 'Automated action by SOAR', 'API call from agent']) },
    ip_address: pick(['10.0.0.1', '10.0.1.50', '192.168.1.100']),
  }));
}

// ── Playbook Generator ────────────────────────────────────────────────────
function generatePlaybooks(): Playbook[] {
  return [
    { id: 'PB-001', name: 'Auto-Block Malicious IPs', priority: 1, severity_action: 'critical', condition: { min_risk_score: 80 }, actions: [{ type: 'block_ip', params: { duration_hours: 24 } }], automated: true },
    { id: 'PB-002', name: 'Isolate Compromised Endpoint', priority: 2, severity_action: 'high', condition: { severity: ['critical', 'high'] }, actions: [{ type: 'isolate_device', params: {} }], automated: true },
    { id: 'PB-003', name: 'Notify SOC on Brute Force', priority: 3, severity_action: 'medium', condition: { rule_name: ['brute_force'] }, actions: [{ type: 'send_notification', params: { channel: 'slack' } }], automated: false },
  ];
}

// ── Auto-seed guard ──────────────────────────────────────────────────────
function ensureSeeded() {
  if (!seeded) seedDemoDataInternal();
}

// ── Seeder ────────────────────────────────────────────────────────────────
let storedAlerts: Alert[] = [];
let storedIncidents: Incident[] = [];
let storedMetrics: DashboardMetrics | null = null;
let storedDevices: Device[] = [];
let storedLogs: SystemLog[] = [];
let storedConnections: NetworkConnection[] = [];
let storedProcesses: ProcessInfo[] = [];
let storedThreatIntel: ThreatIntelItem[] = [];
let storedGlobalFeed: GlobalThreatFeed[] = [];
let storedResponseActions: ResponseAction[] = [];
let storedAuditLogs: AuditLog[] = [];
let storedPlaybooks: Playbook[] = [];

function seedDemoDataInternal() {
  if (seeded) return;
  seeded = true;

  storedAlerts = Array.from({ length: 12 }, (_, i) => generateAlert(i));
  storedIncidents = Array.from({ length: 8 }, (_, i) => generateIncident(i));
  storedMetrics = generateMetrics();
  storedDevices = generateDevices();
  storedLogs = generateLogs();
  storedConnections = generateConnections();
  storedProcesses = generateProcesses();
  storedThreatIntel = generateThreatIntel();
  storedGlobalFeed = generateGlobalFeed();
  storedResponseActions = generateResponseActions();
  storedAuditLogs = generateAuditLogs();
  storedPlaybooks = generatePlaybooks();
}

export function seedDemoData() {
  seedDemoDataInternal();
}

export function getDemoAlerts(): Alert[] { ensureSeeded(); return storedAlerts; }
export function getDemoIncidents(): Incident[] { ensureSeeded(); return storedIncidents; }
export function getDemoMetrics(): DashboardMetrics | null { ensureSeeded(); return storedMetrics; }
export function getDemoDevices(): Device[] { ensureSeeded(); return storedDevices; }
export function getDemoLogs(): SystemLog[] { ensureSeeded(); return storedLogs; }
export function getDemoConnections(): NetworkConnection[] { ensureSeeded(); return storedConnections; }
export function getDemoProcesses(): ProcessInfo[] { ensureSeeded(); return storedProcesses; }
export function getDemoThreatIntel(): ThreatIntelItem[] { ensureSeeded(); return storedThreatIntel; }
export function getDemoGlobalFeed(): GlobalThreatFeed[] { ensureSeeded(); return storedGlobalFeed; }
export function getDemoResponseActions(): ResponseAction[] { ensureSeeded(); return storedResponseActions; }
export function getDemoAIAnalysis(incidentId?: string): AIAnalysis { ensureSeeded(); return generateAIAnalysis(incidentId); }
export function getDemoAuditLogs(): AuditLog[] { ensureSeeded(); return storedAuditLogs; }
export function getDemoPlaybooks(): Playbook[] { ensureSeeded(); return storedPlaybooks; }
