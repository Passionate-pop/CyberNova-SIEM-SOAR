// ================== User/Auth ==================
export type Page = 'dashboard' | 'devices' | 'users' | 'alerts' | 'incidents' | 'monitoring' | 'logs' | 'response' | 'threat-intel' | 'ai-investigation' | 'mitre' | 'settings' | 'audit-logs' | 'analytics' | 'add-device' | 'rate-limits';

export interface User {
  id: string;
  username: string;
  email?: string;
  role: UserRole;
  roles?: UserRole[];
  permissions?: (typeof PERMISSIONS[keyof typeof PERMISSIONS] | string)[]; // flexible: backend may add new permissions over time
  tenant_id?: string;
  token: string;
  // Organization fields (used by LoginPage/OnboardingPage)
  purpose?: UserPurpose;
  org_type?: OrgType;
  org_name?: string;
  company_size?: string;
  org_key?: string; // One-time org key returned after admin registration
}

export type UserRole = 'admin' | 'analyst' | 'viewer';
export type UserPurpose = 'individual' | 'organization';
export type OrgType = 'boss' | 'staff';

export interface LoginCredentials {
  username: string;
  password: string;
  org_key?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  org_key?: string;
  purpose?: string;
  org_type?: string;
  org_name?: string;
  company_size?: string;
}

// ================== Alerts / Incidents ==================
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'open' | 'investigating' | 'closed';

export interface Alert {
  alert_id: string;
  type: string;
  risk_score: number;
  severity: Severity;
  timestamp: string;
  status: AlertStatus;
  source_ip: string;
  destination_ip: string;
  description: string;
  rule_id: string;
  affected_system: string;
  investigation?: {
    threat_intel?: ThreatIntel;
    geo_location?: GeoLocation;
    enrichment_sources?: string[];
    raw_event?: Record<string, unknown>;
    alert_reason?: string;
  };
}

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved';

export interface Incident {
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  related_alerts: string[];
  affected_systems: string[];
  attack_chain: AttackChainStep[];
  timeline: TimelineEvent[];
  assigned_to: string;
  description: string;
}

export interface AttackChainStep {
  phase: string;
  technique: string;
  status: 'completed' | 'blocked' | 'in_progress';
  timestamp: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'alert' | 'action' | 'detection' | 'response' | 'note';
  title: string;
  description: string;
  severity?: Severity;
}

// ================== Dashboard ==================
export interface DashboardMetrics {
  total_alerts: number;
  active_incidents: number;
  risk_score: number;
  system_health: number;
  alerts_today: number;
  blocked_ips: number;
  threats_mitigated: number;
  uptime: number;
  // Executive dashboard fields
  total_devices?: number;
  active_devices?: number;
  critical_alerts?: number;
  incidents_open?: number;
  active_threats?: number;
  devices_at_risk?: number;
  severity_counts?: Record<string, number>;
}

export interface TopThreat {
  name: string;
  count: number;
  severity: Severity;
  trend: 'up' | 'down' | 'stable';
}

export interface SystemLog {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  source: string;
  message: string;
  host: string;
}

export interface NetworkConnection {
  id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: number;
  status: 'active' | 'closed' | 'blocked';
  bytes_sent: number;
  bytes_received: number;
  timestamp: string;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  user: string;
  status: 'running' | 'sleeping' | 'stopped' | 'zombie';
  started_at: string;
  command: string;
  risk_score: number;
}

// ================== Playbooks ==================
export interface PlaybookAction {
  type: string;
  params: Record<string, unknown>;
}

export interface PlaybookCondition {
  severity?: string[];
  min_risk_score?: number;
  rule_name?: string[];
}

export interface Playbook {
  id: string;
  name: string;
  priority: number;
  severity_action: string;
  condition: PlaybookCondition;
  actions: PlaybookAction[];
  automated: boolean;
}

// ================== Response / Actions ==================
export type ActionType = 'block_ip' | 'unblock_ip' | 'kill_process' | 'isolate_device' | 'trigger_automation' | 'send_notification' | 'create_ticket';

export interface ResponseAction {
  id?: string;
  action_type: ActionType;
  target: string;
  status?: 'pending' | 'executing' | 'completed' | 'failed';
  initiated_by?: string;
  executed_at?: string;
  timestamp?: string;
  result?: string;
}

// ================== Threat Intelligence ==================
export interface ThreatIntelItem {
  id: string;
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url';
  risk_score: number;
  source: string;
  last_seen: string;
  tags: string[];
  description: string;
  country?: string;
}

export interface GlobalThreatFeed {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  source: string;
  published_at: string;
  iocs: string[];
}

// ================== AI ==================
export interface AIAnalysis {
  incident_id?: string;
  summary: string;
  attack_narrative: string;
  risk_assessment: string;
  recommended_actions: string[];
  confidence: number;
  timeline_reconstruction: TimelineEvent[];
  mitre_techniques: string[];
  affected_assets: string[];
  threat_profile?: Record<string, number>;
}

// ================== Rules ==================
export interface RuleConfig {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: Severity;
  category: string;
}

// ================== Device ==================
export type DeviceStatus = 'active' | 'offline' | 'isolated' | 'error';

export interface Device {
  id: string;
  hostname: string;
  ip_address: string;
  os_type?: string;
  status: DeviceStatus;
  last_heartbeat?: string;
  tenant_id: string;
  // Optional extended fields (may be populated by future backend enhancements)
  os_version?: string;
  mac_address?: string;
  agent_version?: string;
  is_active?: boolean;
  is_isolated?: boolean;
  risk_score?: number;
  owner_id?: string;
}

// ================== Audit ==================
export interface AuditLog {
  id: string;
  timestamp: string;
  user_id: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
}

// ================== Permissions ==================
export const PERMISSIONS = {
  // Users
  USERS_VIEW: 'users:view',
  USERS_CREATE: 'users:create',
  USERS_UPDATE: 'users:update',
  USERS_DELETE: 'users:delete',
  // Alerts
  ALERTS_VIEW: 'alerts:view',
  ALERTS_UPDATE: 'alerts:update',
  ALERTS_DELETE: 'alerts:delete',
  // Incidents
  INCIDENTS_VIEW: 'incidents:view',
  INCIDENTS_UPDATE: 'incidents:update',
  INCIDENTS_DELETE: 'incidents:delete',
  // Devices
  DEVICES_VIEW: 'devices:view',
  DEVICES_MANAGE: 'devices:manage',
  // Rules / Detection
  RULES_VIEW: 'rules:view',
  RULES_CREATE: 'rules:create',
  RULES_UPDATE: 'rules:update',
  RULES_DELETE: 'rules:delete',
  // Dashboard
  DASHBOARD_VIEW: 'dashboard:view',
  // Settings
  SETTINGS_VIEW: 'settings:view',
  SETTINGS_UPDATE: 'settings:update',
  // Audit
  AUDIT_VIEW: 'audit:view',
  // Pipeline
  PIPELINE_VIEW: 'pipeline:view',
  PIPELINE_MANAGE: 'pipeline:manage',
  // Automation
  AUTOMATION_VIEW: 'automation:view',
  AUTOMATION_TRIGGER: 'automation:trigger',
  // Threat Intelligence
  THREAT_INTEL_VIEW: 'threat_intel:view',
  THREAT_INTEL_MANAGE: 'threat_intel:manage',
  // Analytics
  ANALYTICS_VIEW: 'analytics:view',
  // Data
  DATA_EXPORT: 'data:export',
  DATA_DELETE: 'data:delete',
  // Testing
  TESTING_VIEW: 'testing:view',
  TESTING_EXECUTE: 'testing:execute',
  // Agent
  AGENT_VIEW: 'agent:view',
  AGENT_MANAGE: 'agent:manage',
  // Isolation
  ISOLATION_VIEW: 'isolation:view',
  ISOLATION_MANAGE: 'isolation:manage',
  // Retention
  RETENTION_VIEW: 'retention:view',
  RETENTION_MANAGE: 'retention:manage',
  // Integrations
  INTEGRATIONS_VIEW: 'integrations:view',
  INTEGRATIONS_MANAGE: 'integrations:manage',
  // Notifications
  NOTIFICATIONS_VIEW: 'notifications:view',
  NOTIFICATIONS_MANAGE: 'notifications:manage',
  // Tenant
  TENANT_VIEW: 'tenant:view',
  TENANT_MANAGE: 'tenant:manage',
  // Cloud
  CLOUD_VIEW: 'cloud:view',
  CLOUD_INGEST: 'cloud:ingest',
  // CSPM
  CSPM_VIEW: 'cspm:view',
  CSPM_SCAN: 'cspm:scan',
  // WORM
  WORM_VIEW: 'worm:view',
  WORM_WRITE: 'worm:write',
  WORM_VERIFY: 'worm:verify',
  // Residency
  RESIDENCY_VIEW: 'residency:view',
  RESIDENCY_ADMIN: 'residency:admin',
  // ABAC
  ABAC_VIEW: 'abac:view',
  ABAC_MANAGE: 'abac:manage',
  // RAG
  RAG_VIEW: 'rag:view',
  RAG_MANAGE: 'rag:manage',
  // Frontend-only (backend denies unknown by default)
  POLICIES_VIEW: 'policies:view',
  POLICIES_CREATE: 'policies:create',
  POLICIES_UPDATE: 'policies:update',
  POLICIES_DELETE: 'policies:delete',
  RESPONSE_VIEW: 'response:view',
  RESPONSE_TRIGGER: 'response:trigger',
  USERS_MANAGE: 'users:manage',
  BILLING_VIEW: 'billing:view',
  ANOMALY_VIEW: 'anomaly:view',
} as const;

// Re-exported from utils/permissions.ts for convenience
export { hasPermission } from './utils/permissions';

// ================== Supporting Types (from types/index.ts, Phase 2) ==================

// NOTE: Alert.investigation uses these — they exist only here (not duplicated in types/index.ts)
export interface ThreatIntel {
  verified: boolean;
  verdict: 'Malicious' | 'Safe' | 'Unknown' | string;
  sources: string[];
  risk_level: string;
  virustotal?: {
    malicious: boolean;
    detections: number;
  };
  abuseipdb?: {
    confidence_score: number;
    country_code: string;
    usage_type?: string;
  };
  otx?: {
    pulses: number;
    is_malicious: boolean;
  };
  risk_modifier?: number;
}

export interface GeoLocation {
  country: string;
  country_code?: string;
  city?: string;
  region?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
}

