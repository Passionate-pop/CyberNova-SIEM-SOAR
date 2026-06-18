"""
CyberNova — Shared Constants
Single source of truth for severity levels, plan limits, retention policies.
"""
from __future__ import annotations

import enum

# ── Severity Levels ──────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
VALID_SEVERITIES = set(SEVERITY_ORDER.keys())

SEVERITY_ALIASES = {
    "crit": "critical", "err": "high", "error": "high",
    "warn": "medium", "warning": "medium", "notice": "low", "debug": "info",
}

# ── Plan Limits (SaaS) ──────────────────────────────────────────────────────
PLANS = {
    "free": {"events_limit": 10_000, "rate_limit": 60, "features": ["core_siem"]},
    "pro": {"events_limit": 1_000_000, "rate_limit": 1_000, "features": ["core_siem", "soar", "ai_hunt"]},
    "enterprise": {"events_limit": 100_000_000, "rate_limit": 10_000, "features": ["all"]},
}

# ── Retention Policies (days) ────────────────────────────────────────────────
RETENTION_POLICY = {
    "raw_events": 30,
    "normalized_events": 90,
    "enriched_events": 90,
    "alerts": 365,
    "audit_logs": 365,
}

# ── Event Topics (Event Bus) ────────────────────────────────────────────────
class Topics:
    RAW_EVENT_INGESTED = "raw_event.ingested"
    EVENT_NORMALIZED = "event.normalized"
    EVENT_ENRICHED = "event.enriched"
    ALERT_CREATED = "alert.created"
    INCIDENT_CREATED = "incident.created"
    ACTION_REQUESTED = "action.requested"
    ACTION_CREATED = "action.created"
    ACTION_COMPLETED = "action.completed"
    WEBHOOK_RECEIVED = "webhook.received"

# ── Supported Source Types ───────────────────────────────────────────────────
SUPPORTED_SOURCE_TYPES = {"syslog", "webhook", "agent", "api", "cef", "json"}

# ── Alert Statuses ───────────────────────────────────────────────────────────
ALERT_STATUSES = {"new", "correlated", "in_progress", "resolved", "closed"}
INCIDENT_STATUSES = {"new", "in_progress", "escalated", "resolved", "closed"}

INCIDENT_TRANSITIONS = {
    "new": ["in_progress", "closed"],
    "in_progress": ["resolved", "escalated", "closed"],
    "resolved": ["closed"],
    "escalated": ["resolved", "closed"],
    "closed": [],
}

# ── Action Statuses (SOAR Response Lifecycle) ────────────────────────────────

class ActionStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    COMPLETED = "completed"
    FAILED = "failed"

VALID_ACTION_STATUSES = {s.value for s in ActionStatus}
CALLBACK_STATUSES = {ActionStatus.COMPLETED.value, ActionStatus.FAILED.value}

# ── CORS Origins ────────────────────────────────────────────────────────────────
CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://localhost:8888",
    "https://localhost",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8888",
]

# ── Pipeline Queue Names ────────────────────────────────────────────────────────
PIPELINE_QUEUES = [
    "ingestion",
    "normalization",
    "enrichment",
    "detection",
    "correlation",
    "alert",
    "soar",
    "ai",
    "notification",
]

# ── Detection Rule Categories ───────────────────────────────────────────────────
DETECTION_CATEGORIES = [
    "Brute Force",
    "Malware",
    "C2",
    "Reconnaissance",
    "Web Attack",
    "Exfiltration",
    "Privilege Escalation",
    "Phishing",
    "Lateral Movement",
    "Anomaly",
]

# ── SOAR Action Types ──────────────────────────────────────────────────────────
SOAR_ACTION_TYPES = [
    "block_ip",
    "unblock_ip",
    "isolate_device",
    "restore_device",
    "kill_process",
    "disable_user",
    "enable_user",
    "trigger_automation",
    "send_notification",
    "create_ticket",
]
