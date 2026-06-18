"""
CyberNova — ORM Models (Multi-Tenant SaaS)
All SQLAlchemy table definitions with strict tenant isolation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, JSON, UniqueConstraint,
)

from cybernova.database.postgres.session import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())


# ── SaaS Core ────────────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(100), nullable=False)
    domain = Column(String(100), unique=True, index=True)
    plan = Column(String(50), default="free")
    company_size = Column(String(50), default="")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    __table_args__ = (UniqueConstraint("name", name="uq_tenant_name"),)


class OrganizationKey(Base):
    __tablename__ = "organization_keys"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100), default="default")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    expires_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_org_key_name"),)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), unique=True, nullable=False, index=True)
    stripe_customer_id = Column(String(100), unique=True, index=True)
    stripe_subscription_id = Column(String(100), unique=True)
    status = Column(String(50), default="active", index=True)
    events_limit_per_month = Column(Integer, default=10000)
    current_period_end = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    rate_limit = Column(Integer, default=60)
    is_active = Column(Boolean, default=True, index=True)
    last_used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class TenantUsageDaily(Base):
    __tablename__ = "tenant_usage_daily"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    events_ingested = Column(Integer, default=0)
    alerts_generated = Column(Integer, default=0)
    automation_runs = Column(Integer, default=0)
    __table_args__ = (UniqueConstraint("tenant_id", "date", name="uq_tenant_date"),)


# ── Users / Auth ─────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    username = Column(String(80), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    roles = Column(JSON, default=list)
    is_active = Column(Boolean, default=True, index=True)
    is_disabled = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    __table_args__ = (
        UniqueConstraint("tenant_id", "username", name="uq_user_tenant_username"),
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
    )


# ── Devices ──────────────────────────────────────────────────────────────────

class Device(Base):
    __tablename__ = "devices"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17))
    os_type = Column(String(50))
    os_version = Column(String(100))
    agent_version = Column(String(20))
    status = Column(String(20), default="active", index=True)
    is_active = Column(Boolean, default=True, index=True)
    device_token_hash = Column(String(255), index=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    tags = Column(JSON, default=list)
    last_heartbeat = Column(DateTime(timezone=True))
    is_isolated = Column(Boolean, default=False, index=True)
    registered_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class DeviceCommand(Base):
    __tablename__ = "device_commands"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    payload = Column(JSON, default=dict)
    status = Column(String(20), default="pending", index=True)
    idempotency_key = Column(String(64), index=True)
    created_by = Column(String(36))
    executed_at = Column(DateTime(timezone=True))
    error = Column(Text)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    expires_at = Column(DateTime(timezone=True))


# ── Events ───────────────────────────────────────────────────────────────────

class RawEvent(Base):
    __tablename__ = "raw_events"
    __table_args__ = (
        Index("ix_raw_events_tenant_received", "tenant_id", "received_at"),
    )
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    source = Column(String(100), nullable=False, index=True)
    source_type = Column(String(50))
    payload = Column(JSON, nullable=False)
    received_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"
    __table_args__ = (
        Index("ix_normalized_events_tenant_normalized", "tenant_id", "normalized_at"),
    )
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    raw_event_id = Column(String(36), nullable=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), index=True)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(20))
    user = Column(String(100))
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=True)
    message = Column(Text)
    extra_data = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), index=True)
    normalized_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class EnrichedEvent(Base):
    __tablename__ = "enriched_events"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    normalized_event_id = Column(String(36), nullable=True)
    geo_data = Column(JSON, default=dict)
    threat_intel = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0)
    enrichment_sources = Column(JSON, default=list)
    enriched_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


# ── Alerts / Incidents ───────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_created_severity", "tenant_id", "created_at", "severity"),
        Index("ix_alerts_incident_id", "incident_id"),
    )
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    event_id = Column(String(36), nullable=True)
    incident_id = Column(String(36), nullable=True)
    device_id = Column(String(36))
    rule_name = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Float, default=0.0)
    description = Column(Text)
    status = Column(String(20), default="new", index=True)
    source_ip = Column(String(45), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    user = Column(String(100), nullable=True)
    event_type = Column(String(100), nullable=True)
    raw_event = Column(JSON, nullable=True)
    extra_data = Column(JSON, default=dict)
    mitre_tactic = Column(String(100), nullable=True, index=True)
    mitre_technique = Column(String(100), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(30), default="new", index=True)
    risk_score = Column(Float, default=0.0)
    assigned_to = Column(String(36), ForeignKey("users.id"), nullable=True)
    escalation_level = Column(Integer, default=0)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


# ── Noise Control (Suppression & Whitelist) ──────────────────────────────

class AlertSuppression(Base):
    __tablename__ = "alert_suppressions"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    rule_id = Column(String(36), nullable=True, index=True)
    entity = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(50), default="ip")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class WhitelistEntry(Base):
    __tablename__ = "whitelist_entries"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    entity = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(50), default="ip", index=True)
    reason = Column(Text, nullable=True)
    created_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (UniqueConstraint("tenant_id", "entity", "entity_type", name="uq_whitelist_entity"),)


# ── Playbooks ────────────────────────────────────────────────────────────────

class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(String(100), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    priority = Column(Integer, default=5)
    severity_action = Column(String(50), default="ui_only")
    condition = Column(JSON, default=dict)
    actions = Column(JSON, default=list)
    automated = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


# ── Notifications ────────────────────────────────────────────────────────────

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    type = Column(String(20), default="info", index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=True)
    read = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


# ── Automation ───────────────────────────────────────────────────────────────

class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    device_id = Column(String(36))
    action_type = Column(String(100), nullable=False)
    parameters = Column(JSON, default=dict)
    status = Column(String(20), default="pending", index=True)
    initiated_by = Column(String(36), index=True)
    result = Column(JSON, nullable=True)
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))


# ── Audit Log ────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(36))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(36))
    details = Column(JSON, default=dict)
    ip_address = Column(String(45))
    before_state = Column(JSON, nullable=True)
    after_state = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, index=True)


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    sequence = Column(JSON, nullable=False)
    entity_field = Column(String(50), nullable=False)
    window_seconds = Column(Integer, default=300)
    severity = Column(String(20), default="high")
    enabled = Column(Boolean, default=True, index=True)
    tenant_id = Column(String(36), nullable=False, index=True)
    data = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    rule_expression = Column(Text, nullable=False)
    severity = Column(String(20), default="medium")
    risk_score = Column(Float, default=50.0)
    event_type = Column(String(100), nullable=True, index=True)
    category = Column(String(100), nullable=True, index=True)
    mitre_tactic = Column(String(100), nullable=True, index=True)
    mitre_technique = Column(String(100), nullable=True, index=True)
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


# ── Blocked IPs (Built-in SOAR) ────────────────────────────────────────

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    blocked_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "ip_address", name="uq_blocked_ip"),)


# ── Analytics ────────────────────────────────────────────────────────────────

class AnalyticsEvent(Base):
    __tablename__ = "analytics_events"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    device_id = Column(String(36), nullable=True, index=True)
    event_name = Column(String(100), nullable=False, index=True)
    event_category = Column(String(50), nullable=True, index=True)
    event_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=True, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), default=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    ttf_device_seconds = Column(Integer, nullable=True)


class Insight(Base):
    __tablename__ = "insights"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    type = Column(String(50), nullable=False)
    severity = Column(String(20), default="medium")
    message = Column(Text, nullable=False)
    action = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


# ── Dead Letter Queue ────────────────────────────────────────────────────────

class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), nullable=False, index=True)
    original_queue = Column(String(100), nullable=False)
    payload = Column(JSON, nullable=False)
    error = Column(Text, nullable=False)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    failed_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class TrainingRecord(Base):
    __tablename__ = "training_records"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    recorded_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    entity_type = Column(String(50), nullable=True)
    entity_id = Column(String(100), nullable=True)
    feature_vector = Column(JSON, default=dict)
    label = Column(String(20), nullable=True)
    label_source = Column(String(50), nullable=True)
    event_count = Column(Integer, default=0)
    source = Column(String(50), default="pipeline")


class ModelRegistry(Base):
    __tablename__ = "model_registry"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    model_id = Column(String(100), nullable=False, index=True)
    version = Column(String(20), nullable=False)
    algorithm = Column(String(50), nullable=False)
    feature_names = Column(JSON, default=list)
    model_data = Column(JSON, nullable=False)
    metadata_json = Column(JSON, default=dict)
    training_samples = Column(Integer, default=0)
    is_active = Column(Boolean, default=False, index=True)
    metrics = Column(JSON, default=dict)
    trained_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class EntityBaseline(Base):
    __tablename__ = "entity_baselines"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_value = Column(String(255), nullable=False, index=True)
    window_days = Column(Integer, default=30)
    total_events = Column(Integer, default=0)
    event_frequency = Column(JSON, default=dict)
    hourly_distribution = Column(JSON, default=list)
    daily_distribution = Column(JSON, default=list)
    port_diversity = Column(JSON, default=dict)
    ip_diversity = Column(JSON, default=dict)
    event_type_distribution = Column(JSON, default=dict)
    computed_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (
        UniqueConstraint("tenant_id", "entity_type", "entity_value", name="uq_entity_baseline"),
    )


class DriftRecord(Base):
    __tablename__ = "drift_records"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_value = Column(String(255), nullable=False, index=True)
    drift_score = Column(Float, default=0.0, index=True)
    drift_metrics = Column(JSON, default=dict)
    frequency_drift = Column(Float, default=0.0)
    hourly_drift = Column(Float, default=0.0)
    port_drift = Column(Float, default=0.0)
    ip_drift = Column(Float, default=0.0)
    event_type_drift = Column(Float, default=0.0)
    window_minutes = Column(Integer, default=60)
    window_event_count = Column(Integer, default=0)
    baseline_event_count = Column(Integer, default=0)
    detected_at = Column(DateTime(timezone=True), default=_utcnow, index=True)


class ABTest(Base):
    __tablename__ = "ab_tests"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    model_id = Column(String(100), nullable=False, index=True)
    version_a = Column(String(20), nullable=False)
    version_b = Column(String(20), nullable=False)
    split_ratio = Column(Float, default=0.5)
    is_active = Column(Boolean, default=True, index=True)
    total_a = Column(Integer, default=0)
    total_b = Column(Integer, default=0)
    anomaly_rate_a = Column(Float, default=0.0)
    anomaly_rate_b = Column(Float, default=0.0)
    started_at = Column(DateTime(timezone=True), default=_utcnow)
    ended_at = Column(DateTime(timezone=True), nullable=True)


class ABTestResult(Base):
    __tablename__ = "ab_test_results"
    id = Column(String(36), primary_key=True, default=_uuid)
    test_id = Column(String(36), ForeignKey("ab_tests.id"), nullable=False, index=True)
    event_id = Column(String(36), nullable=False)
    model_version = Column(String(20), nullable=False)
    anomaly_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    confidence = Column(Float, default=0.0)
    actual_outcome = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
