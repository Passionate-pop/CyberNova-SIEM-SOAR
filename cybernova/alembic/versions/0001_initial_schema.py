"""Initial database schema — CyberNova core tables

Revision ID: 0001
Revises: None
Create Date: 2026-05-10
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Tenants ────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("domain", sa.String(100), unique=True, index=True),
        sa.Column("plan", sa.String(50), server_default="free"),
        sa.Column("is_active", sa.Boolean(), server_default="true", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Organization Keys ──────────────────────────────────────
    op.create_table(
        "organization_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("key_hash", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("name", sa.String(100), server_default="default"),
        sa.Column("is_active", sa.Boolean(), server_default="true", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_org_key_name"),
    )

    # ── Users ──────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("username", sa.String(100), nullable=False, index=True),
        sa.Column("email", sa.String(255), nullable=False, index=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False, server_default='["viewer"]'),
        sa.Column("is_active", sa.Boolean(), server_default="true", index=True),
        sa.Column("is_disabled", sa.Boolean(), server_default="false"),
        sa.Column("failed_login_attempts", sa.Integer(), server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_secret", sa.String(64), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "username", name="uq_user_tenant_username"),
        sa.UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
    )

    # ── Devices ────────────────────────────────────────────────
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("hostname", sa.String(255), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=True, index=True),
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("os", sa.String(100), nullable=True),
        sa.Column("os_version", sa.String(100), nullable=True),
        sa.Column("agent_version", sa.String(50), nullable=True),
        sa.Column("is_isolated", sa.Boolean(), server_default="false"),
        sa.Column("is_active", sa.Boolean(), server_default="true", index=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "hostname", name="uq_device_tenant_hostname"),
    )

    # ── Blocked IPs ────────────────────────────────────────────
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("source", sa.String(50), server_default="manual"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # ── Alerts ─────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("status", sa.String(20), server_default="open", index=True),
        sa.Column("category", sa.String(100), nullable=True, index=True),
        sa.Column("source_ip", sa.String(45), nullable=True, index=True),
        sa.Column("dest_ip", sa.String(45), nullable=True, index=True),
        sa.Column("user", sa.String(100), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=True),
        sa.Column("raw_event", postgresql.JSONB() if op.get_context().dialect.name == "postgresql" else sa.JSON(), nullable=True),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("mitre_technique", sa.String(100), nullable=True),
        sa.Column("risk_score", sa.Float(), server_default="0"),
        sa.Column("assigned_to", sa.String(100), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Alert Suppressions ─────────────────────────────────────
    op.create_table(
        "alert_suppressions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # ── Detection Rules ────────────────────────────────────────
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rule_type", sa.String(50), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("mitre_technique", sa.String(100), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="true", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Incidents ──────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("status", sa.String(20), server_default="open", index=True),
        sa.Column("alert_ids", sa.JSON(), nullable=True),
        sa.Column("assigned_to", sa.String(100), nullable=True),
        sa.Column("risk_score", sa.Float(), server_default="0"),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Audit Logs ─────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("user_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(100), nullable=False, index=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )

    # ── Subscriptions (Billing) ────────────────────────────────
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True, unique=True),
        sa.Column("stripe_customer_id", sa.String(100), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("events_limit_per_month", sa.Integer(), server_default="100000"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Usage Records ──────────────────────────────────────────
    op.create_table(
        "usage_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("event_count", sa.Integer(), server_default="0"),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── SOAR Actions ───────────────────────────────────────────
    op.create_table(
        "soar_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("alert_id", sa.String(36), nullable=True, index=True),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), server_default="pending", index=True),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("soar_actions")
    op.drop_table("usage_records")
    op.drop_table("subscriptions")
    op.drop_table("audit_logs")
    op.drop_table("incidents")
    op.drop_table("detection_rules")
    op.drop_table("alert_suppressions")
    op.drop_table("alerts")
    op.drop_table("blocked_ips")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("organization_keys")
    op.drop_table("tenants")
