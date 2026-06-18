"""Add composite indexes for tenant-scoped query optimization

Adds:
- alerts: ix_alerts_tenant_created_severity (tenant_id, created_at, severity)
- normalized_events: ix_normalized_events_tenant_normalized (tenant_id, normalized_at)
- raw_events: ix_raw_events_tenant_received (tenant_id, received_at)

These composite indexes accelerate the most common multi-tenant query patterns:
filtering alerts by tenant + time range + severity, and filtering events by
tenant + ingestion time.

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-16
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_alerts_tenant_created_severity",
        "alerts",
        ["tenant_id", "created_at", "severity"],
        postgresql_using="btree",
    )
    op.create_index(
        "ix_normalized_events_tenant_normalized",
        "normalized_events",
        ["tenant_id", "normalized_at"],
        postgresql_using="btree",
    )
    op.create_index(
        "ix_raw_events_tenant_received",
        "raw_events",
        ["tenant_id", "received_at"],
        postgresql_using="btree",
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_tenant_created_severity", table_name="alerts")
    op.drop_index("ix_normalized_events_tenant_normalized", table_name="normalized_events")
    op.drop_index("ix_raw_events_tenant_received", table_name="raw_events")
