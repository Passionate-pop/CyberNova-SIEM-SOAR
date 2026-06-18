"""Create correlation_rules table

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-14
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlation_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sequence", sa.JSON(), nullable=False),
        sa.Column("entity_field", sa.String(50), nullable=False),
        sa.Column("window_seconds", sa.Integer(), server_default="300"),
        sa.Column("severity", sa.String(20), server_default="high"),
        sa.Column("enabled", sa.Boolean(), server_default="true", index=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("data", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("correlation_rules")
