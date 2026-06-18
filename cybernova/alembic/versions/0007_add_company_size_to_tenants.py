"""Add company_size column to tenants table

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-20
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("company_size", sa.String(50), server_default="", nullable=False))
    # Set existing rows to empty string
    op.execute("UPDATE tenants SET company_size = '' WHERE company_size IS NULL")


def downgrade() -> None:
    op.drop_column("tenants", "company_size")
