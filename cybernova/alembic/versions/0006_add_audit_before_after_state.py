"""Add before_state and after_state columns to audit_logs

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-17
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("before_state", sa.JSON(), nullable=True))
    op.add_column("audit_logs", sa.Column("after_state", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "after_state")
    op.drop_column("audit_logs", "before_state")
