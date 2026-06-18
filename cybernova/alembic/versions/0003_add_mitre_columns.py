"""Add mitre_tactic/mitre_technique to alerts and detection_rules

NOTE: These columns already exist from migration 0001 (initial_schema).
This migration is idempotent — it skips columns that already exist
so it works whether applied fresh or as an incremental upgrade.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-11
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


COLUMN_DEFINITIONS = [
    ("alerts", "mitre_tactic", sa.Column("mitre_tactic", sa.String(100), nullable=True, index=True)),
    ("alerts", "mitre_technique", sa.Column("mitre_technique", sa.String(100), nullable=True, index=True)),
    ("detection_rules", "mitre_tactic", sa.Column("mitre_tactic", sa.String(100), nullable=True, index=True)),
    ("detection_rules", "mitre_technique", sa.Column("mitre_technique", sa.String(100), nullable=True, index=True)),
    ("detection_rules", "category", sa.Column("category", sa.String(100), nullable=True, index=True)),
]


def _column_exists(table: str, column: str) -> bool:
    """Check if a column exists in the given table (PostgreSQL + SQLite compatible)."""
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        result = bind.execute(
            sa.text(
                "SELECT EXISTS ("
                "SELECT FROM information_schema.columns "
                "WHERE table_name = :table AND column_name = :column"
                ")"
            ),
            {"table": table, "column": column},
        ).scalar()
    else:
        # SQLite: use PRAGMA table_info
        rows = bind.execute(sa.text(f"PRAGMA table_info({table})")).fetchall()
        result = any(row[1] == column for row in rows)
    return bool(result)


def upgrade() -> None:
    for table_name, col_name, column in COLUMN_DEFINITIONS:
        if _column_exists(table_name, col_name):
            op.execute(sa.text(f"-- Column {table_name}.{col_name} already exists, skipping"))
        else:
            op.add_column(table_name, column)


def downgrade() -> None:
    for table_name, col_name, _ in reversed(COLUMN_DEFINITIONS):
        try:
            op.drop_column(table_name, col_name)
        except Exception:
            op.execute(sa.text(f"-- Column {table_name}.{col_name} does not exist, skipping drop"))
