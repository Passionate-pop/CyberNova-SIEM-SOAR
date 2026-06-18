"""
CyberNova — PostgreSQL Row-Level Security (RLS)
Enables tenant isolation at the database level.

Every tenant-scoped table gets:
  ALTER TABLE ... ENABLE ROW LEVEL SECURITY;
  CREATE POLICY tenant_isolation_policy ON ...
    USING (tenant_id = current_setting('app.tenant_id', true)::text);

When app.tenant_id is NOT set → no rows visible (fail-closed).
Set it per-transaction via set_tenant_context(db, tenant_id).
"""

import logging
from typing import Dict, List

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

TENANT_SCOPED_TABLES: List[str] = [
    "organization_keys",
    "subscriptions",
    "api_keys",
    "tenant_usage_daily",
    "users",
    "devices",
    "device_commands",
    "raw_events",
    "normalized_events",
    "enriched_events",
    "alerts",
    "incidents",
    "alert_suppressions",
    "whitelist_entries",
    "playbooks",
    "notifications",
    "response_actions",
    "audit_logs",
    "correlation_rules",
    "detection_rules",
    "blocked_ips",
    "analytics_events",
    "user_sessions",
    "insights",
    "dead_letter_events",
    "training_records",
    "model_registry",
    "entity_baselines",
    "drift_records",
    "ab_tests",
]

POLICY_NAME = "tenant_isolation_policy"


def _policy_sql(table: str) -> str:
    return (
        f"CREATE POLICY {POLICY_NAME} ON {table} "
        f"USING (tenant_id = current_setting('app.tenant_id', true)::text) "
        f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::text)"
    )


async def set_tenant_context(db: AsyncSession, tenant_id: str) -> None:
    """Set the active tenant for the current database transaction.
    Must be called after every transaction begin (or at request start)."""
    await db.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


async def get_tenant_context(db: AsyncSession) -> str:
    """Return the tenant_id set for the current session, or empty string."""
    result = await db.execute(
        text("SELECT current_setting('app.tenant_id', true)"),
    )
    val = result.scalar()
    return val or ""


async def clear_tenant_context(db: AsyncSession) -> None:
    """Clear the tenant context (set to empty, which makes RLS deny all)."""
    await db.execute(
        text("SELECT set_config('app.tenant_id', '', true)"),
    )


async def enable_rls(db: AsyncSession, tables: List[str] = None) -> int:
    """Enable RLS and create isolation policies on tenant-scoped tables.
    Returns the number of tables successfully processed."""
    targets = tables or TENANT_SCOPED_TABLES
    count = 0
    for table in targets:
        try:
            await db.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            await db.execute(text(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}"))
            await db.execute(text(_policy_sql(table)))
            count += 1
            log.debug("RLS enabled on %s", table)
        except Exception as exc:
            log.warning("Failed to enable RLS on %s: %s", table, exc)
    await db.commit()
    log.info("RLS enabled on %d/%d tables", count, len(targets))
    return count


async def disable_rls(db: AsyncSession, tables: List[str] = None) -> int:
    """Drop policies and disable RLS on tenant-scoped tables.
    Returns the number of tables successfully processed."""
    targets = tables or TENANT_SCOPED_TABLES
    count = 0
    for table in targets:
        try:
            await db.execute(text(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}"))
            await db.execute(text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
            count += 1
            log.debug("RLS disabled on %s", table)
        except Exception as exc:
            log.warning("Failed to disable RLS on %s: %s", table, exc)
    await db.commit()
    log.info("RLS disabled on %d/%d tables", count, len(targets))
    return count


async def verify_rls(db: AsyncSession) -> Dict[str, bool]:
    """Check RLS status for all tenant-scoped tables.
    Returns dict of table_name -> rls_enabled (boolean)."""
    result = await db.execute(
        text("""
            SELECT relname, relrowsecurity
            FROM pg_class
            WHERE relname = ANY(:tables) AND relkind = 'r'
            ORDER BY relname
        """),
        {"tables": TENANT_SCOPED_TABLES},
    )
    rows = result.fetchall()
    status: Dict[str, bool] = {row[0]: row[1] for row in rows}
    for t in TENANT_SCOPED_TABLES:
        status.setdefault(t, False)
    return status
