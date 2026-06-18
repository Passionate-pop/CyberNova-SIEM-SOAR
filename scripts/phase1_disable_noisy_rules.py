#!/usr/bin/env python3
"""Phase 1: Disable noisy detection rules (noisy baseline)"""

import logging
import sys

from sqlalchemy import text

from cybernova.database.postgres.session import get_db_session, engine

log = logging.getLogger("cybernova.migration")

NOISY_RULES = [
    'External Connection',
    'New Listener',
    'agent_heartbeat',
    'Suspicious Browser Activity',
    'usb_connected',
    'logoff',
    'successful_login',
    'new_download',
]

ALLOWED_TABLES = {"detection_rules"}
ALLOWED_COLUMNS = {"name", "enabled"}


async def main():
    async for db in get_db_session():
        table = "detection_rules"
        col = "name"
        if table not in ALLOWED_TABLES or col not in ALLOWED_COLUMNS:
            log.error("Migration blocked: %s.%s not in allowlist", table, col)
            sys.exit(1)

        # SAFETY: table/column validated against ALLOWED_TABLES/ALLOWED_COLUMNS above
        result = await db.execute(
            text(f"UPDATE {table} SET enabled = FALSE WHERE {col} = ANY(:names)"),
            {"names": NOISY_RULES},
        )
        log.info("Disabled %d noisy rules", result.rowcount)

        # Also disable common noisy variants by partial match
        for pattern in ["%Unusual%", "%Heartbeat%"]:
            await db.execute(
                text(f"UPDATE {table} SET enabled = FALSE WHERE {col} ILIKE :pattern"),
                {"pattern": pattern},
            )

    await engine.dispose()


if __name__ == '__main__':
    import asyncio
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
