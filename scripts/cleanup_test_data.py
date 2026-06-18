"""Cleanup duplicate test data from database."""
import asyncio
from cybernova.database.postgres.session import engine
from sqlalchemy import text


async def cleanup():
    async with engine.begin() as conn:
        # Find duplicate tenants
        r = await conn.execute(
            text("SELECT name, COUNT(*) as cnt FROM tenants GROUP BY name HAVING COUNT(*) > 1")
        )
        dupes = r.fetchall()
        print(f"Duplicate tenants found: {len(dupes)}")
        for d in dupes:
            print(f"  {d}")

        # Find duplicate users
        r2 = await conn.execute(
            text("SELECT username, COUNT(*) as cnt FROM users GROUP BY username HAVING COUNT(*) > 1")
        )
        user_dupes = r2.fetchall()
        print(f"Duplicate users found: {len(user_dupes)}")
        for d in user_dupes:
            print(f"  {d}")

        # Clean up CyberCorp test data (keep only the first tenant with this name)
        await conn.execute(text("""
            DELETE FROM organization_keys
            WHERE tenant_id IN (
                SELECT id FROM tenants WHERE name = 'CyberCorp'
                AND id NOT IN (
                    SELECT MIN(id) FROM tenants WHERE name = 'CyberCorp'
                )
            )
        """))
        await conn.execute(text("""
            DELETE FROM users
            WHERE tenant_id IN (
                SELECT id FROM tenants WHERE name = 'CyberCorp'
                AND id NOT IN (
                    SELECT MIN(id) FROM tenants WHERE name = 'CyberCorp'
                )
            )
        """))
        await conn.execute(text("""
            DELETE FROM tenants
            WHERE name = 'CyberCorp'
            AND id NOT IN (
                SELECT MIN(id) FROM tenants WHERE name = 'CyberCorp'
            )
        """))

        # Also clean up 'default' tenant duplicates
        await conn.execute(text("""
            DELETE FROM tenants
            WHERE name = 'default'
            AND id NOT IN (
                SELECT MIN(id) FROM tenants WHERE name = 'default'
            )
        """))
        await conn.execute(text("""
            DELETE FROM tenants
            WHERE name = 'personal'
            AND id NOT IN (
                SELECT MIN(id) FROM tenants WHERE name = 'personal'
            )
        """))

        # Verify cleanup
        r3 = await conn.execute(text("SELECT name, COUNT(*) FROM tenants GROUP BY name HAVING COUNT(*) > 1"))
        remaining = r3.fetchall()
        print(f"Remaining duplicates after cleanup: {len(remaining)}")

        r4 = await conn.execute(text("SELECT username, COUNT(*) FROM users GROUP BY username HAVING COUNT(*) > 1"))
        user_remaining = r4.fetchall()
        print(f"Remaining user duplicates after cleanup: {len(user_remaining)}")

        print("Cleanup complete!")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(cleanup())
