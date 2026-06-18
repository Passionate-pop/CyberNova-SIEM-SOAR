"""
CyberNova — SOAR Seed Script
Pre-populates devices and users so SOAR actions (isolate, disable, kill, etc.) work.

Usage:
  docker exec cybernova-backend python scripts/seed_soar_data.py
  # OR
  cd /app && python scripts/seed_soar_data.py
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from uuid import uuid4

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("seed")

SEED_DATA = {
    "tenant_id": "default",
    "devices": [
        {"hostname": "WORKSTATION-042", "ip_address": "192.168.1.42", "os_type": "windows", "os_version": "11", "status": "active", "tags": ["workstation", "engineering"]},
        {"hostname": "WORKSTATION-007", "ip_address": "192.168.1.7", "os_type": "windows", "os_version": "10", "status": "active", "tags": ["workstation", "sales"]},
        {"hostname": "SERVER-DB-01", "ip_address": "10.0.1.10", "os_type": "linux", "os_version": "ubuntu-22.04", "status": "active", "tags": ["server", "database"]},
        {"hostname": "SERVER-WEB-01", "ip_address": "10.0.1.20", "os_type": "linux", "os_version": "debian-12", "status": "active", "tags": ["server", "web"]},
        {"hostname": "LAPTOP-ADMIN", "ip_address": "192.168.1.100", "os_type": "macos", "os_version": "14", "status": "active", "tags": ["laptop", "admin"]},
    ],
    "users": [
        {"username": "john.doe", "email": "john.doe@cybernova.local", "roles": ["viewer"]},
        {"username": "jane.smith", "email": "jane.smith@cybernova.local", "roles": ["analyst"]},
        {"username": "bob.jones", "email": "bob.jones@cybernova.local", "roles": ["admin"]},
        {"username": "alice.wang", "email": "alice.wang@cybernova.local", "roles": ["soc_manager"]},
        {"username": "charlie.brown", "email": "charlie.brown@cybernova.local", "roles": ["viewer"]},
    ],
}


async def seed():
    sys.path.insert(0, "/app")
    sys.path.insert(0, ".")

    try:
        from sqlalchemy import select, text
        from cybernova.database.postgres.session import get_db_session
        from cybernova.database.postgres.models import Device, User
    except ImportError as e:
        log.error("Cannot import CyberNova modules: %s", e)
        log.error("Run from inside the backend container or with PYTHONPATH set")
        # Try with /app path
        try:
            import sys as _sys
            _sys.path.insert(0, "/app")
            from sqlalchemy import select, text
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import Device, User
        except ImportError as e2:
            log.error("Still failed: %s", e2)
            sys.exit(1)

    data = SEED_DATA
    tenant_id = data["tenant_id"]

    async for db in get_db_session():
        # Check if tenant exists
        from cybernova.database.postgres.models import Tenant
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        if not tenant:
            log.info("Creating default tenant...")
            tenant = Tenant(id=tenant_id, name="Default Tenant", domain="cybernova.local", plan="enterprise")
            db.add(tenant)
            await db.flush()

        # Seed devices
        device_count = 0
        for dev in data["devices"]:
            result = await db.execute(
                select(Device).where(Device.tenant_id == tenant_id, Device.hostname == dev["hostname"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                log.info("Device %s already exists (id=%s)", dev["hostname"], existing.id)
                continue
            device = Device(
                id=str(uuid4()),
                tenant_id=tenant_id,
                hostname=dev["hostname"],
                ip_address=dev["ip_address"],
                os_type=dev.get("os_type", ""),
                os_version=dev.get("os_version", ""),
                status=dev.get("status", "active"),
                is_active=True,
                is_isolated=False,
                tags=dev.get("tags", []),
            )
            db.add(device)
            device_count += 1
            log.info("Created device %s (ip=%s) id=%s", dev["hostname"], dev["ip_address"], device.id)

        # Seed users
        user_count = 0
        for usr in data["users"]:
            result = await db.execute(
                select(User).where(User.tenant_id == tenant_id, User.username == usr["username"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                log.info("User %s already exists (id=%s)", usr["username"], existing.id)
                continue
            user = User(
                id=str(uuid4()),
                tenant_id=tenant_id,
                username=usr["username"],
                email=usr["email"],
                hashed_password="<seed-no-password>",
                roles=usr.get("roles", ["viewer"]),
                is_active=True,
                is_disabled=False,
            )
            db.add(user)
            user_count += 1
            log.info("Created user %s (email=%s) id=%s", usr["username"], usr["email"], user.id)

        await db.commit()
        log.info("")
        log.info("=== SEED COMPLETE ===")
        log.info("Devices created: %d", device_count)
        log.info("Users created: %d", user_count)
        log.info("")
        log.info("Now run SOAR actions against these devices/users!")
        log.info("")
        log.info("Example commands:")
        log.info("  docker exec cybernova-backend python -c \"import asyncio; from scripts.seed_soar_data import list_all; asyncio.run(list_all())\"")
        log.info("")


async def list_all():
    """List all devices and users in the database."""
    sys.path.insert(0, "/app")
    sys.path.insert(0, ".")
    try:
        from sqlalchemy import select
        from cybernova.database.postgres.session import get_db_session
        from cybernova.database.postgres.models import Device, User
    except ImportError:
        log.error("Run inside backend container or with PYTHONPATH=/app")
        return

    async for db in get_db_session():
        print("\n=== DEVICES ===")
        result = await db.execute(select(Device))
        devices = result.scalars().all()
        for d in devices:
            isolated = "[ISOLATED]" if d.is_isolated else "[ACTIVE]"
            print(f"  {d.id[:8]}.. | {d.hostname:20s} | {d.ip_address:15s} | {d.os_type or '?':8s} | {isolated}")

        print("\n=== USERS ===")
        result = await db.execute(select(User))
        users = result.scalars().all()
        for u in users:
            disabled = "[DISABLED]" if u.is_disabled else "[ACTIVE]"
            print(f"  {u.id[:8]}.. | {u.username:20s} | {u.email:30s} | {disabled}")

        print("\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "list":
        asyncio.run(list_all())
    else:
        asyncio.run(seed())
