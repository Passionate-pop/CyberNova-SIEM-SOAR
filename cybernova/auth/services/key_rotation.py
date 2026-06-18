"""
CyberNova — API Key Rotation Service
Daily rotation for internal service account API keys with automated
renewal without downtime (overlap window keeps old keys valid).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import APIKey
from cybernova.database.postgres.session import get_db
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.audit.service import audit_service

log = logging.getLogger("cybernova.auth.key_rotation")

SERVICE_KEY_PREFIX = "svc:"
OVERLAP_HOURS = 48
ROTATION_INTERVAL = 86400


@dataclass
class ServiceKeyInfo:
    service_name: str
    current_key_hash: str
    previous_key_hash: str = ""
    previous_expires_at: Optional[str] = None
    created_at: str = ""
    last_rotated_at: str = ""
    key_id: str = ""


class KeyRotationService:
    """
    Manages daily rotation of internal service account API keys.
    Old keys remain active for OVERLAP_HOURS to ensure zero-downtime rotation.
    """

    def __init__(self):
        self._keys: Dict[str, ServiceKeyInfo] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def _generate_raw_key(self) -> str:
        return f"{SERVICE_KEY_PREFIX}{secrets.token_urlsafe(32)}"

    def _hash_key(self, raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def register_service_key(
        self,
        service_name: str,
        db: AsyncSession,
        rate_limit: int = 1000,
    ) -> Dict[str, Any]:
        """Register a new internal service account with a fresh API key."""
        raw_key = self._generate_raw_key()
        key_hash = self._hash_key(raw_key)

        key_id = new_id()
        now = utcnow()

        api_key = APIKey(
            id=key_id,
            tenant_id="system",
            name=f"{SERVICE_KEY_PREFIX}{service_name}",
            key_hash=key_hash,
            rate_limit=rate_limit,
            is_active=True,
            created_at=now,
        )
        db.add(api_key)
        await db.flush()

        info = ServiceKeyInfo(
            service_name=service_name,
            current_key_hash=key_hash,
            created_at=now.isoformat(),
            last_rotated_at=now.isoformat(),
            key_id=key_id,
        )
        self._keys[service_name] = info

        await audit_service.log(
            db=db,
            action="service_key_created",
            tenant_id="system",
            user_id="system",
            resource_type="service_key",
            resource_id=key_id,
            details={"service_name": service_name},
        )

        return {"service_name": service_name, "api_key": raw_key, "key_id": key_id}

    async def rotate_key(
        self,
        service_name: str,
        db: AsyncSession,
        rate_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Rotate a single service key — generates new key while keeping old one active."""
        info = self._keys.get(service_name)
        if not info:
            result = await db.execute(
                select(APIKey).where(
                    APIKey.name == f"{SERVICE_KEY_PREFIX}{service_name}",
                    APIKey.is_active,
                )
            )
            existing = result.scalar_one_or_none()
            if not existing:
                raise ValueError(f"No registered service key for '{service_name}'")
            info = ServiceKeyInfo(
                service_name=service_name,
                current_key_hash=existing.key_hash,
                created_at=existing.created_at.isoformat() if existing.created_at else "",
                last_rotated_at=utcnow().isoformat(),
                key_id=existing.id,
            )
            self._keys[service_name] = info

        raw_key = self._generate_raw_key()
        new_hash = self._hash_key(raw_key)
        now = utcnow()

        new_id_str = new_id()
        new_key = APIKey(
            id=new_id_str,
            tenant_id="system",
            name=f"{SERVICE_KEY_PREFIX}{service_name}",
            key_hash=new_hash,
            rate_limit=rate_limit or 1000,
            is_active=True,
            created_at=now,
        )
        db.add(new_key)
        await db.flush()

        overlap_end = (now + timedelta(hours=OVERLAP_HOURS)).isoformat()

        info.previous_key_hash = info.current_key_hash
        info.previous_expires_at = overlap_end
        info.current_key_hash = new_hash
        info.last_rotated_at = now.isoformat()
        info.key_id = new_id_str

        await audit_service.log(
            db=db,
            action="service_key_rotated",
            tenant_id="system",
            user_id="system",
            resource_type="service_key",
            resource_id=new_id_str,
            details={
                "service_name": service_name,
                "previous_key_id": info.key_id,
                "overlap_hours": OVERLAP_HOURS,
            },
        )

        return {
            "service_name": service_name,
            "api_key": raw_key,
            "key_id": new_id_str,
            "previous_key_active_until": overlap_end,
        }

    async def deactivate_old_keys(self, db: AsyncSession) -> int:
        """Deactivate old service keys that have exceeded the overlap window."""
        now = utcnow()
        deactivated = 0
        for service_name, info in list(self._keys.items()):
            if not info.previous_key_hash or not info.previous_expires_at:
                continue
            try:
                expires = datetime.fromisoformat(info.previous_expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires <= now:
                    result = await db.execute(
                        select(APIKey).where(
                            APIKey.key_hash == info.previous_key_hash,
                            APIKey.is_active,
                        )
                    )
                    old_key = result.scalar_one_or_none()
                    if old_key:
                        old_key.is_active = False
                        await db.flush()
                        deactivated += 1
                        log.info("Deactivated old key for %s (hash=%s)", service_name, info.previous_key_hash[:12])

                    info.previous_key_hash = ""
                    info.previous_expires_at = None
            except (ValueError, TypeError):
                pass
        return deactivated

    async def rotate_all(self, db: AsyncSession) -> Dict[str, Any]:
        """Rotate all registered service keys."""
        results = {"rotated": 0, "errors": 0, "keys": []}
        for service_name in list(self._keys.keys()):
            try:
                result = await self.rotate_key(service_name, db)
                results["rotated"] += 1
                results["keys"].append(result)
            except Exception as e:
                log.warning("Rotation failed for '%s': %s", service_name, e)
                results["errors"] += 1

        deactivated = await self.deactivate_old_keys(db)
        results["old_keys_deactivated"] = deactivated
        return results

    async def list_service_keys(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """List all registered service keys with their status."""
        result = await db.execute(
            select(APIKey).where(
                APIKey.name.like(f"{SERVICE_KEY_PREFIX}%"),
            ).order_by(APIKey.created_at.desc())
        )
        keys = result.scalars().all()
        output = []
        for k in keys:
            service = k.name[len(SERVICE_KEY_PREFIX):] if k.name.startswith(SERVICE_KEY_PREFIX) else k.name
            info = self._keys.get(service)
            output.append({
                "key_id": k.id,
                "service_name": service,
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat() if k.created_at else "",
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "rate_limit": k.rate_limit,
                "has_previous_key": bool(info and info.previous_key_hash) if info else False,
            })
        return output

    async def start(self, interval: int = ROTATION_INTERVAL) -> None:
        """Start the daily background rotation loop."""
        self._running = True
        self._task = asyncio.create_task(self._run_loop(interval))
        log.info("Key rotation service started (interval: %ds)", interval)

    async def stop(self) -> None:
        """Stop the background rotation loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Key rotation service stopped")

    async def _run_loop(self, interval: int) -> None:
        while self._running:
            try:
                async for db in get_db():
                    try:
                        rotated = await self.rotate_all(db)
                        deactivated = rotated.get("old_keys_deactivated", 0)
                        log.info("Daily key rotation complete: %d rotated, %d deactivated", rotated.get("rotated", 0), deactivated)
                        await db.commit()
                    except Exception as e:
                        await db.rollback()
                        log.warning("Key rotation cycle error: %s", e)
                    finally:
                        await db.close()
            except Exception as e:
                log.error("Key rotation loop error: %s", e)
            await asyncio.sleep(interval)

    def get_status(self) -> Dict[str, Any]:
        """Get current status of all managed service keys."""
        return {
            "managed_services": len(self._keys),
            "services": [
                {
                    "service_name": info.service_name,
                    "has_previous_key": bool(info.previous_key_hash),
                    "previous_expires_at": info.previous_expires_at,
                    "last_rotated_at": info.last_rotated_at,
                    "created_at": info.created_at,
                }
                for info in sorted(self._keys.values(), key=lambda x: x.service_name)
            ],
            "is_running": self._running,
            "overlap_hours": OVERLAP_HOURS,
            "rotation_interval_seconds": ROTATION_INTERVAL,
        }


key_rotation_service = KeyRotationService()
