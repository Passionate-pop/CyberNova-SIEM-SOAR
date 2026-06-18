"""
CyberNova — Domain Repositories
Typed repositories for events, alerts, incidents.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.repository.base import BaseRepository
from cybernova.database.postgres.models import (
    RawEvent, NormalizedEvent, EnrichedEvent,
    Alert, Incident, ResponseAction, AuditLog,
    User, Device, Tenant,
)

log = logging.getLogger("cybernova.repository.domain")


class EventRepository(BaseRepository[RawEvent]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(RawEvent, db, tenant_id)

    async def get_unprocessed(self, processed_ids_subq, limit: int = 100) -> List[RawEvent]:
        query = self._tenant_filter(
            select(self.model)
            .where(~self.model.id.in_(processed_ids_subq))
            .order_by(self.model.received_at.asc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())


class NormalizedEventRepository(BaseRepository[NormalizedEvent]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(NormalizedEvent, db, tenant_id)


class EnrichedEventRepository(BaseRepository[EnrichedEvent]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(EnrichedEvent, db, tenant_id)


class AlertRepository(BaseRepository[Alert]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(Alert, db, tenant_id)

    async def get_uncorrelated(self) -> List[Alert]:
        query = self._tenant_filter(
            select(self.model)
            .where(self.model.incident_id.is_(None))
            .where(self.model.status == "new")
            .order_by(self.model.created_at.asc())
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_unautomated(self, automated_ids_subq, limit: int = 50) -> List[Alert]:
        query = self._tenant_filter(
            select(self.model)
            .where(~self.model.id.in_(automated_ids_subq))
            .where(self.model.status.in_(["new", "correlated"]))
            .order_by(self.model.created_at.asc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())


class IncidentRepository(BaseRepository[Incident]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(Incident, db, tenant_id)


class ResponseActionRepository(BaseRepository[ResponseAction]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(ResponseAction, db, tenant_id)


class AuditLogRepository(BaseRepository[AuditLog]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(AuditLog, db, tenant_id)


class UserRepository(BaseRepository[User]):
    def __init__(self, db: AsyncSession, tenant_id: str):
        super().__init__(User, db, tenant_id)

    async def get_by_username(self, username: str) -> Optional[User]:
        query = select(self.model).where(self.model.username == username)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        query = self._tenant_filter(
            select(self.model).where(self.model.email == email)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()


class DeviceRepository(BaseRepository[Device]):
    def __init__(self, db: AsyncSession, tenant_id: str = None):
        self.db = db
        self.model = Device
        self.tenant_id = tenant_id
    
    async def get_by_token_hash(self, token_hash: str) -> Optional[Device]:
        from sqlalchemy import select
        query = select(Device).where(
            Device.device_token_hash == token_hash,
            Device.is_active
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_by_id(self, device_id: str) -> Optional[Device]:
        from sqlalchemy import select
        query = select(Device).where(Device.id == device_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Device]:
        from sqlalchemy import select
        query = select(Device).offset(skip).limit(limit).order_by(Device.last_heartbeat.desc())
        result = await self.db.execute(query)
        return list(result.scalars().all())


class TenantRepository:
    """Tenant repository — no tenant scoping since it manages tenants themselves."""
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        result = await self.db.execute(
            select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active)
        )
        return result.scalar_one_or_none()

    async def create(self, tenant: Tenant) -> Tenant:
        self.db.add(tenant)
        await self.db.flush()
        return tenant
