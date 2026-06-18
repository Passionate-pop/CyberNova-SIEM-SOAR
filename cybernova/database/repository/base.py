"""
CyberNova — Base Repository
Generic async CRUD operations with mandatory tenant isolation.
Services MUST use repositories — never access ORM directly.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar
from datetime import datetime

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import Base

log = logging.getLogger("cybernova.repository")
T = TypeVar("T", bound=Base)


class BaseRepository(Generic[T]):
    """Tenant-scoped async repository. All queries auto-filter by tenant_id."""

    def __init__(self, model: Type[T], db: AsyncSession, tenant_id: str) -> None:
        self.model = model
        self.db = db
        self.tenant_id = tenant_id

    def _tenant_filter(self, query):
        """Inject tenant isolation into every query."""
        if hasattr(self.model, "tenant_id"):
            return query.where(self.model.tenant_id == self.tenant_id)
        return query

    async def get_by_id(self, entity_id: str) -> Optional[T]:
        query = self._tenant_filter(select(self.model).where(self.model.id == entity_id))
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
        order_by=None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[T]:
        query = self._tenant_filter(select(self.model))
        if filters:
            for field, value in filters.items():
                col = getattr(self.model, field, None)
                if col is not None:
                    if isinstance(value, list):
                        query = query.where(col.in_(value))
                    else:
                        query = query.where(col == value)
        if order_by is not None:
            query = query.order_by(order_by)
        query = query.offset(offset).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        query = self._tenant_filter(select(func.count(self.model.id)))
        if filters:
            for field, value in filters.items():
                col = getattr(self.model, field, None)
                if col is not None:
                    if isinstance(value, list):
                        query = query.where(col.in_(value))
                    else:
                        query = query.where(col == value)
        result = await self.db.execute(query)
        return result.scalar() or 0

    async def create(self, entity: T) -> T:
        if hasattr(entity, "tenant_id"):
            entity.tenant_id = self.tenant_id
        self.db.add(entity)
        await self.db.flush()
        return entity

    async def create_many(self, entities: List[T]) -> List[T]:
        for entity in entities:
            if hasattr(entity, "tenant_id"):
                entity.tenant_id = self.tenant_id
            self.db.add(entity)
        await self.db.flush()
        return entities

    async def bulk_insert(self, mappings: List[Dict[str, Any]]) -> None:
        """True bulk insert using SQLAlchemy bulk_insert_mappings.
        
        Accepts a list of dicts (column_name → value) and inserts them
        in a single multi-row INSERT statement. More efficient than
        create_many() for large batches.
        """
        if not mappings:
            return
        for m in mappings:
            if "tenant_id" not in m and hasattr(self.model, "tenant_id"):
                m["tenant_id"] = self.tenant_id
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(self.model).values(mappings)
        stmt = stmt.on_conflict_do_nothing()
        await self.db.execute(stmt)

    async def update_fields(self, entity_id: str, **fields) -> Optional[T]:
        entity = await self.get_by_id(entity_id)
        if not entity:
            return None
        for key, value in fields.items():
            if hasattr(entity, key):
                setattr(entity, key, value)
        await self.db.flush()
        return entity

    async def delete_by_id(self, entity_id: str) -> bool:
        entity = await self.get_by_id(entity_id)
        if not entity:
            return False
        await self.db.delete(entity)
        await self.db.flush()
        return True

    async def delete_older_than(self, date_column, cutoff: datetime) -> int:
        stmt = delete(self.model)
        if hasattr(self.model, "tenant_id"):
            stmt = stmt.where(self.model.tenant_id == self.tenant_id)
        stmt = stmt.where(date_column < cutoff)
        result = await self.db.execute(stmt)
        return result.rowcount
