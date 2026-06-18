"""
CyberNova — Policy Model
Security automation policies stored in DB.
"""
from __future__ import annotations
from datetime import datetime, timezone

from sqlalchemy import (
    Column, DateTime, String, Text, Boolean, JSON, Integer,
    ForeignKey, UniqueConstraint,
)

from cybernova.database.postgres.session import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _uuid():
    import uuid
    return str(uuid.uuid4())


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id = Column(String(36), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    enabled = Column(Boolean, default=True, index=True)
    
    conditions = Column(JSON, nullable=False)
    actions = Column(JSON, nullable=False)
    
    cooldown_seconds = Column(Integer, default=300)
    created_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_policy_name"),
    )


class PolicyExecutionLog(Base):
    __tablename__ = "policy_execution_logs"
    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(36), ForeignKey("policies.id"), nullable=False, index=True)
    tenant_id = Column(String(36), nullable=False, index=True)
    device_id = Column(String(36), nullable=True)
    action = Column(String(50), nullable=False)
    status = Column(String(20), default="success")
    details = Column(JSON)
    executed_at = Column(DateTime(timezone=True), default=_utcnow, index=True)