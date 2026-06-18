"""
CyberNova — Global Alert Schemas
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: str
    rule_name: str
    severity: str
    risk_score: float
    status: str
    device_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    created_at: datetime
    model_config = {"from_attributes": True}


class AlertDetailResponse(AlertResponse):
    description: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None
    incident_id: Optional[str] = None
    raw_event: Optional[dict] = None
    extra_data: Optional[dict] = None
    updated_at: Optional[datetime] = None
