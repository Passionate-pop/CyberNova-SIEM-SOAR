"""
CyberNova — Global Event Schemas
Backbone schemas used across the entire pipeline.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class EventIngest(BaseModel):
    """Payload accepted by the ingestion endpoint."""
    source: str
    source_type: str = "api"
    events: List[Dict[str, Any]]


class EventResponse(BaseModel):
    id: str
    event_type: str
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    model_config = {"from_attributes": True}


class NormalizationResult(BaseModel):
    event_id: str
    event_type: str
    severity: str
    fields_extracted: int


class EnrichmentResult(BaseModel):
    event_id: str
    risk_score: float
    geo_data: Dict[str, Any] = {}
    threat_intel: Dict[str, Any] = {}
    sources_consulted: List[str] = []


class DeviceRegister(BaseModel):
    hostname: str
    ip_address: str
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    tags: List[str] = []


class DeviceResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: Optional[str] = None
    status: str
    last_heartbeat: Optional[datetime] = None
    registered_at: datetime
    model_config = {"from_attributes": True}


class HeartbeatRequest(BaseModel):
    device_id: str
    timestamp: Optional[datetime] = None
    metrics: Dict[str, Any] = {}
