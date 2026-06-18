"""
CyberNova — Global Response/Automation Schemas
Pydantic models for request validation and response serialization.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel

# ── Action Schemas ───────────────────────────────────────────────────────────


class ActionRequest(BaseModel):
    alert_id: str
    action_type: str
    parameters: Dict[str, Any] = {}


class ActionResponse(BaseModel):
    id: str
    action_type: str
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ActionDetailResponse(BaseModel):
    """Full action object — used by the debug/test endpoint."""
    id: str
    tenant_id: str
    alert_id: Optional[str] = None
    action_type: str
    parameters: Dict[str, Any] = {}
    status: str
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class DashboardMetrics(BaseModel):
    total_events: int = 0
    events_last_24h: int = 0
    active_alerts: int = 0
    open_incidents: int = 0
    active_devices: int = 0
    top_severities: Dict[str, int] = {}
    top_event_types: Dict[str, int] = {}


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    services: Dict[str, str]
    timestamp: datetime
