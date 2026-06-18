"""
CyberNova — Global Incident Schemas
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    risk_score: float
    escalation_level: Optional[int] = Field(default=0)
    created_at: datetime
    model_config = {"from_attributes": True}

    @field_validator("escalation_level", mode="before")
    @classmethod
    def default_zero(cls, v):
        return 0 if v is None else v
