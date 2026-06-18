"""
CyberNova — Auth Schemas
"""
from __future__ import annotations
import re
from typing import List
from datetime import datetime
from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    username: str
    password: str
    org_key: str = ""


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    tenant_name: str = "default"
    roles: List[str] = ["viewer"]
    org_key: str = ""
    company_size: str = ""

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if len(v) > 100:
            raise ValueError("Username must be at most 100 characters long")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Username can only contain letters, numbers, hyphens, underscores, and dots")
        return v


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    roles: List[str]
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}
