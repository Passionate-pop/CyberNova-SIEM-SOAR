"""
CyberNova — Miscellaneous Helpers
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def safe_get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current


def generate_org_key() -> str:
    """Generate a secure organization key."""
    return f"ORG-{secrets.token_urlsafe(8).upper()}"


def hash_org_key(key: str) -> str:
    """Hash an organization key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()
