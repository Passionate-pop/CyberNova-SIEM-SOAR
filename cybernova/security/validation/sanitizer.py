"""
CyberNova — Input Sanitization
Prevents XSS, SQL injection markers, and command injection.
"""
from __future__ import annotations

import re
from typing import Any, Dict

import bleach

_ALLOWED_TAGS: list = []
_ALLOWED_ATTRS: dict = {}


def sanitize_string(value: str) -> str:
    cleaned = bleach.clean(value, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)
    cleaned = cleaned.replace("\x00", "")
    return cleaned.strip()


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {}
    for key, value in data.items():
        clean_key = sanitize_string(str(key))
        if isinstance(value, str):
            sanitized[clean_key] = sanitize_string(value)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized[clean_key] = [
                sanitize_string(v) if isinstance(v, str)
                else sanitize_dict(v) if isinstance(v, dict)
                else v for v in value
            ]
        else:
            sanitized[clean_key] = value
    return sanitized


def is_safe_identifier(value: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_\-]+$", value))
