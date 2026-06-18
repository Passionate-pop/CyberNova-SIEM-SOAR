"""
CyberNova — Rate Limiting
Redis-backed rate limiter with in-memory fallback.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("cybernova.security.rate_limit")

# Ensure UTF-8 encoding for file reads
os.environ["PYTHONIOENCODING"] = "utf-8"


def get_limiter():
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    return Limiter(
        key_func=get_remote_address,
        default_limits=["1000/minute"],
        storage_uri="memory://",
    )
