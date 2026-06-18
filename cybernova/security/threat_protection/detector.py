"""
CyberNova — Request Threat Protection
Detects suspicious request patterns and blocks abuse.
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("cybernova.security.threat_protection")

# SQL injection patterns
_SQL_PATTERNS = [
    r"(\bunion\b.*\bselect\b)", r"(\bor\b\s+1\s*=\s*1)", r"(;\s*drop\s+table)",
    r"(--\s)", r"(\binsert\b.*\binto\b)", r"(\bdelete\b.*\bfrom\b)",
]
_SQL_RE = re.compile("|".join(_SQL_PATTERNS), re.IGNORECASE)

# XSS patterns
_XSS_PATTERNS = [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*="]
_XSS_RE = re.compile("|".join(_XSS_PATTERNS), re.IGNORECASE)

# Command injection
_CMD_PATTERNS = [r";\s*\w+", r"\|\s*\w+", r"`[^`]+`", r"\$\([^)]+\)"]
_CMD_RE = re.compile("|".join(_CMD_PATTERNS))


def detect_sql_injection(value: str) -> bool:
    return bool(_SQL_RE.search(value))


def detect_xss(value: str) -> bool:
    return bool(_XSS_RE.search(value))


def detect_command_injection(value: str) -> bool:
    return bool(_CMD_RE.search(value))


def scan_request_body(body: str) -> list[str]:
    """Returns list of detected threat types, empty if clean."""
    threats = []
    if detect_sql_injection(body):
        threats.append("sql_injection")
    if detect_xss(body):
        threats.append("xss")
    if detect_command_injection(body):
        threats.append("command_injection")
    if threats:
        log.warning("Threat detected: %s in request body", threats)
    return threats
