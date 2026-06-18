"""
CyberNova — Common Validators
"""
from __future__ import annotations

import ipaddress
import re

from cybernova.config.constants import SEVERITY_ALIASES, VALID_SEVERITIES


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_port(port: int) -> bool:
    return 0 < port <= 65535


def is_valid_severity(severity: str) -> bool:
    return severity.lower() in VALID_SEVERITIES


def normalize_severity(severity: str) -> str:
    s = severity.lower().strip()
    return SEVERITY_ALIASES.get(s, s if s in VALID_SEVERITIES else "info")


def extract_ip_addresses(text: str) -> list[str]:
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(pattern, text)
    return [ip for ip in candidates if is_valid_ip(ip)]
