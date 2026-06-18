"""
Data Loss Prevention — detects sensitive data (PII, credentials, secrets)
in transit, at rest, and in event payloads.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.protection.dlp")

SENSITIVE_PATTERNS = {
    "aws_access_key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "aws_secret_key": re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]([A-Za-z0-9+/=]{40})['\"]"),
    "gcp_service_account": re.compile(r"(\"type\":\s*\"service_account\")"),
    "azure_connection_string": re.compile(r"(DefaultEndpointsProtocol=https;AccountName=)"),
    "github_token": re.compile(r"(ghp_[0-9a-zA-Z]{36})"),
    "github_old_token": re.compile(r"(gho_[0-9a-zA-Z]{36})"),
    "github_pat": re.compile(r"(github_pat_[0-9a-zA-Z]{82})"),
    "slack_token": re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{24,})"),
    "discord_token": re.compile(r"(mfa\.[a-zA-Z0-9_-]{84})"),
    "jwt_token": re.compile(r"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),
    "private_ssh_key": re.compile(r"(-{5,}BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-{5,})"),
    "pgp_private_key": re.compile(r"(-{5,}BEGIN PGP PRIVATE KEY BLOCK-{5,})"),
    "generic_api_key": re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I),
    "password_inline": re.compile(r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.I),
    "secret_inline": re.compile(r"(secret|token|credential)\s*[:=]\s*['\"][A-Za-z0-9_\-+/=]{8,}['\"]", re.I),
    "ssn": re.compile(r"\b(\d{3}-\d{2}-\d{4})\b"),
    "credit_card": re.compile(r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b"),
    "email": re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
    "ip_address_internal": re.compile(r"\b((10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))\b"),
    "database_connection_string": re.compile(r"(postgresql|mysql|mongodb|redis|sqlite)://[^\s]{10,}"),
    "basic_auth_header": re.compile(r"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,})", re.I),
    "bearer_token": re.compile(r"(Authorization:\s*Bearer\s+[A-Za-z0-9._-]{10,})", re.I),
}

SEVERITY_MAP = {
    "aws_access_key": "critical", "aws_secret_key": "critical",
    "gcp_service_account": "critical", "azure_connection_string": "critical",
    "github_token": "high", "github_old_token": "high", "github_pat": "high",
    "slack_token": "high", "discord_token": "high",
    "jwt_token": "critical",
    "private_ssh_key": "critical", "pgp_private_key": "critical",
    "generic_api_key": "high", "password_inline": "high",
    "secret_inline": "medium",
    "ssn": "critical", "credit_card": "critical",
    "email": "low",
    "ip_address_internal": "low",
    "database_connection_string": "critical",
    "basic_auth_header": "critical", "bearer_token": "critical",
}  # nosec - severity labels, not secrets


RISK_MAP = {
    "critical": 90.0, "high": 75.0, "medium": 50.0, "low": 20.0, "info": 5.0,
}


def scan_text(text: str, context: Optional[str] = None) -> Dict[str, Any]:
    findings = []
    max_risk = 0.0

    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            sev = SEVERITY_MAP.get(name, "medium")
            risk = RISK_MAP.get(sev, 50.0)
            # Deduplicate matches and truncate for safety
            unique_matches = list(set(m[0] if isinstance(m, tuple) else m for m in matches))[:3]
            masked = [m[:4] + "..." + m[-4:] if len(m) > 12 else m for m in unique_matches]
            findings.append({
                "type": f"dlp_{name}",
                "severity": sev,
                "risk_score": risk,
                "message": f"Sensitive data detected: {name} ({sev})",
                "pattern": name,
                "matches": masked,
                "count": len(matches),
            })
            max_risk = max(max_risk, risk)

    return {
        "dlp_scan_complete": True,
        "sensitive_data_found": len(findings) > 0,
        "max_risk_score": round(max_risk, 1),
        "finding_count": len(findings),
        "findings": findings,
        "context": context,
    }


def scan_event(event: dict) -> Optional[Dict[str, Any]]:
    text_parts = []
    for field in ("message", "raw_log", "payload"):
        val = event.get(field)
        if val:
            text_parts.append(str(val))
    extra = event.get("extra_data") or event.get("extra", {})
    for val in extra.values():
        if isinstance(val, str) and len(val) < 10000:
            text_parts.append(val)
    combined = " ".join(text_parts)
    if not combined:
        return None
    return scan_text(combined, context=f"event_{event.get('event_type', 'unknown')}")


class DLPEngine:
    """Data Loss Prevention engine — wraps pattern scanning with rule discovery."""

    def __init__(self) -> None:
        self._patterns = dict(SENSITIVE_PATTERNS)

    @property
    def rules(self) -> Dict[str, str]:
        return {name: sev for name, sev in SEVERITY_MAP.items()}

    @property
    def patterns(self) -> Dict[str, re.Pattern]:
        return self._patterns

    def __call__(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        return self.scan(text, context)

    def scan(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        return scan_text(text, context)

    def scan_event(self, event: dict) -> Optional[Dict[str, Any]]:
        return scan_event(event)


dlp_engine = DLPEngine()
