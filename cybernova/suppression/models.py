"""
CyberNova — Alert Suppression Models
"""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class SuppressionType(str, Enum):
    DEDUP = "dedup"  # Deduplicate identical alerts within time window
    RULE = "rule"    # Suppress by rule name
    SOURCE_IP = "source_ip"  # Suppress by source IP
    SEVERITY = "severity"  # Suppress by severity threshold
    PATTERN = "pattern"  # Suppress by regex pattern on message/description
    CUSTOM = "custom"  # Custom suppression logic


class SuppressionScope(str, Enum):
    GLOBAL = "global"  # Applies to all tenants
    TENANT = "tenant"  # Applies to specific tenant
    RULE = "rule"  # Applies to specific rule


@dataclass
class SuppressionRule:
    id: str
    tenant_id: str
    name: str
    description: str = ""
    type: SuppressionType = SuppressionType.RULE
    scope: SuppressionScope = SuppressionScope.TENANT
    pattern: str = ""  # Rule name, source IP, or regex pattern
    severity_threshold: Optional[str] = None  # "low", "medium", "high", "critical"
    risk_score_min: float = 0.0
    risk_score_max: float = 100.0
    window_minutes: int = 60  # For dedup: time window
    max_count: int = 0  # 0 = unlimited (just dedup), >0 = max before alerting stops
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "type": self.type.value,
            "scope": self.scope.value,
            "pattern": self.pattern,
            "severity_threshold": self.severity_threshold,
            "risk_score_min": self.risk_score_min,
            "risk_score_max": self.risk_score_max,
            "window_minutes": self.window_minutes,
            "max_count": self.max_count,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class SuppressionMatch:
    suppressed: bool
    rule_id: Optional[str] = None
    reason: str = ""
    suppressed_count: int = 0


@dataclass
class DedupKey:
    tenant_id: str
    rule_name: str
    source_ip: str
    event_type: str
    
    def to_key(self) -> str:
        return f"{self.tenant_id}:{self.rule_name}:{self.source_ip}:{self.event_type}"
