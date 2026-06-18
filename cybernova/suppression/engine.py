"""
CyberNova — Alert Suppression Engine
Handles deduplication, suppression rules, and noise reduction.
"""
import asyncio
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.suppression.models import (
    SuppressionRule, SuppressionType, SuppressionScope,
    SuppressionMatch, DedupKey,
)

log = logging.getLogger("cybernova.suppression.engine")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DedupTracker:
    """
    In-memory deduplication tracker using a sliding window.
    Tracks alert fingerprints and suppresses duplicates within the window.
    """
    
    def __init__(self):
        self._buckets: Dict[str, list] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    async def check_and_record(self, key: DedupKey, window_minutes: int = 60) -> SuppressionMatch:
        async with self._lock:
            now = time.time()
            cache_key = key.to_key()
            cutoff = now - (window_minutes * 60)
            
            self._buckets[cache_key] = [t for t in self._buckets[cache_key] if t > cutoff]
            
            if self._buckets[cache_key]:
                self._buckets[cache_key].append(now)
                return SuppressionMatch(
                    suppressed=True,
                    reason=f"Duplicate alert (same rule + source within {window_minutes}m window)",
                    suppressed_count=len(self._buckets[cache_key]),
                )
            
            self._buckets[cache_key].append(now)
            return SuppressionMatch(suppressed=False)
    
    async def get_count(self, key: DedupKey, window_minutes: int = 60) -> int:
        async with self._lock:
            cache_key = key.to_key()
            cutoff = time.time() - (window_minutes * 60)
            return len([t for t in self._buckets[cache_key] if t > cutoff])
    
    def cleanup(self) -> None:
        now = time.time()
        for key in list(self._buckets.keys()):
            cutoff = now - 3600
            self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
            if not self._buckets[key]:
                del self._buckets[key]


class SuppressionEngine:
    """
    Evaluates alerts against suppression rules and dedup tracker.
    """
    
    def __init__(self):
        self._rules: Dict[str, SuppressionRule] = {}
        self._dedup = DedupTracker()
        self._lock = asyncio.Lock()
    
    # ── Rule Management ──────────────────────────────────────────────────
    
    async def add_rule(self, rule: SuppressionRule) -> None:
        async with self._lock:
            self._rules[rule.id] = rule
    
    async def remove_rule(self, rule_id: str) -> bool:
        async with self._lock:
            return self._rules.pop(rule_id, None) is not None
    
    async def update_rule(self, rule: SuppressionRule) -> None:
        async with self._lock:
            self._rules[rule.id] = rule
    
    async def get_rule(self, rule_id: str) -> Optional[SuppressionRule]:
        return self._rules.get(rule_id)
    
    async def list_rules(self, tenant_id: Optional[str] = None) -> List[SuppressionRule]:
        if tenant_id:
            return [r for r in self._rules.values() if r.tenant_id == tenant_id or r.scope == SuppressionScope.GLOBAL]
        return list(self._rules.values())
    
    # ── Evaluation ───────────────────────────────────────────────────────
    
    async def evaluate(self, alert: Dict[str, Any], tenant_id: str) -> SuppressionMatch:
        rule_name = alert.get("rule_name", "")
        source_ip = alert.get("source_ip", "")
        severity = alert.get("severity", "info")
        risk_score = alert.get("risk_score", 0)
        event_type = alert.get("event_type", "")
        message = alert.get("description", "") or alert.get("message", "")
        
        # 1. Check static suppression rules
        async with self._lock:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue
                if rule.tenant_id not in (tenant_id, "global") and rule.scope != SuppressionScope.GLOBAL:
                    continue
                
                if rule.type == SuppressionType.RULE:
                    if rule.pattern and rule.pattern.lower() in rule_name.lower():
                        return SuppressionMatch(
                            suppressed=True, rule_id=rule.id,
                            reason=f"Suppressed by rule '{rule.name}': matches rule pattern '{rule.pattern}'",
                        )
                
                elif rule.type == SuppressionType.SOURCE_IP:
                    if rule.pattern and source_ip and self._match_pattern(source_ip, rule.pattern):
                        return SuppressionMatch(
                            suppressed=True, rule_id=rule.id,
                            reason=f"Suppressed by rule '{rule.name}': source IP matches '{rule.pattern}'",
                        )
                
                elif rule.type == SuppressionType.SEVERITY:
                    if severity and rule.severity_threshold:
                        if SEVERITY_ORDER.get(severity, -1) < SEVERITY_ORDER.get(rule.severity_threshold, 0):
                            continue
                        if risk_score < rule.risk_score_min or risk_score > rule.risk_score_max:
                            continue
                        if rule.pattern and rule.pattern.lower() not in rule_name.lower():
                            continue
                        return SuppressionMatch(
                            suppressed=True, rule_id=rule.id,
                            reason=f"Suppressed by severity rule '{rule.name}': severity={severity}, risk={risk_score}",
                        )
                
                elif rule.type == SuppressionType.PATTERN:
                    if rule.pattern and re.search(rule.pattern, message, re.IGNORECASE):
                        return SuppressionMatch(
                            suppressed=True, rule_id=rule.id,
                            reason=f"Suppressed by pattern rule '{rule.name}': message matches '{rule.pattern}'",
                        )
        
        # 2. Deduplication check
        if rule_name and source_ip:
            dedup_key = DedupKey(
                tenant_id=tenant_id,
                rule_name=rule_name,
                source_ip=source_ip,
                event_type=event_type or rule_name,
            )
            match = await self._dedup.check_and_record(dedup_key, window_minutes=60)
            if match.suppressed:
                return match
        
        return SuppressionMatch(suppressed=False)
    
    async def get_dedup_count(self, alert: Dict[str, Any], tenant_id: str) -> int:
        rule_name = alert.get("rule_name", "")
        source_ip = alert.get("source_ip", "")
        event_type = alert.get("event_type", "") or rule_name
        if rule_name and source_ip:
            key = DedupKey(tenant_id, rule_name, source_ip, event_type)
            return await self._dedup.get_count(key)
        return 0
    
    @staticmethod
    def _match_pattern(value: str, pattern: str) -> bool:
        if "*" in pattern:
            regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
            return bool(re.search(regex, value))
        return pattern.lower() in value.lower()


async def seed_default_suppression_rules():
    """Create default suppression rules for common noisy patterns."""
    now = datetime.now(timezone.utc).isoformat()
    defaults = [
        SuppressionRule(
            id="suppress-heartbeat",
            tenant_id="default",
            name="Suppress Agent Heartbeats",
            description="Suppress agent heartbeat alerts (informational only)",
            type=SuppressionType.RULE,
            pattern="agent_heartbeat",
            enabled=True,
            created_at=now, updated_at=now,
        ),
        SuppressionRule(
            id="suppress-port-scan-low",
            tenant_id="default",
            name="Suppress Low-Severity Port Scans",
            description="Suppress port scan alerts with low severity and low risk score (false positives from scanners)",
            type=SuppressionType.SEVERITY,
            pattern="port_scan",
            severity_threshold="low",
            risk_score_max=65,
            enabled=True,
            created_at=now, updated_at=now,
        ),
        SuppressionRule(
            id="suppress-low-risk-events",
            tenant_id="default",
            name="Suppress Low-Risk Info Events",
            description="Suppress all info/low severity events with risk_score < 25 (new_process, logoff, ssh/http/tls connections, usb_removed, etc.)",
            type=SuppressionType.SEVERITY,
            pattern="",
            severity_threshold="info",
            risk_score_max=25,
            enabled=True,
            created_at=now, updated_at=now,
        ),
        SuppressionRule(
            id="dedup-default",
            tenant_id="default",
            name="Default Deduplication",
            description="Deduplicate identical alerts within 60 minutes",
            type=SuppressionType.DEDUP,
            window_minutes=60,
            enabled=True,
            created_at=now, updated_at=now,
        ),
    ]
    for rule in defaults:
        await suppression_engine.add_rule(rule)


suppression_engine = SuppressionEngine()
