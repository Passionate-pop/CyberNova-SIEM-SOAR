"""
CyberNova — Dynamic Detection Rules DSL
Rules stored in DB, evaluated via expression parser, hot-reloadable per tenant.
Rule format:
{
  "rule": "failed_logins > 5 in 60s",
  "severity": "high"
}
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from cybernova.core.utils.helpers import utcnow
from cybernova.detection.isolation.manager import tenant_isolation

log = logging.getLogger("cybernova.detection.rules_dsl")


@dataclass
class DetectionRule:
    id: str
    tenant_id: str
    name: str
    description: str
    rule_expression: str
    severity: str
    risk_score: float
    event_type: str
    enabled: bool
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    @classmethod
    def from_dict(cls, d: Dict[str, Any], tenant_id: str = "default") -> "DetectionRule":
        return cls(
            id=d.get("id", str(uuid4())),
            tenant_id=tenant_id or d.get("tenant_id", "default"),
            name=d.get("name", ""),
            description=d.get("description", ""),
            rule_expression=d.get("rule_expression", d.get("rule", "")),
            severity=d.get("severity", "medium"),
            risk_score=d.get("risk_score", 50.0),
            event_type=d.get("event_type", ""),
            enabled=d.get("enabled", True),
            created_at=d.get("created_at", utcnow()),
            updated_at=d.get("updated_at", utcnow()),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "rule_expression": self.rule_expression,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "event_type": self.event_type,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "updated_at": self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at,
        }


BUILTIN_RULES: List[Dict[str, Any]] = [
    {"name": "Failed Login Pattern", "description": "Multiple failed login attempts detected", "rule_expression": "failed_logins > 3 in 60s", "severity": "high", "risk_score": 65.0, "event_type": "auth", "enabled": True},
    {"name": "Brute Force Attack", "description": "Brute force attack pattern detected", "rule_expression": "failed_logins > 10 in 120s", "severity": "critical", "risk_score": 90.0, "event_type": "auth", "enabled": True},
    {"name": "Port Scan Detection", "description": "Multiple ports accessed in short time", "rule_expression": "unique_ports > 10 in 30s", "severity": "high", "risk_score": 70.0, "event_type": "network", "enabled": True},
    {"name": "Malware Detected", "description": "Malware signature match", "rule_expression": "threat_level > 5", "severity": "critical", "risk_score": 95.0, "event_type": "malware", "enabled": True},
    {"name": "Suspicious Outbound", "description": "Unusual outbound traffic pattern", "rule_expression": "bytes_out > 1000000 in 60s", "severity": "medium", "risk_score": 55.0, "event_type": "network", "enabled": True},
    {"name": "Privilege Escalation", "description": "Privilege escalation attempt detected", "rule_expression": "privilege_change == true", "severity": "critical", "risk_score": 85.0, "event_type": "auth", "enabled": True},
    {"name": "Data Exfiltration", "description": "Large data transfer detected", "rule_expression": "bytes_out > 50000000 in 300s", "severity": "critical", "risk_score": 95.0, "event_type": "data", "enabled": True},
    {"name": "C2 Communication", "description": "Possible C2 communication detected", "rule_expression": "suspicious_connections > 5 in 60s", "severity": "critical", "risk_score": 90.0, "event_type": "network", "enabled": True},
]


class RuleExpressionParser:
    def __init__(self) -> None:
        self._compiled: Dict[str, Callable[[Dict[str, Any]], Optional[float]]] = {}

    def compile(self, expression: str) -> Callable[[Dict[str, Any]], Optional[float]]:
        if expression in self._compiled:
            return self._compiled[expression]

        rate_pattern = re.compile(
            r"(\w+)\s*(==|!=|>|<|>=|<=)\s*(.+?)\s+in\s+(\d+)([smhd])"
        )
        simple_pattern = re.compile(
            r"(\w+)\s*(==|!=|>|<|>=|<=)\s*(.+)"
        )

        def evaluator(event: Dict[str, Any]) -> Optional[float]:
            m = rate_pattern.match(expression)
            if m:
                field_name, op, value, amount, unit = m.groups()
                seconds = self._unit_to_seconds(amount, unit)
                return self._evaluate_rate(event, field_name, op, value.strip(), seconds)
            
            m = simple_pattern.match(expression)
            if m:
                field_name, op, value = m.groups()
                return self._evaluate_simple(event, field_name, op, value.strip())
            
            return None

        self._compiled[expression] = evaluator
        return evaluator

    def _unit_to_seconds(self, amount: str, unit: str) -> int:
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return int(amount) * multipliers.get(unit, 1)

    def _evaluate_rate(
        self, event: Dict[str, Any], field: str, op: str, value: str, window: int
    ) -> Optional[float]:
        count = self._get_field_value(event, field)
        if count is None:
            return None
        threshold = float(value.strip())
        if self._compare(count, op, threshold):
            return float(count)
        return None

    def _evaluate_simple(self, event: Dict[str, Any], field: str, op: str, value: str) -> Optional[float]:
        field_val = self._get_field_value(event, field)
        if field_val is None:
            return None
        threshold = self._parse_value(value)
        if threshold is None:
            return None
        if self._compare(field_val, op, threshold):
            return float(field_val)
        return None

    def _get_field_value(self, event: Dict[str, Any], field: str) -> Optional[float]:
        val = event.get(field)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                return None
        raw = event.get("raw_event", {})
        val = raw.get(field)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                return None
        return None

    def _parse_value(self, value: str) -> Optional[float]:
        value = value.strip()
        if value.lower() == "true":
            return 1.0
        if value.lower() == "false":
            return 0.0
        try:
            return float(value)
        except ValueError:
            return None

    def _compare(self, a: float, op: str, b: float) -> bool:
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == ">":
            return a > b
        if op == "<":
            return a < b
        if op == ">=":
            return a >= b
        if op == "<=":
            return a <= b
        return False


class DetectionRulesEngine:
    def __init__(self) -> None:
        self._rules: Dict[str, List[DetectionRule]] = {}
        self._parser = RuleExpressionParser()
        self._lock = asyncio.Lock()

    async def load_rules(self, tenant_id: str = "default") -> List[DetectionRule]:
        async with self._lock:
            if tenant_id in self._rules:
                return self._rules[tenant_id]

            await tenant_isolation.register_tenant(tenant_id)
            rules = await self._load_from_db(tenant_id)
            if not rules:
                rules = [DetectionRule.from_dict(r, tenant_id) for r in BUILTIN_RULES]
                await self._save_to_db(rules, tenant_id)
                log.info("Seeded %d detection rules for tenant %s", len(rules), tenant_id)

            self._rules[tenant_id] = rules
            for _ in rules:
                await tenant_isolation.increment_rule_count(tenant_id)
            return rules

    async def _load_from_db(self, tenant_id: str) -> List[DetectionRule]:
        try:
            from cybernova.database.postgres.session import get_db_session
            async for db in get_db_session():
                from sqlalchemy import text
                result = await db.execute(
                    text("SELECT id, tenant_id, name, description, rule_expression, severity, risk_score, event_type, enabled, created_at FROM detection_rules WHERE tenant_id = :tid AND enabled = true"),
                    {"tid": tenant_id}
                )
                rows = result.fetchall()
                if rows:
                    return [
                        DetectionRule(
                            id=r[0], tenant_id=r[1], name=r[2], description=r[3],
                            rule_expression=r[4], severity=r[5], risk_score=r[6],
                            event_type=r[7], enabled=r[8], created_at=r[9],
                        )
                        for r in rows
                    ]
                return []
        except Exception as exc:
            log.warning("Could not load detection rules from DB: %s", exc)
            return []

    async def _save_to_db(self, rules: List[DetectionRule], tenant_id: str) -> None:
        try:
            from cybernova.database.postgres.session import get_db_session
            async for db in get_db_session():
                from sqlalchemy import text
                for rule in rules:
                    await db.execute(
                        text("""
                            INSERT INTO detection_rules (id, tenant_id, name, description, rule_expression, severity, risk_score, event_type, enabled, created_at)
                            VALUES (:id, :tid, :name, :desc, :expr, :sev, :score, :etype, :en, :ca)
                            ON CONFLICT (id) DO NOTHING
                        """),
                        {
                            "id": rule.id, "tid": rule.tenant_id, "name": rule.name,
                            "desc": rule.description, "expr": rule.rule_expression,
                            "sev": rule.severity, "score": rule.risk_score,
                            "etype": rule.event_type, "en": rule.enabled, "ca": rule.created_at,
                        }
                    )
                await db.commit()
        except Exception as exc:
            log.warning("Could not save detection rules to DB: %s", exc)

    async def add_rule(self, rule: DetectionRule) -> None:
        async with self._lock:
            tenant = rule.tenant_id
            if tenant not in self._rules:
                self._rules[tenant] = []
            self._rules[tenant] = [r if r.id != rule.id else rule for r in self._rules[tenant]]

    async def evaluate(self, event: Dict[str, Any], tenant_id: str = "default") -> List[DetectionRule]:
        allowed = await tenant_isolation.record_evaluation(tenant_id)
        if not allowed:
            log.warning("Tenant %s evaluation blocked (quota/circuit)", tenant_id)
            return []
        rules = self._rules.get(tenant_id, [])
        triggered = []
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.event_type and rule.event_type not in (event.get("event_type", ""), event.get("raw_event", {}).get("event_type", "")):
                continue
            try:
                evaluator = self._parser.compile(rule.rule_expression)
                if evaluator(event) is not None:
                    triggered.append(rule)
            except Exception as exc:
                log.warning("Rule %s evaluation error: %s", rule.name, exc)
                await tenant_isolation.record_error(tenant_id)
        return triggered


detection_rules_engine = DetectionRulesEngine()
