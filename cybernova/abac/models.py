from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class AttributeSource(str, Enum):
    USER = "user"
    RESOURCE = "resource"
    ACTION = "action"
    ENVIRONMENT = "environment"


class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_OR_EQUAL = "less_or_equal"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    MATCHES = "matches"


@dataclass
class AttributeCondition:
    source: AttributeSource
    key: str
    operator: Operator
    value: Any

    def evaluate(self, context: ABACContext) -> bool:
        attrs = {
            AttributeSource.USER: context.user_attrs,
            AttributeSource.RESOURCE: context.resource_attrs,
            AttributeSource.ACTION: context.action_attrs,
            AttributeSource.ENVIRONMENT: context.env_attrs,
        }
        actual = attrs.get(self.source, {}).get(self.key)

        if self.operator == Operator.EQUALS:
            return actual == self.value
        elif self.operator == Operator.NOT_EQUALS:
            return actual != self.value
        elif self.operator == Operator.IN:
            return actual in self.value if isinstance(self.value, list) else False
        elif self.operator == Operator.NOT_IN:
            return actual not in self.value if isinstance(self.value, list) else False
        elif self.operator == Operator.CONTAINS:
            return self.value in actual if isinstance(actual, (list, str)) else False
        elif self.operator == Operator.GREATER_THAN:
            return isinstance(actual, (int, float)) and actual > self.value
        elif self.operator == Operator.LESS_THAN:
            return isinstance(actual, (int, float)) and actual < self.value
        elif self.operator == Operator.GREATER_OR_EQUAL:
            return isinstance(actual, (int, float)) and actual >= self.value
        elif self.operator == Operator.LESS_OR_EQUAL:
            return isinstance(actual, (int, float)) and actual <= self.value
        elif self.operator == Operator.EXISTS:
            return actual is not None
        elif self.operator == Operator.NOT_EXISTS:
            return actual is None
        elif self.operator == Operator.MATCHES:
            import re
            return bool(re.match(str(self.value), str(actual))) if actual else False
        return False


@dataclass
class ABACPolicy:
    id: str
    name: str
    description: str
    effect: Effect
    conditions: List[AttributeCondition] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True

    def evaluate(self, context: ABACContext) -> Optional[bool]:
        if not self.enabled:
            return None
        for condition in self.conditions:
            if not condition.evaluate(context):
                return None
        return self.effect == Effect.ALLOW


@dataclass
class ABACContext:
    user_attrs: Dict[str, Any] = field(default_factory=dict)
    resource_attrs: Dict[str, Any] = field(default_factory=dict)
    action_attrs: Dict[str, Any] = field(default_factory=dict)
    env_attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ABACEvaluationResult:
    allowed: bool
    matched_policy: Optional[ABACPolicy] = None
    reason: str = ""


class ABACPolicyStore:
    def __init__(self):
        self._policies: Dict[str, ABACPolicy] = {}
        self._by_priority: List[ABACPolicy] = []

    def add_policy(self, policy: ABACPolicy) -> None:
        self._policies[policy.id] = policy
        self._rebuild_priority()

    def remove_policy(self, policy_id: str) -> bool:
        if policy_id in self._policies:
            del self._policies[policy_id]
            self._rebuild_priority()
            return True
        return False

    def get_policy(self, policy_id: str) -> Optional[ABACPolicy]:
        return self._policies.get(policy_id)

    def list_policies(self, enabled_only: bool = False) -> List[ABACPolicy]:
        if enabled_only:
            return [p for p in self._by_priority if p.enabled]
        return list(self._by_priority)

    def _rebuild_priority(self) -> None:
        self._by_priority = sorted(
            self._policies.values(),
            key=lambda p: (-p.priority, p.id),
        )

    def clear(self) -> None:
        self._policies.clear()
        self._by_priority.clear()
