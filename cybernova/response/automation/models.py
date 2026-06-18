from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class StepType(str, Enum):
    ACTION = "action"
    CONDITION = "condition"
    DELAY = "delay"
    NOTIFICATION = "notification"
    APPROVAL = "approval"
    SUB_PLAYBOOK = "sub_playbook"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PlaybookTrigger(str, Enum):
    ALERT_CREATED = "alert_created"
    ALERT_UPDATED = "alert_updated"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class ConditionOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    IN = "in"
    NOT_IN = "not_in"
    MATCHES = "matches"


@dataclass
class Condition:
    field: str
    operator: ConditionOperator
    value: Any


@dataclass
class StepConfig:
    action_type: Optional[str] = None
    action_params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[Condition] = None
    conditions: List[Condition] = field(default_factory=list)
    else_steps: List[dict] = field(default_factory=list)
    delay_seconds: int = 0
    notification_channel: Optional[str] = None
    notification_message: Optional[str] = None
    approval_roles: List[str] = field(default_factory=list)
    playbook_id: Optional[str] = None


@dataclass
class PlaybookStep:
    id: str
    name: str
    type: StepType
    config: StepConfig = field(default_factory=StepConfig)
    next_on_success: Optional[str] = None
    next_on_failure: Optional[str] = None
    timeout_seconds: Optional[int] = None


@dataclass
class PlaybookDefinition:
    id: str
    name: str
    description: str = ""
    trigger: PlaybookTrigger = PlaybookTrigger.ALERT_CREATED
    enabled: bool = True
    priority: int = 5
    tenant_id: str = "default"
    conditions: List[Condition] = field(default_factory=list)
    steps: List[PlaybookStep] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger.value,
            "enabled": self.enabled,
            "priority": self.priority,
            "tenant_id": self.tenant_id,
            "conditions": [{"field": c.field, "operator": c.operator.value, "value": c.value} for c in self.conditions],
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.type.value,
                    "config": {k: v for k, v in s.config.__dict__.items() if v is not None},
                    "next_on_success": s.next_on_success,
                    "next_on_failure": s.next_on_failure,
                    "timeout_seconds": s.timeout_seconds,
                }
                for s in self.steps
            ],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class StepExecution:
    step_id: str
    step_name: str
    step_type: StepType
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class PlaybookExecution:
    id: str
    playbook_id: str
    playbook_name: str
    trigger: PlaybookTrigger
    context: Dict[str, Any]
    status: ExecutionStatus = ExecutionStatus.RUNNING
    steps: List[StepExecution] = field(default_factory=list)
    current_step_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    last_retry_at: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
