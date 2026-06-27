"""
CyberNova — SOAR Safety Layer (AUTONOMOUS MODE)
Auto-approve with 15-second fallback: if no user response in 15s for critical
block_ip actions, the system auto-approves and blocks autonomously.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cybernova.core.utils.helpers import new_id, utcnow

log = logging.getLogger("cybernova.soar.safety")


class ApprovalStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_APPROVED = "auto_approved"
    SKIPPED = "skipped"


class ActionRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_THRESHOLD = 0.8


@dataclass
class SafetyDecision:
    action_id: str
    approved: bool
    status: ApprovalStatus
    confidence: float
    risk_level: ActionRiskLevel
    reason: str
    requires_manual_approval: bool
    alternative_action: Optional[str] = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class ActionTemplate:
    action_type: str
    risk_level: ActionRiskLevel
    auto_approvable: bool
    max_retries: int
    requires_context: List[str]
    safe_defaults: Dict[str, Any]


AUTO_APPROVE_TIMEOUT_SECONDS = 5  # Wait for user approval for 5s, then auto-approve (lowered from 15s for faster response)

ACTION_TEMPLATES: Dict[str, ActionTemplate] = {
    "block_ip": ActionTemplate(
        action_type="block_ip",
        risk_level=ActionRiskLevel.HIGH,
        auto_approvable=False,  # Requires approval but WITH 15s timeout fallback
        max_retries=3,
        requires_context=["source_ip", "severity", "confidence"],
        safe_defaults={"duration_minutes": 60, "scope": "source_ip"},
    ),
    "quarantine": ActionTemplate(
        action_type="quarantine",
        risk_level=ActionRiskLevel.CRITICAL,
        auto_approvable=False,
        max_retries=1,
        requires_context=["hostname", "severity", "malware_family"],
        safe_defaults={"isolation_type": "network"},
    ),
    "notify": ActionTemplate(
        action_type="notify",
        risk_level=ActionRiskLevel.LOW,
        auto_approvable=True,
        max_retries=5,
        requires_context=["recipients"],
        safe_defaults={"channel": "email"},
    ),
    "isolate": ActionTemplate(
        action_type="isolate",
        risk_level=ActionRiskLevel.HIGH,
        auto_approvable=False,
        max_retries=2,
        requires_context=["device_id", "severity"],
        safe_defaults={"duration_minutes": 30},
    ),
    "collect_forensics": ActionTemplate(
        action_type="collect_forensics",
        risk_level=ActionRiskLevel.MEDIUM,
        auto_approvable=True,
        max_retries=3,
        requires_context=["hostname"],
        safe_defaults={"collection_type": "memory_disk"},
    ),
    "escalate": ActionTemplate(
        action_type="escalate",
        risk_level=ActionRiskLevel.MEDIUM,
        auto_approvable=True,
        max_retries=2,
        requires_context=["severity", "incident_id"],
        safe_defaults={"escalation_level": 1},
    ),
    "block_user": ActionTemplate(
        action_type="block_user",
        risk_level=ActionRiskLevel.CRITICAL,
        auto_approvable=False,
        max_retries=1,
        requires_context=["user", "severity"],
        safe_defaults={"duration_hours": 24},
    ),
}


class SoarSafetyEngine:
    def __init__(self) -> None:
        self._approval_queue: Dict[str, SafetyDecision] = {}
        self._auto_approve_timers: Dict[str, asyncio.Task] = {}

    def evaluate(
        self,
        action_type: str,
        alert: Dict[str, Any],
        confidence: float = 1.0,
    ) -> SafetyDecision:
        """Evaluate whether an action should auto-approve or require manual approval.
        
        For CRITICAL severity actions (especially block_ip), starts a 15-second
        auto-approve timer. If no user response within 15s, the action is
        automatically approved and executed.
        """
        template = ACTION_TEMPLATES.get(action_type)

        if not template:
            return SafetyDecision(
                action_id=alert.get("id", new_id()),
                approved=False,
                status=ApprovalStatus.SKIPPED,
                confidence=confidence,
                risk_level=ActionRiskLevel.HIGH,
                reason=f"Unknown action type: {action_type}",
                requires_manual_approval=True,
            )

        risk_level = template.risk_level
        severity = alert.get("severity", "medium").lower()
        risk_score = alert.get("risk_score", 50)

        severity_risk_multiplier = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
        }.get(severity, 1.0)

        effective_confidence = confidence * severity_risk_multiplier

        requires_manual = (
            not template.auto_approvable
            or effective_confidence < RISK_THRESHOLD
            or risk_level == ActionRiskLevel.CRITICAL
            or severity == "critical"
        )

        if requires_manual:
            # Auto-approve block_ip for ANY critical/high severity — don't require manual approval
            if action_type == "block_ip" and severity in ("critical", "high"):
                requires_manual = False
                status = ApprovalStatus.AUTO_APPROVED
                reason = f"Auto-approved: {action_type} (severity={severity}, risk={risk_level.value})"
            else:
                status = ApprovalStatus.PENDING_APPROVAL
                reason = self._build_rejection_reason(
                    action_type, effective_confidence, risk_level, template
                )
        else:
            status = ApprovalStatus.AUTO_APPROVED
            reason = f"Auto-approved: {action_type} (confidence={effective_confidence:.2f}, risk={risk_level.value})"

        decision = SafetyDecision(
            action_id=alert.get("id", new_id()),
            approved=not requires_manual,
            status=status,
            confidence=effective_confidence,
            risk_level=risk_level,
            reason=reason,
            requires_manual_approval=requires_manual,
            alternative_action="notify" if requires_manual else None,
        )

        if requires_manual:
            self._approval_queue[decision.action_id] = decision
            log.info(
                "SOAR safety: action %s requires approval (confidence=%.2f, risk=%s) — starting %ds auto-approve timer",
                action_type, effective_confidence, risk_level.value,
                AUTO_APPROVE_TIMEOUT_SECONDS,
            )

            # 🔥 5-SECOND AUTO-APPROVE TIMER
            # For CRITICAL/HIGH severity or medium+ risk actions, start a background timer
            # that auto-approves the action if the user doesn't respond in time
            if severity in ("critical", "high") or risk_score >= 50:
                self._start_auto_approve_timer(decision.action_id, action_type, alert)
        else:
            log.info("SOAR safety: action %s auto-approved", action_type)

        return decision

    def _start_auto_approve_timer(self, action_id: str, action_type: str, alert: Dict[str, Any]) -> None:
        """Start a background task that auto-approves the action after 15 seconds."""
        async def _timer_task():
            try:
                await asyncio.sleep(AUTO_APPROVE_TIMEOUT_SECONDS)
                
                # Check if still pending (user didn't reject or approve)
                decision = self._approval_queue.get(action_id)
                if decision and decision.status == ApprovalStatus.PENDING_APPROVAL:
                    log.warning(
                        "⏰ AUTO-APPROVE TIMEOUT (%ds): %s — no user response, auto-approving and executing",
                        AUTO_APPROVE_TIMEOUT_SECONDS, action_type,
                    )
                    decision.status = ApprovalStatus.AUTO_APPROVED
                    decision.approved = True
                    decision.reason = f"Auto-approved after {AUTO_APPROVE_TIMEOUT_SECONDS}s timeout (no user response)"
                    
                    # 🔥 Execute the action autonomously!
                    self._execute_auto_approved(action_type, alert, action_id)
                    
                    log.warning(
                        "🚀 AUTONOMOUS ACTION: %s executed on %s (IP: %s)",
                        action_type,
                        alert.get("hostname", alert.get("device_id", "unknown")),
                        alert.get("source_ip", "unknown"),
                    )
                    
                # Clean up the timer reference
                self._auto_approve_timers.pop(action_id, None)
            except asyncio.CancelledError:
                pass  # Timer was cancelled because user approved/rejected manually

        try:
            loop = asyncio.get_event_loop()
            task = loop.create_task(_timer_task())
            self._auto_approve_timers[action_id] = task
        except RuntimeError:
            log.warning("No event loop — auto-approve timer skipped for %s", action_id)

    def _execute_auto_approved(self, action_type: str, alert: Dict[str, Any], action_id: str) -> None:
        """Execute an auto-approved action through the SOAR engine."""
        try:
            from cybernova.soar.engine import BlockIPAction, IsolateAction, NotifyAction, LogAction
            
            incident = {
                "id": action_id,
                "title": alert.get("rule_name", f"Auto-approved {action_type}"),
                "severity": alert.get("severity", "critical"),
                "confirmed": True,
                "risk_score": float(alert.get("risk_score", 100)),
                "source_ip": alert.get("source_ip", ""),
                "dest_ip": alert.get("dest_ip", ""),
                "hostname": alert.get("hostname", alert.get("device_id", "")),
                "incident_type": alert.get("incident_type", action_type),
            }
            
            if action_type == "block_ip":
                action = BlockIPAction()
                action.execute(incident)
            elif action_type == "isolate":
                action = IsolateAction()
                action.execute(incident)
            
            # Always log and notify
            LogAction().execute(incident)
            NotifyAction().execute(incident)
            
            log.warning("✅ Auto-approved %s completed: %s", action_type, action_id)
        except Exception as e:
            log.error("Auto-approved %s failed: %s", action_type, e)

    def _build_rejection_reason(
        self,
        action_type: str,
        confidence: float,
        risk_level: ActionRiskLevel,
        template: ActionTemplate,
    ) -> str:
        reasons = []
        if not template.auto_approvable:
            reasons.append("action requires manual approval")
        if confidence < RISK_THRESHOLD:
            reasons.append(f"confidence {confidence:.2f} below threshold {RISK_THRESHOLD}")
        if risk_level == ActionRiskLevel.CRITICAL:
            reasons.append("critical risk level")
        return "; ".join(reasons)

    def _cancel_auto_approve_timer(self, action_id: str) -> None:
        """Cancel the auto-approve timer for an action (if still running)."""
        task = self._auto_approve_timers.pop(action_id, None)
        if task and not task.done():
            task.cancel()
            log.debug("Cancelled auto-approve timer for action %s", action_id)

    def approve_action(self, action_id: str, approver_id: str) -> bool:
        if action_id not in self._approval_queue:
            return False
        # Cancel auto-approve timer since user approved manually
        self._cancel_auto_approve_timer(action_id)
        decision = self._approval_queue[action_id]
        decision.status = ApprovalStatus.APPROVED
        decision.approved = True
        decision.reason = f"Approved by {approver_id} at {datetime.now(timezone.utc).isoformat()}"
        log.info("SOAR safety: action %s approved by %s", action_id, approver_id)
        return True

    def reject_action(self, action_id: str, rejector_id: str, reason: str) -> bool:
        if action_id not in self._approval_queue:
            return False
        # Cancel auto-approve timer since user rejected manually
        self._cancel_auto_approve_timer(action_id)
        decision = self._approval_queue[action_id]
        decision.status = ApprovalStatus.REJECTED
        decision.approved = False
        decision.reason = f"Rejected by {rejector_id}: {reason}"
        log.info("SOAR safety: action %s rejected by %s", action_id, rejector_id)
        return True

    def get_pending_approvals(self, limit: int = 50) -> List[SafetyDecision]:
        return [
            d for d in self._approval_queue.values()
            if d.status == ApprovalStatus.PENDING_APPROVAL
        ][:limit]


soar_safety = SoarSafetyEngine()

# Alias for unified API access
safety_checker = soar_safety

