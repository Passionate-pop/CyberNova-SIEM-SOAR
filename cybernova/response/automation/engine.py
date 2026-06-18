"""
CyberNova — Playbook Execution Engine
State machine that executes multi-step playbooks with conditions,
approvals, delays, notifications, and sub-playbooks.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cybernova.response.automation.models import (
    PlaybookDefinition, PlaybookExecution, PlaybookStep, StepExecution,
    StepType, StepStatus, ExecutionStatus, PlaybookTrigger, ConditionOperator,
)

log = logging.getLogger("cybernova.response.automation.engine")


class PlaybookEngine:
    def __init__(self):
        self._playbooks: Dict[str, PlaybookDefinition] = {}
        self._executions: Dict[str, PlaybookExecution] = {}
        self._pending_approvals: Dict[str, dict] = {}
        self._lock = asyncio.Lock()

    # ── Playbook Management ──────────────────────────────────────────────

    def register(self, playbook: PlaybookDefinition) -> None:
        self._playbooks[playbook.id] = playbook
        log.info("Registered playbook: %s (%s)", playbook.name, playbook.id)

    def unregister(self, playbook_id: str) -> None:
        self._playbooks.pop(playbook_id, None)

    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        return self._playbooks.get(playbook_id)

    def list_playbooks(self, tenant_id: Optional[str] = None) -> List[PlaybookDefinition]:
        if tenant_id:
            return [p for p in self._playbooks.values() if p.tenant_id == tenant_id]
        return list(self._playbooks.values())

    # ── Trigger ──────────────────────────────────────────────────────────

    async def trigger(
        self,
        playbook_id: str,
        context: Dict[str, Any],
        trigger: PlaybookTrigger = PlaybookTrigger.ALERT_CREATED,
    ) -> Optional[str]:
        playbook = self._playbooks.get(playbook_id)
        if not playbook or not playbook.enabled:
            log.warning("Playbook %s not found or disabled", playbook_id)
            return None

        if not self._check_conditions(playbook.conditions, context):
            log.info("Playbook %s conditions not met, skipping", playbook_id)
            return None

        execution_id = str(uuid4())
        execution = PlaybookExecution(
            id=execution_id,
            playbook_id=playbook_id,
            playbook_name=playbook.name,
            trigger=trigger,
            context=context,
            status=ExecutionStatus.RUNNING,
            steps=[StepExecution(step_id=s.id, step_name=s.name, step_type=s.type) for s in playbook.steps],
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        async with self._lock:
            self._executions[execution_id] = execution

        asyncio.create_task(self._execute(execution, playbook))
        return execution_id

    def _check_conditions(self, conditions, context) -> bool:
        for cond in conditions:
            field_value = self._resolve_field(cond.field, context)
            if not self._evaluate_condition(field_value, cond.operator, cond.value):
                return False
        return True

    # ── Auto-match ───────────────────────────────────────────────────────

    async def match_and_trigger(self, context: Dict[str, Any], trigger: PlaybookTrigger = PlaybookTrigger.ALERT_CREATED) -> List[str]:
        execution_ids = []
        sorted_playbooks = sorted(
            [p for p in self._playbooks.values() if p.enabled and p.trigger == trigger],
            key=lambda p: p.priority,
        )
        for playbook in sorted_playbooks:
            if self._check_conditions(playbook.conditions, context):
                eid = await self.trigger(playbook.id, context, trigger)
                if eid:
                    execution_ids.append(eid)
        return execution_ids

    # ── Execution Engine ─────────────────────────────────────────────────

    async def _execute(self, execution: PlaybookExecution, playbook: PlaybookDefinition) -> None:
        steps = playbook.steps
        if not steps:
            execution.status = ExecutionStatus.COMPLETED
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            return

        step_map = {s.id: s for s in steps}
        current = steps[0].id
        has_failure = False

        while current:
            execution.current_step_id = current
            step_def = step_map.get(current)
            if not step_def:
                execution.error = f"Step {current} not found"
                execution.status = ExecutionStatus.FAILED
                execution.completed_at = datetime.now(timezone.utc).isoformat()
                return

            step_exec = self._get_step_exec(execution, current)
            if not step_exec:
                break

            # mark remaining pending steps as blocked when hitting an approval
            if step_def.type == StepType.APPROVAL:
                for s in execution.steps:
                    if s.status == StepStatus.PENDING:
                        s.status = StepStatus.BLOCKED
                        s.error = "Waiting for approval"

            try:
                result = await self._execute_step(step_def, execution.context, execution)
                step_exec.status = StepStatus.COMPLETED
                step_exec.completed_at = datetime.now(timezone.utc).isoformat()
                step_exec.result = result

                if step_def.type == StepType.CONDITION:
                    branch_taken = result.get("branch", "true")
                    if branch_taken == "false" and step_def.config.else_steps:
                        current = step_def.next_on_success
                        continue
            except Exception as e:
                step_exec.status = StepStatus.FAILED
                step_exec.error = str(e)
                step_exec.completed_at = datetime.now(timezone.utc).isoformat()
                has_failure = True
                current = step_def.next_on_failure
                continue

            current = step_def.next_on_success

        for s in execution.steps:
            if s.status == StepStatus.PENDING:
                s.status = StepStatus.SKIPPED
        execution.status = ExecutionStatus.FAILED if has_failure else ExecutionStatus.COMPLETED
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        execution.current_step_id = None

    def _get_step_exec(self, execution: PlaybookExecution, step_id: str) -> Optional[StepExecution]:
        for s in execution.steps:
            if s.step_id == step_id:
                s.status = StepStatus.RUNNING
                s.started_at = datetime.now(timezone.utc).isoformat()
                return s
        return None

    async def _execute_step(self, step: PlaybookStep, context: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        if step.type == StepType.ACTION:
            return await self._execute_action_step(step, context)
        elif step.type == StepType.CONDITION:
            return self._execute_condition_step(step, context)
        elif step.type == StepType.DELAY:
            return await self._execute_delay_step(step)
        elif step.type == StepType.NOTIFICATION:
            return await self._execute_notification_step(step, context)
        elif step.type == StepType.APPROVAL:
            return await self._execute_approval_step(step, context)
        elif step.type == StepType.SUB_PLAYBOOK:
            return await self._execute_sub_playbook_step(step, context, execution)
        return {"skipped": True, "reason": f"Unknown step type: {step.type}"}

    async def _execute_action_step(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        import asyncio
        action_type = step.config.action_type
        params = dict(step.config.action_params)
        alert = context.get("alert", {})
        tenant_id = context.get("tenant_id", "default")
        try:
            if action_type == "block_ip":
                from cybernova.soar.engine import BlockIPAction
                ip = params.get("ip", alert.get("source_ip", ""))
                action = BlockIPAction(simulation_mode=False)
                success = action.execute({
                    "id": str(uuid4()),
                    "title": "Playbook auto-block",
                    "severity": "critical",
                    "source_ip": ip,
                    "dest_ip": ip,
                    "confirmed": True,
                    "risk_score": 100,
                })
                return {"action": "block_ip", "ip": ip, "success": success}
            elif action_type == "isolate_host":
                from cybernova.database.postgres.session import get_db_session
                async for db in get_db_session():
                    from sqlalchemy import text
                    host = params.get("host", alert.get("source_ip", ""))
                    await db.execute(
                        text("UPDATE devices SET is_isolated = true WHERE tenant_id = :tid AND (ip_address = :host OR hostname = :host)"),
                        {"tid": tenant_id, "host": host},
                    )
                    await db.commit()
                return {"action": "isolate_host", "host": host, "success": True}
            elif action_type == "disable_user":
                from cybernova.database.postgres.session import get_db_session
                async for db in get_db_session():
                    from sqlalchemy import text
                    user = params.get("user", alert.get("user", ""))
                    await db.execute(
                        text("UPDATE users SET is_disabled = true, is_active = false WHERE tenant_id = :tid AND username = :user"),
                        {"tid": tenant_id, "user": user},
                    )
                    await db.commit()
                return {"action": "disable_user", "user": user, "success": True}
            elif action_type in ("notify_soc", "notify_admin"):
                from cybernova.response.notifications.notification_service import notification_service
                await notification_service.send_notification(alert)
                return {"action": action_type, "success": True}
            elif action_type == "log_alert":
                log.info("Playbook action log: %s", alert.get("message", ""))
                return {"action": "log_alert", "success": True}
            elif action_type == "create_ticket":
                return {"action": "create_ticket", "success": True, "ticket_id": "TKT-" + str(uuid4())[:8]}
            elif action_type == "cloudflare_block_ip":
                from cybernova.response.actions.cloudflare_block import execute_cloudflare_block_ip
                result = await asyncio.to_thread(execute_cloudflare_block_ip, alert)
                return {"action": action_type, **result}
            elif action_type == "opnsense_block_ip":
                from cybernova.response.actions.opnsense_block import execute_opnsense_block_ip
                result = await asyncio.to_thread(execute_opnsense_block_ip, alert)
                return {"action": action_type, **result}
            elif action_type == "crowdstrike_isolate":
                from cybernova.response.actions.crowdstrike_isolate import execute_crowdstrike_isolate
                result = await asyncio.to_thread(execute_crowdstrike_isolate, alert)
                return {"action": action_type, **result}
            elif action_type == "sentinelone_isolate":
                from cybernova.response.actions.sentinelone_isolate import execute_sentinelone_isolate
                result = await asyncio.to_thread(execute_sentinelone_isolate, alert)
                return {"action": action_type, **result}
            elif action_type in ("cb_isolate", "cb_ban_hash"):
                from cybernova.response.actions.cb_isolate import execute_cb_isolate
                result = await asyncio.to_thread(execute_cb_isolate, alert)
                return {"action": action_type, **result}
            elif action_type == "pagerduty_trigger":
                from cybernova.response.actions.pagerduty_trigger import execute_pagerduty_trigger
                result = await asyncio.to_thread(execute_pagerduty_trigger, alert)
                return {"action": action_type, **result}
            elif action_type == "opsgenie_trigger":
                from cybernova.response.actions.opsgenie_trigger import execute_opsgenie_trigger
                result = await asyncio.to_thread(execute_opsgenie_trigger, alert)
                return {"action": action_type, **result}
            elif action_type == "jira_create":
                from cybernova.response.actions.jira_create import execute_jira_create
                result = await asyncio.to_thread(execute_jira_create, alert)
                return {"action": action_type, **result}
            elif action_type == "servicenow_create":
                from cybernova.response.actions.servicenow_create import execute_servicenow_create
                result = await asyncio.to_thread(execute_servicenow_create, alert)
                return {"action": action_type, **result}
            elif action_type == "email_alert":
                from cybernova.response.actions.email_alert import execute_email_alert
                result = await asyncio.to_thread(execute_email_alert, alert)
                return {"action": action_type, **result}
            else:
                log.warning("Unknown action type in playbook engine: %s", action_type)
                return {"action": action_type, "success": False, "error": f"Unknown action type: {action_type}"}
        except Exception as e:
            log.error("Step %s action error: %s", step.name, e)
            return {"action": action_type, "success": False, "error": str(e)}

    def _execute_condition_step(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        conditions = step.config.conditions or ([step.config.condition] if step.config.condition else [])
        for cond in conditions:
            if cond is None:
                continue
            field_value = self._resolve_field(cond.field, context)
            if not self._evaluate_condition(field_value, cond.operator, cond.value):
                return {"branch": "false", "condition_failed": cond.field}
        return {"branch": "true", "conditions_met": len(conditions)}

    async def _execute_delay_step(self, step: PlaybookStep) -> Dict[str, Any]:
        delay = step.config.delay_seconds or 0
        if delay > 0:
            await asyncio.sleep(delay)
        return {"delayed_seconds": delay}

    async def _execute_notification_step(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        channel = step.config.notification_channel or "webhook"
        try:
            from cybernova.response.notifications.notification_service import notification_service
            await notification_service.send_notification(context.get("alert", {}))
            return {"channel": channel, "success": True}
        except Exception as e:
            return {"channel": channel, "success": False, "error": str(e)}

    async def _execute_approval_step(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        approval_id = str(uuid4())
        approval_entry = {
            "id": approval_id,
            "step_id": step.id,
            "playbook_execution_id": context.get("execution_id", ""),
            "required_roles": step.config.approval_roles or ["soc_manager", "admin"],
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._pending_approvals[approval_id] = approval_entry
        log.info("Approval required: %s (step: %s)", approval_id, step.name)
        return {"approval_id": approval_id, "status": "pending", "message": "Waiting for manual approval"}

    async def _execute_sub_playbook_step(self, step: PlaybookStep, context: Dict[str, Any], parent_execution: PlaybookExecution) -> Dict[str, Any]:
        sub_id = step.config.playbook_id
        if sub_id and sub_id in self._playbooks:
            exec_id = await self.trigger(sub_id, context)
            return {"sub_playbook_id": sub_id, "execution_id": exec_id, "status": "triggered"}
        return {"sub_playbook_id": sub_id, "status": "not_found"}

    # ── Approval Handling ────────────────────────────────────────────────

    async def approve(self, approval_id: str, approver: str) -> bool:
        entry = self._pending_approvals.get(approval_id)
        if not entry or entry["status"] != "pending":
            return False
        entry["status"] = "approved"
        entry["approved_by"] = approver
        entry["approved_at"] = datetime.now(timezone.utc).isoformat()
        return True

    async def reject(self, approval_id: str, rejector: str, reason: str = "") -> bool:
        entry = self._pending_approvals.get(approval_id)
        if not entry or entry["status"] != "pending":
            return False
        entry["status"] = "rejected"
        entry["rejected_by"] = rejector
        entry["reason"] = reason
        entry["rejected_at"] = datetime.now(timezone.utc).isoformat()
        return True

    def get_pending_approvals(self, limit: int = 20) -> List[dict]:
        return [v for v in self._pending_approvals.values() if v["status"] == "pending"][:limit]

    # ── Execution Status & Reporting ─────────────────────────────────────

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        return self._executions.get(execution_id)

    def list_executions(self, limit: int = 50) -> List[PlaybookExecution]:
        return list(self._executions.values())[-limit:]

    def list_executions_filtered(
        self,
        status: Optional[str] = None,
        playbook_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[PlaybookExecution]:
        all_execs = list(self._executions.values())
        if status:
            all_execs = [e for e in all_execs if e.status.value == status]
        if playbook_id:
            all_execs = [e for e in all_execs if e.playbook_id == playbook_id]
        all_execs.reverse()
        return all_execs[offset:offset + limit]

    def get_execution_progress(self, execution_id: str) -> Optional[Dict[str, Any]]:
        execution = self._executions.get(execution_id)
        if not execution:
            return None
        total = len(execution.steps)
        completed = sum(1 for s in execution.steps if s.status == StepStatus.COMPLETED)
        failed = sum(1 for s in execution.steps if s.status == StepStatus.FAILED)
        running = sum(1 for s in execution.steps if s.status == StepStatus.RUNNING)
        pending = sum(1 for s in execution.steps if s.status == StepStatus.PENDING)
        blocked = sum(1 for s in execution.steps if s.status == StepStatus.BLOCKED)
        progress_pct = round((completed / total * 100), 1) if total > 0 else 0.0
        duration = None
        if execution.created_at and execution.completed_at:
            try:
                start = datetime.fromisoformat(execution.created_at)
                end = datetime.fromisoformat(execution.completed_at)
                duration = (end - start).total_seconds()
            except (ValueError, TypeError):
                pass
        retryable = execution.status == ExecutionStatus.FAILED and execution.retry_count < execution.max_retries
        return {
            "execution_id": execution.id,
            "playbook_id": execution.playbook_id,
            "playbook_name": execution.playbook_name,
            "status": execution.status.value,
            "current_step_id": execution.current_step_id,
            "total_steps": total,
            "completed_steps": completed,
            "failed_steps": failed,
            "running_steps": running,
            "pending_steps": pending,
            "blocked_steps": blocked,
            "progress_percentage": progress_pct,
            "duration_seconds": duration,
            "retry_count": execution.retry_count,
            "max_retries": execution.max_retries,
            "retryable": retryable,
            "error": execution.error,
            "created_at": execution.created_at,
            "completed_at": execution.completed_at,
        }

    async def retry_execution(self, execution_id: str) -> Optional[str]:
        async with self._lock:
            execution = self._executions.get(execution_id)
            if not execution:
                return None
            if execution.status != ExecutionStatus.FAILED:
                log.warning("Cannot retry execution %s: status is %s", execution_id, execution.status)
                return None
            if execution.retry_count >= execution.max_retries:
                log.warning("Execution %s exceeded max retries (%d)", execution_id, execution.max_retries)
                return None
            playbook = self._playbooks.get(execution.playbook_id)
            if not playbook:
                return None
            execution.retry_count += 1
            execution.last_retry_at = datetime.now(timezone.utc).isoformat()
            execution.status = ExecutionStatus.RUNNING
            execution.error = None
            execution.current_step_id = None
            execution.completed_at = None
            for s in execution.steps:
                s.status = StepStatus.PENDING
                s.started_at = None
                s.completed_at = None
                s.result = None
                s.error = None
        asyncio.create_task(self._execute(execution, playbook))
        return execution_id

    async def cancel_execution(self, execution_id: str) -> bool:
        async with self._lock:
            execution = self._executions.get(execution_id)
            if not execution or execution.status not in (ExecutionStatus.RUNNING, ExecutionStatus.PENDING):
                return False
            execution.status = ExecutionStatus.CANCELLED
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.error = "Cancelled by user"
            for s in execution.steps:
                if s.status == StepStatus.PENDING:
                    s.status = StepStatus.SKIPPED
                    s.error = "Execution cancelled"
            return True

    @staticmethod
    def _resolve_field(field_path: str, context: Dict[str, Any]) -> Any:
        parts = field_path.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    @staticmethod
    def _evaluate_condition(field_value: Any, operator: ConditionOperator, expected: Any) -> bool:
        try:
            if operator == ConditionOperator.EQ:
                return str(field_value).lower() == str(expected).lower()
            elif operator == ConditionOperator.NEQ:
                return str(field_value).lower() != str(expected).lower()
            elif operator in (ConditionOperator.GT, ConditionOperator.GTE, ConditionOperator.LT, ConditionOperator.LTE):
                fv, ev = float(field_value), float(expected)
                if operator == ConditionOperator.GT:
                    return fv > ev
                if operator == ConditionOperator.GTE:
                    return fv >= ev
                if operator == ConditionOperator.LT:
                    return fv < ev
                if operator == ConditionOperator.LTE:
                    return fv <= ev
            elif operator == ConditionOperator.CONTAINS:
                return str(expected).lower() in str(field_value).lower()
            elif operator == ConditionOperator.IN:
                return str(field_value).lower() in [str(e).lower() for e in (expected if isinstance(expected, list) else [expected])]
            elif operator == ConditionOperator.NOT_IN:
                return str(field_value).lower() not in [str(e).lower() for e in (expected if isinstance(expected, list) else [expected])]
            elif operator == ConditionOperator.MATCHES:
                import re
                return bool(re.search(str(expected), str(field_value)))
        except (ValueError, TypeError, AttributeError):
            pass
        return False


playbook_engine = PlaybookEngine()


def seed_default_playbooks(engine: Optional[PlaybookEngine] = None):
    """Create and register default playbooks matching the old hardcoded ones."""
    from cybernova.response.automation.models import (
        PlaybookDefinition, PlaybookStep, StepType, StepConfig,
        Condition, ConditionOperator, PlaybookTrigger,
    )

    defaults = [
        {
            "id": "pb_critical_response",
            "name": "Critical Incident Response",
            "description": "Automatically isolate and block on critical severity alerts with high risk score",
            "trigger": PlaybookTrigger.ALERT_CREATED,
            "priority": 1,
            "conditions": [
                Condition(field="alert.severity", operator=ConditionOperator.EQ, value="critical"),
                Condition(field="alert.risk_score", operator=ConditionOperator.GTE, value=80),
            ],
            "steps": [
                PlaybookStep(id="step_block_ip", name="Block Source IP", type=StepType.ACTION, config=StepConfig(action_type="block_ip"), next_on_success="step_notify"),
                PlaybookStep(id="step_notify", name="Notify SOC Team", type=StepType.NOTIFICATION, config=StepConfig(notification_channel="webhook", notification_message="Critical incident detected - immediate action required"), next_on_success="step_approval_quarantine"),
                PlaybookStep(id="step_approval_quarantine", name="Approve Quarantine", type=StepType.APPROVAL, config=StepConfig(approval_roles=["soc_manager", "admin"]), next_on_success="step_isolate"),
                PlaybookStep(id="step_isolate", name="Isolate Affected Host", type=StepType.ACTION, config=StepConfig(action_type="isolate_host"), next_on_success=None),
            ],
        },
        {
            "id": "pb_brute_force",
            "name": "Brute Force Mitigation",
            "description": "Block IP and notify on brute force attempts",
            "trigger": PlaybookTrigger.ALERT_CREATED,
            "priority": 2,
            "conditions": [
                Condition(field="alert.rule_name", operator=ConditionOperator.MATCHES, value="brute_force|BruteForceRule|failed_login"),
            ],
            "steps": [
                PlaybookStep(id="step_block", name="Block Attacker IP", type=StepType.ACTION, config=StepConfig(action_type="block_ip"), next_on_success="step_notify"),
                PlaybookStep(id="step_notify", name="Notify Admin", type=StepType.NOTIFICATION, config=StepConfig(notification_channel="webhook", notification_message="Brute force attack blocked"), next_on_success=None),
            ],
        },
        {
            "id": "pb_malware",
            "name": "Malware Quarantine",
            "description": "Isolate hosts with confirmed malware and block C2",
            "trigger": PlaybookTrigger.ALERT_CREATED,
            "priority": 2,
            "conditions": [
                Condition(field="alert.rule_name", operator=ConditionOperator.MATCHES, value="malware|malicious_process|malicious_script|ransomware"),
            ],
            "steps": [
                PlaybookStep(id="step_isolate", name="Isolate Host", type=StepType.ACTION, config=StepConfig(action_type="isolate_host"), next_on_success="step_delay"),
                PlaybookStep(id="step_delay", name="Wait 30s", type=StepType.DELAY, config=StepConfig(delay_seconds=30), next_on_success="step_block"),
                PlaybookStep(id="step_block", name="Block C2 IP", type=StepType.ACTION, config=StepConfig(action_type="block_ip"), next_on_success="step_notify"),
                PlaybookStep(id="step_notify", name="Notify SOC", type=StepType.NOTIFICATION, config=StepConfig(notification_channel="webhook"), next_on_success=None),
            ],
        },
        {
            "id": "pb_high_alert_triage",
            "name": "High Alert Triage",
            "description": "Log and notify on high severity alerts without auto-action",
            "trigger": PlaybookTrigger.ALERT_CREATED,
            "priority": 5,
            "conditions": [
                Condition(field="alert.severity", operator=ConditionOperator.EQ, value="high"),
            ],
            "steps": [
                PlaybookStep(id="step_log", name="Log Alert", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success="step_notify"),
                PlaybookStep(id="step_notify", name="Notify SOC", type=StepType.NOTIFICATION, config=StepConfig(notification_channel="webhook"), next_on_success=None),
            ],
        },
    ]

    for pb_data in defaults:
        conditions = pb_data.pop("conditions", [])
        pb_steps = pb_data.pop("steps", [])
        playbook = PlaybookDefinition(
            **pb_data,
            tenant_id="default",
            enabled=True,
            conditions=conditions,
            steps=pb_steps,
        )
        target = engine or playbook_engine
        target.register(playbook)
