"""
CyberNova — SOAR Execution Engine
Tracked response actions with retry and execution logging.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cybernova.core.utils.helpers import utcnow
from cybernova.soar.engine import (
    BlockIPAction, LogAction, IsolateAction, NotifyAction, ForensicsAction,
    KillProcessAction, DisableUserAction, EnableUserAction,
    CreateTicketAction, SendNotificationAction, QuarantineFileAction, ResetMFAAction,
)

log = logging.getLogger("cybernova.response.execution")


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTERED = "dead_lettered"
    CANCELLED = "cancelled"


@dataclass
class ActionExecution:
    action_id: str
    alert_id: Optional[str]
    playbook_id: Optional[str]
    action_type: str
    payload: Dict[str, Any]
    status: ExecutionStatus = ExecutionStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    last_error: Optional[str] = None
    execution_logs: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None

    def add_log(self, message: str, level: str = "info", data: Optional[Dict[str, Any]] = None) -> None:
        self.execution_logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            "data": data or {},
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "alert_id": self.alert_id,
            "playbook_id": self.playbook_id,
            "action_type": self.action_type,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "last_error": self.last_error,
            "execution_logs": self.execution_logs,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "next_retry_at": self.next_retry_at.isoformat() if self.next_retry_at else None,
        }


RETRY_DELAYS = [30, 60, 120]


class ResponseExecutor:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def execute_action(self, execution: ActionExecution) -> bool:
        execution.started_at = utcnow()
        execution.status = ExecutionStatus.RUNNING
        execution.add_log("Starting execution", level="info")

        try:
            execution.add_log(f"Executing action type: {execution.action_type}", level="info")

            if execution.action_type == "block_ip":
                success = await self._execute_block_ip(execution)
            elif execution.action_type == "isolate_host":
                success = await self._execute_isolate_host(execution)
            elif execution.action_type in ("log_alert", "scan_host"):
                success = self._execute_log(execution)
            elif execution.action_type in ("notify_soc", "notify_admin"):
                success = await self._execute_notify(execution)
            elif execution.action_type == "collect_forensics":
                success = await self._execute_forensics(execution)
            elif execution.action_type == "kill_process":
                success = await self._execute_kill_process(execution)
            elif execution.action_type == "disable_user":
                success = await self._execute_disable_user(execution)
            elif execution.action_type == "enable_user":
                success = await self._execute_enable_user(execution)
            elif execution.action_type == "create_ticket":
                success = self._execute_create_ticket(execution)
            elif execution.action_type == "send_notification":
                success = await self._execute_send_notification(execution)
            elif execution.action_type == "quarantine_file":
                success = self._execute_quarantine_file(execution)
            elif execution.action_type == "reset_mfa":
                success = self._execute_reset_mfa(execution)
            else:
                success = self._execute_via_soar(execution)

            if success:
                await self._record_success(execution)
            else:
                raise Exception(f"Action {execution.action_type} returned failure")

            return True

        except Exception as exc:
            execution.last_error = str(exc)
            execution.add_log(f"Execution failed: {exc}", level="error")
            execution.completed_at = utcnow()
            await self._persist_execution(execution)
            return False

    async def _execute_block_ip(self, execution: ActionExecution) -> bool:
        ip = execution.payload.get("source_ip", execution.payload.get("ip", ""))
        if not ip:
            execution.add_log("No IP address provided", level="error")
            return False

        execution.add_log(f"Blocking IP: {ip}", level="info")
        action = BlockIPAction()
        incident = {
            "id": execution.action_id,
            "source_ip": ip,
            "dest_ip": ip,
            "severity": "critical",
        }
        return action.execute(incident)

    async def _execute_isolate_host(self, execution: ActionExecution) -> bool:
        ip = execution.payload.get("source_ip", execution.payload.get("ip", ""))
        hostname = execution.payload.get("hostname", execution.payload.get("device_id", ""))
        execution.add_log(f"Isolating host: {hostname or ip}", level="warning")
        action = IsolateAction()
        incident = {
            "id": execution.action_id,
            "source_ip": ip,
            "dest_ip": ip,
            "hostname": hostname,
            "severity": "critical",
        }
        return action.execute(incident)

    def _execute_log(self, execution: ActionExecution) -> bool:
        action = LogAction()
        incident = {
            "id": execution.action_id,
            "title": execution.action_type,
            "severity": "info",
        }
        return action.execute(incident)

    async def _execute_notify(self, execution: ActionExecution) -> bool:
        ip = execution.payload.get("source_ip", execution.payload.get("ip", ""))
        execution.add_log(f"Notifying SOC about incident involving {ip}", level="warning")
        action = NotifyAction()
        incident = {
            "id": execution.action_id,
            "title": execution.action_type,
            "severity": "critical",
            "source_ip": ip,
        }
        result = action.execute(incident)
        execution.add_log(f"SOC notification {'sent' if result else 'failed'}", level="info")
        return result

    async def _execute_forensics(self, execution: ActionExecution) -> bool:
        ip = execution.payload.get("source_ip", execution.payload.get("ip", ""))
        hostname = execution.payload.get("hostname", execution.payload.get("device_id", ""))
        execution.add_log(f"Collecting forensics from {hostname or ip}", level="warning")
        action = ForensicsAction()
        incident = {
            "id": execution.action_id,
            "title": execution.action_type,
            "severity": "critical",
            "source_ip": ip,
            "hostname": hostname,
        }
        result = action.execute(incident)
        execution.add_log(f"Forensics collection {'initiated' if result else 'failed'}", level="info")
        return result

    async def _execute_kill_process(self, execution: ActionExecution) -> bool:
        pid = execution.payload.get("pid")
        process_name = execution.payload.get("process_name", "")
        device_id = execution.payload.get("device_id", "")
        hostname = execution.payload.get("hostname", "")
        execution.add_log(f"Killing process: pid={pid} name={process_name} host={hostname or device_id}", level="warning")
        action = KillProcessAction()
        incident = {
            "id": execution.action_id,
            "pid": pid,
            "process_name": process_name,
            "hostname": hostname or device_id,
            "device_id": device_id,
            "severity": "critical",
        }
        return action.execute(incident)

    async def _execute_disable_user(self, execution: ActionExecution) -> bool:
        username = execution.payload.get("username", execution.payload.get("user", ""))
        email = execution.payload.get("email", "")
        execution.add_log(f"Disabling user: {username} ({email})", level="warning")
        action = DisableUserAction()
        incident = {
            "id": execution.action_id,
            "username": username,
            "email": email,
            "severity": "critical",
        }
        return action.execute(incident)

    async def _execute_enable_user(self, execution: ActionExecution) -> bool:
        username = execution.payload.get("username", execution.payload.get("user", ""))
        email = execution.payload.get("email", "")
        execution.add_log(f"Enabling user: {username} ({email})", level="info")
        action = EnableUserAction()
        incident = {
            "id": execution.action_id,
            "username": username,
            "email": email,
            "severity": "info",
        }
        return action.execute(incident)

    def _execute_create_ticket(self, execution: ActionExecution) -> bool:
        execution.add_log(f"Creating ticket: {execution.payload.get('title', '')}", level="info")
        action = CreateTicketAction()
        incident = {
            "id": execution.action_id,
            "title": execution.payload.get("title", ""),
            "severity": execution.payload.get("severity", "medium"),
        }
        return action.execute(incident)

    async def _execute_send_notification(self, execution: ActionExecution) -> bool:
        channel = execution.payload.get("channel", "webhook")
        execution.add_log(f"Sending notification via {channel}: {execution.payload.get('title', '')}", level="info")
        action = SendNotificationAction(channel=channel)
        incident = {
            "id": execution.action_id,
            "title": execution.payload.get("title", ""),
            "severity": execution.payload.get("severity", "info"),
        }
        return action.execute(incident)

    def _execute_quarantine_file(self, execution: ActionExecution) -> bool:
        file_path = execution.payload.get("file_path", "")
        sha256 = execution.payload.get("sha256", "")
        hostname = execution.payload.get("hostname", "")
        execution.add_log(f"Quarantining file: {file_path} on {hostname}", level="warning")
        action = QuarantineFileAction()
        incident = {
            "id": execution.action_id,
            "file_path": file_path,
            "sha256": sha256,
            "hostname": hostname,
            "severity": "critical",
        }
        return action.execute(incident)

    async def _execute_reset_mfa(self, execution: ActionExecution) -> bool:
        username = execution.payload.get("username", execution.payload.get("user", ""))
        email = execution.payload.get("email", "")
        execution.add_log(f"Resetting MFA for user: {username} ({email})", level="warning")
        action = ResetMFAAction()
        incident = {
            "id": execution.action_id,
            "username": username,
            "email": email,
            "severity": "critical",
        }
        return action.execute(incident)

    def _execute_via_soar(self, execution: ActionExecution) -> bool:
        from cybernova.soar.engine import get_engine
        engine = get_engine()
        incident = {
            "id": execution.action_id,
            "title": execution.action_type,
            "severity": "critical",
            "confirmed": True,
            "risk_score": 120,
        }
        return engine.trigger(incident)

    async def _record_success(self, execution: ActionExecution) -> None:
        execution.status = ExecutionStatus.SUCCESS
        execution.completed_at = utcnow()
        execution.add_log("Execution successful", level="info")
        await self._persist_execution(execution)

    async def schedule_retry(self, execution: ActionExecution) -> None:
        if execution.retry_count >= execution.max_retries:
            execution.status = ExecutionStatus.DEAD_LETTERED
            execution.completed_at = utcnow()
            execution.add_log("Max retries reached — dead-lettered", level="error")
            log.warning("Action %s dead-lettered after %d retries", execution.action_id, execution.retry_count)
        else:
            delay = RETRY_DELAYS[min(execution.retry_count, len(RETRY_DELAYS) - 1)]
            execution.next_retry_at = datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + delay,
                tz=timezone.utc,
            )
            execution.status = ExecutionStatus.RETRYING
            execution.add_log(f"Scheduled retry #{execution.retry_count + 1} in {delay}s", level="warning")

        await self._persist_execution(execution)

    async def _persist_execution(self, execution: ActionExecution) -> None:
        try:
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import ResponseAction

            async for db in get_db_session():
                result = await db.execute(
                    __import__("sqlalchemy").select(ResponseAction).where(ResponseAction.id == execution.action_id)
                )
                db_action = result.scalar_one_or_none()
                if db_action:
                    db_action.status = execution.status.value
                    db_action.result = json.dumps(execution.to_dict())
                    db_action.error_message = execution.last_error
                    db_action.retry_count = execution.retry_count
                    db_action.started_at = execution.started_at
                    db_action.completed_at = execution.completed_at
                await db.commit()
        except Exception as exc:
            log.warning("Could not persist execution state: %s", exc)

    async def get_pending(self, limit: int = 50) -> List[ActionExecution]:
        try:
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import ResponseAction
            from sqlalchemy import select

            async for db in get_db_session():
                result = await db.execute(
                    select(ResponseAction)
                    .where(ResponseAction.status.in_(["pending", "retrying"]))
                    .limit(limit)
                )
                rows = result.scalars().all()
                executions = []
                for row in rows:
                    executions.append(ActionExecution(
                        action_id=row.id,
                        alert_id=row.alert_id,
                        playbook_id=row.incident_id,
                        action_type=row.action_type,
                        payload=row.parameters or {},
                        status=ExecutionStatus(row.status),
                        retry_count=row.retry_count,
                        max_retries=row.max_retries,
                        last_error=row.error_message,
                        created_at=row.created_at,
                    ))
                return executions
        except Exception as exc:
            log.error("Failed to get pending actions: %s", exc)
            return []

    async def get_execution_history(self, alert_id: str, limit: int = 100) -> List[ActionExecution]:
        try:
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import ResponseAction
            from sqlalchemy import select

            async for db in get_db_session():
                result = await db.execute(
                    select(ResponseAction)
                    .where(ResponseAction.alert_id == alert_id)
                    .limit(limit)
                )
                rows = result.scalars().all()
                return [
                    ActionExecution(
                        action_id=row.id,
                        alert_id=row.alert_id,
                        playbook_id=row.incident_id,
                        action_type=row.action_type,
                        payload=row.parameters or {},
                        status=ExecutionStatus(row.status),
                        retry_count=row.retry_count,
                        max_retries=row.max_retries,
                        last_error=row.error_message,
                        created_at=row.created_at,
                    )
                    for row in rows
                ]
        except Exception as exc:
            log.error("Failed to get execution history: %s", exc)
            return []


response_executor = ResponseExecutor()

# Alias for unified API access
execution_engine = response_executor

