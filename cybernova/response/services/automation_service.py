"""
CyberNova — Automation Service (SOAR)
Decision engine: matches alerts → playbooks → creates actions → executes locally.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.config.settings import get_settings
from cybernova.core.event_bus.producer import event_producer
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.database.postgres.models import Alert, BlockedIP, Device, ResponseAction, User
from cybernova.database.repository.repositories import AlertRepository, ResponseActionRepository
from cybernova.response.policy_engine.playbooks import match_playbook
from cybernova.config.constants import ActionStatus, Topics
from cybernova.soar.engine import BlockIPAction, LogAction

log = logging.getLogger("cybernova.response.service")


class AutomationService:
    """Orchestrates the response lifecycle with local action execution."""

    def __init__(self):
        self.settings = get_settings()

    async def process_alert(self, alert_id: str, db: AsyncSession, tenant_id: str) -> List[ResponseAction]:
        """Match alerts to playbooks and create pending actions."""
        from cybernova.response.automation.engine import playbook_engine

        repo = AlertRepository(db, tenant_id)
        alert = await repo.get_by_id(alert_id)
        if not alert:
            return []

        alert_dict = {
            "id": alert.id,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "rule_name": alert.rule_name,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "user": alert.user,
            "device_id": alert.device_id,
            "description": alert.description,
        }
        context = {"alert": alert_dict, "tenant_id": tenant_id}
        execution_ids = await playbook_engine.match_and_trigger(context)
        if execution_ids:
            log.info("Playbook engine triggered %d executions for alert %s", len(execution_ids), alert_id)

        playbooks = match_playbook({
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "rule_name": alert.rule_name,
        })

        actions = []

        for pb in playbooks:
            for action_def in pb.get("actions", []):
                now = utcnow()
                action = ResponseAction(
                    id=new_id(),
                    tenant_id=tenant_id,
                    alert_id=alert.id,
                    device_id=alert.device_id,
                    action_type=action_def["type"],
                    parameters=action_def.get("params", {}),
                    status=ActionStatus.PENDING.value,
                    created_at=now,
                    updated_at=now,
                )
                db.add(action)
                actions.append(action)

        if actions:
            await db.flush()
            await event_producer.publish(topic=Topics.ACTION_CREATED, data={"action_count": len(actions)}, tenant_id=tenant_id)
            log.info("CREATE: %d actions for alert %s", len(actions), alert_id)
            await self._publish_to_stream(actions, alert, tenant_id)

        return actions

    async def _publish_to_stream(self, actions: List[ResponseAction], alert: Alert, tenant_id: str) -> None:
        """Publish actions to Redis Stream for SOAR worker consumption."""
        try:
            from cybernova.database.redis import get_redis
            redis = await get_redis()
            if not redis:
                log.warning("Redis unavailable — actions created but not published to stream")
                return

            from cybernova.streaming.producer import StreamProducer
            producer = StreamProducer(redis)
            for act in actions:
                action_dict = {
                    "id": act.id,
                    "tenant_id": tenant_id,
                    "alert_id": alert.id,
                    "device_id": act.device_id,
                    "action_type": act.action_type,
                    "parameters": act.parameters or {},
                    "payload": {
                        "alert": {
                            "id": alert.id,
                            "source_ip": alert.source_ip,
                            "dest_ip": alert.dest_ip,
                            "severity": alert.severity,
                            "rule_name": alert.rule_name,
                            "risk_score": alert.risk_score,
                            "user": alert.user,
                            "device_id": alert.device_id,
                            "description": alert.description,
                        },
                        "action_type": act.action_type,
                    },
                    "status": "pending",
                    "created_at": act.created_at.isoformat() if hasattr(act.created_at, 'isoformat') else str(act.created_at),
                }
                await producer.produce_response_action(action_dict, tenant_id)
            log.info("PUBLISHED %d actions to stream for alert %s", len(actions), alert.id)
        except Exception as e:
            log.error("Failed to publish actions to stream: %s", e)

    async def execute_action(self, action_id: str, db: AsyncSession, tenant_id: str) -> Optional[ResponseAction]:
        """Execute a pending action locally."""
        action_repo = ResponseActionRepository(db, tenant_id)
        action = await action_repo.get_by_id(action_id)
        if not action:
            return None

        if action.status != ActionStatus.PENDING.value:
            log.warning("EXECUTE SKIPPED action %s - status is '%s'", action_id, action.status)
            return action

        alert = await self._get_alert(db, tenant_id, action.alert_id)

        now = utcnow()
        action.started_at = now
        action.updated_at = now
        await db.flush()

        try:
            log.info("EXECUTING action %s of type '%s'", action.id, action.action_type)

            if action.action_type == "block_ip":
                await self._execute_block_ip(action, alert, db, tenant_id)
            elif action.action_type == "cloudflare_block_ip":
                result = await self._execute_cloudflare_block_ip(action, alert)
                action.result = result
            elif action.action_type == "opnsense_block_ip":
                result = await self._execute_opnsense_block_ip(action, alert)
                action.result = result
            elif action.action_type == "crowdstrike_isolate":
                result = await self._execute_crowdstrike_isolate(action, alert)
                action.result = result
            elif action.action_type == "sentinelone_isolate":
                result = await self._execute_sentinelone_isolate(action, alert)
                action.result = result
            elif action.action_type in ("cb_isolate", "cb_ban_hash"):
                result = await self._execute_cb_isolate(action, alert)
                action.result = result
            elif action.action_type == "isolate_host":
                await self._execute_isolate_host(action, alert, db, tenant_id)
            elif action.action_type == "disable_user":
                await self._execute_disable_user(action, alert, db, tenant_id)
            elif action.action_type in ("log_alert", "scan_host"):
                self._execute_log(action, alert)
            elif action.action_type == "pagerduty_trigger":
                result = await self._execute_pagerduty_trigger(action, alert)
                action.result = result
            elif action.action_type == "opsgenie_trigger":
                result = await self._execute_opsgenie_trigger(action, alert)
                action.result = result
            elif action.action_type == "jira_create":
                result = await self._execute_jira_create(action, alert)
                action.result = result
            elif action.action_type == "servicenow_create":
                result = await self._execute_servicenow_create(action, alert)
                action.result = result
            elif action.action_type == "email_alert":
                result = await self._execute_email_alert(action, alert)
                action.result = result
            elif action.action_type in ("notify_soc", "notify_admin"):
                await self._execute_notify(action, alert)
            else:
                await self._execute_via_soar(action, alert)

            action.status = ActionStatus.COMPLETED.value
            action.result = {"status": "completed", "action_type": action.action_type}
            log.info("COMPLETED action %s (%s)", action.id, action.action_type)

        except Exception as exc:
            action.status = ActionStatus.FAILED.value
            action.error_message = str(exc)[:400]
            log.error("FAILED action %s (%s): %s", action.id, action.action_type, exc)

        action.updated_at = utcnow()
        action.completed_at = utcnow()
        await db.flush()
        return action

    async def process_pending_alerts(self, db: AsyncSession, tenant_id: str, limit: int = 50) -> int:
        """Process pending alerts and create actions."""
        already_processed = select(ResponseAction.alert_id)
        repo = AlertRepository(db, tenant_id)
        alerts = await repo.get_unautomated(already_processed, limit=limit)
        count = 0
        for alert in alerts:
            actions = await self.process_alert(alert.id, db, tenant_id)
            count += len(actions)
        return count

    async def _execute_block_ip(self, action: ResponseAction, alert: Optional[Alert], db: AsyncSession, tenant_id: str) -> None:
        ip = alert.source_ip if alert and alert.source_ip else action.parameters.get("ip", "")
        if not ip:
            raise ValueError("No IP address to block")

        block_action = BlockIPAction()
        block_action.execute({
            "id": action.id,
            "title": "SOAR Automation Block",
            "severity": "critical",
            "source_ip": ip,
            "dest_ip": ip,
        })

        from datetime import datetime, timezone, timedelta
        expires = None
        duration = action.parameters.get("duration", 0)
        if duration:
            expires = datetime.now(timezone.utc) + timedelta(hours=int(duration))

        entry = BlockedIP(
            tenant_id=tenant_id,
            ip_address=ip,
            reason=action.parameters.get("reason", "Automated SOAR action"),
            blocked_by="system",
            expires_at=expires,
        )
        db.add(entry)
        log.warning("IP %s blocked by SOAR automation", ip)

    async def _execute_cloudflare_block_ip(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        ip = alert.source_ip if alert and alert.source_ip else action.parameters.get("ip", "")
        if not ip:
            raise ValueError("No IP address to block via Cloudflare")

        from cybernova.response.actions.cloudflare_block import execute_cloudflare_block_ip
        incident = {
            "id": action.id,
            "title": action.parameters.get("reason", "SOAR Cloudflare block"),
            "severity": alert.severity if alert else "high",
            "source_ip": ip,
            "dest_ip": ip,
        }
        result = await asyncio.to_thread(execute_cloudflare_block_ip, incident)
        if result.get("success"):
            log.warning("Cloudflare blocked IP %s via SOAR automation", ip)
        else:
            log.error("Cloudflare block failed for %s: %s", ip, result.get("error"))
        return result

    async def _execute_opnsense_block_ip(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        ip = alert.source_ip if alert and alert.source_ip else action.parameters.get("ip", "")
        if not ip:
            raise ValueError("No IP address to block via OPNsense")

        from cybernova.response.actions.opnsense_block import execute_opnsense_block_ip
        incident = {
            "id": action.id,
            "title": action.parameters.get("reason", "SOAR OPNsense block"),
            "severity": alert.severity if alert else "high",
            "source_ip": ip,
            "dest_ip": ip,
        }
        result = await asyncio.to_thread(execute_opnsense_block_ip, incident)
        if result.get("success"):
            log.warning("OPNsense blocked IP %s via SOAR automation", ip)
        else:
            log.error("OPNsense block failed for %s: %s", ip, result.get("error"))
        return result

    async def _execute_crowdstrike_isolate(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.crowdstrike_isolate import execute_crowdstrike_isolate
        device_id = action.device_id or (alert.device_id if alert else "")
        incident = {
            "id": action.id,
            "title": action.parameters.get("reason", "SOAR CrowdStrike isolate"),
            "device_id": device_id,
            "hostname": action.parameters.get("hostname", ""),
        }
        result = await asyncio.to_thread(execute_crowdstrike_isolate, incident)
        if result.get("success"):
            log.warning("CrowdStrike isolated host %s via SOAR automation", device_id)
        else:
            log.error("CrowdStrike isolate failed %s: %s", device_id, result.get("error"))
        return result

    async def _execute_sentinelone_isolate(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.sentinelone_isolate import execute_sentinelone_isolate
        agent_id = action.device_id or (alert.device_id if alert else "")
        incident = {
            "id": action.id,
            "title": action.parameters.get("reason", "SOAR SentinelOne isolate"),
            "agent_id": agent_id,
            "device_id": agent_id,
            "hostname": action.parameters.get("hostname", ""),
        }
        result = await asyncio.to_thread(execute_sentinelone_isolate, incident)
        if result.get("success"):
            log.warning("SentinelOne isolated agent %s via SOAR automation", agent_id)
        else:
            log.error("SentinelOne isolate failed %s: %s", agent_id, result.get("error"))
        return result

    async def _execute_cb_isolate(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.cb_isolate import execute_cb_isolate
        sensor_id = action.device_id or (alert.device_id if alert else "")
        incident = {
            "id": action.id,
            "title": action.parameters.get("reason", "SOAR Carbon Black isolate"),
            "sensor_id": sensor_id,
            "device_id": sensor_id,
            "hostname": action.parameters.get("hostname", ""),
            "md5_hash": action.parameters.get("md5_hash", ""),
        }
        result = await asyncio.to_thread(execute_cb_isolate, incident)
        if result.get("success"):
            log.warning("Carbon Black completed action via SOAR automation (sensor=%s)", sensor_id)
        else:
            log.error("Carbon Black action failed: %s", result.get("error"))
        return result

    async def _execute_isolate_host(self, action: ResponseAction, alert: Optional[Alert], db: AsyncSession, tenant_id: str) -> None:
        device_id = action.device_id or (alert.device_id if alert else None)
        if not device_id:
            raise ValueError("No device to isolate")

        result = await db.execute(
            select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id)
        )
        device = result.scalar_one_or_none()
        if not device:
            raise ValueError(f"Device {device_id} not found")

        device.is_isolated = True
        log.warning("Device %s isolated by SOAR automation", device.hostname)

    async def _execute_disable_user(self, action: ResponseAction, alert: Optional[Alert], db: AsyncSession, tenant_id: str) -> None:
        user_email = action.parameters.get("email", "")
        if not user_email:
            raise ValueError("No user email specified")

        result = await db.execute(
            select(User).where(User.email == user_email, User.tenant_id == tenant_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise ValueError(f"User {user_email} not found")

        user.is_disabled = True
        user.is_active = False
        log.warning("User %s disabled by SOAR automation", user_email)

    def _execute_log(self, action: ResponseAction, alert: Optional[Alert]) -> None:
        log_action = LogAction()
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
        }
        log_action.execute(incident)

    async def _execute_pagerduty_trigger(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.pagerduty_trigger import execute_pagerduty_trigger
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "user": alert.user if alert else "",
            "risk_score": alert.risk_score if alert else 0,
            "description": alert.description if alert else "",
        }
        result = await asyncio.to_thread(execute_pagerduty_trigger, incident)
        if result.get("success"):
            log.info("PagerDuty triggered for action %s", action.id)
        else:
            log.error("PagerDuty trigger failed for action %s: %s", action.id, result.get("error"))
        return result

    async def _execute_opsgenie_trigger(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.opsgenie_trigger import execute_opsgenie_trigger
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "user": alert.user if alert else "",
            "risk_score": alert.risk_score if alert else 0,
            "description": alert.description if alert else "",
        }
        result = await asyncio.to_thread(execute_opsgenie_trigger, incident)
        if result.get("success"):
            log.info("Opsgenie alert created for action %s", action.id)
        else:
            log.error("Opsgenie trigger failed for action %s: %s", action.id, result.get("error"))
        return result

    async def _execute_jira_create(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.jira_create import execute_jira_create
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "user": alert.user if alert else "",
            "risk_score": alert.risk_score if alert else 0,
            "description": alert.description if alert else "",
        }
        result = await asyncio.to_thread(execute_jira_create, incident)
        if result.get("success"):
            log.info("Jira issue created for action %s", action.id)
        else:
            log.error("Jira create failed for action %s: %s", action.id, result.get("error"))
        return result

    async def _execute_servicenow_create(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.servicenow_create import execute_servicenow_create
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "user": alert.user if alert else "",
            "risk_score": alert.risk_score if alert else 0,
            "description": alert.description if alert else "",
        }
        result = await asyncio.to_thread(execute_servicenow_create, incident)
        if result.get("success"):
            log.info("ServiceNow incident created for action %s", action.id)
        else:
            log.error("ServiceNow create failed for action %s: %s", action.id, result.get("error"))
        return result

    async def _execute_email_alert(self, action: ResponseAction, alert: Optional[Alert]) -> Dict[str, Any]:
        from cybernova.response.actions.email_alert import execute_email_alert
        to_addr = action.parameters.get("to", "")
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "user": alert.user if alert else "",
            "risk_score": alert.risk_score if alert else 0,
            "description": alert.description if alert else "",
            "to": to_addr,
        }
        result = await asyncio.to_thread(execute_email_alert, incident)
        if result.get("success"):
            log.info("Email alert sent for action %s", action.id)
        else:
            log.error("Email alert failed for action %s: %s", action.id, result.get("error"))
        return result

    async def _execute_notify(self, action: ResponseAction, alert: Optional[Alert]) -> None:
        from cybernova.response.notifications.notification_service import notification_service
        if alert:
            alert_dict = {
                "id": alert.id,
                "severity": alert.severity,
                "rule_name": alert.rule_name,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "user": alert.user,
                "risk_score": alert.risk_score,
            }
            await notification_service.send_notification(alert_dict)
        log.info("Notification sent for action %s", action.id)

    async def _execute_via_soar(self, action: ResponseAction, alert: Optional[Alert]) -> None:
        from cybernova.soar.engine import get_engine
        engine = get_engine()
        incident = {
            "id": alert.id if alert else action.id,
            "title": alert.rule_name if alert else action.action_type,
            "severity": alert.severity if alert else "info",
            "confirmed": True,
            "risk_score": alert.risk_score if alert else 0,
            "source_ip": alert.source_ip if alert else "",
            "dest_ip": alert.dest_ip if alert else "",
            "action_type": action.action_type,
        }
        engine.trigger(incident)

    @staticmethod
    async def _get_alert(db: AsyncSession, tenant_id: str, alert_id: str) -> Optional[Alert]:
        repo = AlertRepository(db, tenant_id)
        return await repo.get_by_id(alert_id)


automation_service = AutomationService()
