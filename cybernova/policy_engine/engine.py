"""
CyberNova — Policy Engine
Evaluates policies and executes actions on events.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Device
from cybernova.database.postgres.policy_models import Policy, PolicyExecutionLog
from cybernova.api.websocket import connection_manager, WebSocketMessage, EventType
from cybernova.audit.service import audit_service

log = logging.getLogger("cybernova.policy_engine")


class PolicyEngine:
    """Evaluate policies and execute actions on events."""
    
    def __init__(self):
        self._cooldown_cache: Dict[str, datetime] = {}
    
    async def evaluate(
        self,
        event: Dict[str, Any],
        tenant_id: str,
        db: AsyncSession
    ):
        """Evaluate all enabled policies for an event."""
        if not tenant_id:
            return
        
        query = select(Policy).where(
            Policy.tenant_id == tenant_id,
            Policy.enabled
        )
        result = await db.execute(query)
        policies = result.scalars().all()
        
        for policy in policies:
            try:
                if self._matches_conditions(policy.conditions, event):
                    await self._execute_policy(policy, event, tenant_id, db)
            except Exception as e:
                log.error(f"Policy {policy.id} failed: {e}")
    
    def _matches_conditions(
        self,
        conditions: Dict[str, Any],
        event: Dict[str, Any]
    ) -> bool:
        """Check if event matches policy conditions."""
        
        severity = conditions.get("severity")
        if severity and event.get("severity") != severity:
            return False
        
        event_type = conditions.get("event_type")
        if event_type and event.get("type") != event_type:
            return False
        
        source = conditions.get("source")
        if source and event.get("source") != source:
            return False
        
        device_id = conditions.get("device_id")
        if device_id and event.get("device_id") != device_id:
            return False
        
        description_pattern = conditions.get("description_contains")
        if description_pattern:
            desc = event.get("description", "").lower()
            pattern = description_pattern.lower()
            if pattern not in desc:
                return False
        
        return True
    
    async def _execute_policy(
        self,
        policy: Policy,
        event: Dict[str, Any],
        tenant_id: str,
        db: AsyncSession
    ):
        """Execute all actions for a matching policy."""
        
        device_id = event.get("device_id")
        
        if device_id:
            cooldown_key = f"{policy.id}:{device_id}"
            
            if cooldown_key in self._cooldown_cache:
                last_executed = self._cooldown_cache[cooldown_key]
                cooldown = timedelta(seconds=policy.cooldown_seconds)
                if datetime.now(timezone.utc) - last_executed < cooldown:
                    log.info(f"Policy {policy.id} in cooldown for {device_id}")
                    return
            
            self._cooldown_cache[cooldown_key] = datetime.now(timezone.utc)
        
        actions = policy.actions or []
        
        for action in actions:
            try:
                await self._execute_action(action, policy, event, tenant_id, db)
            except Exception as e:
                log.error(f"Action {action} failed: {e}")
                await self._log_execution(
                    policy.id, tenant_id, device_id, action, "failed", str(e), db
                )
    
    async def _execute_action(
        self,
        action: str,
        policy: Policy,
        event: Dict[str, Any],
        tenant_id: str,
        db: AsyncSession
    ):
        """Execute a single action."""
        
        if action == "isolate_device":
            await self._action_isolate_device(event, policy, tenant_id, db)
        elif action == "notify_admin":
            await self._action_notify_admin(event, policy, tenant_id)
        elif action == "create_incident":
            await self._action_create_incident(event, policy, tenant_id, db)
        else:
            log.warning(f"Unknown action: {action}")
        
        await self._log_execution(
            policy.id, tenant_id, event.get("device_id"), action, "success", "", db
        )
    
    async def _action_isolate_device(
        self,
        event: Dict[str, Any],
        policy: Policy,
        tenant_id: str,
        db: AsyncSession
    ):
        """Isolate a device."""
        device_id = event.get("device_id")
        if not device_id:
            return
        
        query = select(Device).where(
            Device.id == device_id,
            Device.tenant_id == tenant_id
        )
        result = await db.execute(query)
        device = result.scalar_one_or_none()
        
        if device and device.status != "isolated":
            device.status = "isolated"
            await db.commit()
            log.warning(f"Device {device_id} auto-isolated by policy {policy.id}")
            
            await audit_service.log(
                db=db,
                action="device_auto_isolated",
                tenant_id=tenant_id,
                user_id="system",
                resource_type="device",
                resource_id=device_id,
                details={"policy_id": policy.id},
            )
    
    async def _action_notify_admin(
        self,
        event: Dict[str, Any],
        policy: Policy,
        tenant_id: str
    ):
        """Notify admins via WebSocket."""
        notification = {
            "type": "policy_notification",
            "title": "Security Alert",
            "message": event.get("description", "Security event detected"),
            "severity": event.get("severity", "high"),
            "device_id": event.get("device_id"),
            "policy": policy.name,
        }
        
        msg = WebSocketMessage(
            event_type=EventType.SYSTEM_NOTIFICATION,
            data=notification,
            tenant_id=tenant_id
        )
        
        await connection_manager.send_to_tenant(tenant_id, msg)
        log.info(f"Admin notified for event {event.get('alert_id')}")
    
    async def _action_create_incident(
        self,
        event: Dict[str, Any],
        policy: Policy,
        tenant_id: str,
        db: AsyncSession
    ):
        """Create incident from event."""
        log.info(f"Would create incident for {event.get('alert_id')}")
    
    async def _log_execution(
        self,
        policy_id: str,
        tenant_id: str,
        device_id: Optional[str],
        action: str,
        status: str,
        details: str,
        db: AsyncSession
    ):
        """Log policy execution."""
        log_entry = PolicyExecutionLog(
            policy_id=policy_id,
            tenant_id=tenant_id,
            device_id=device_id,
            action=action,
            status=status,
            details={"error": details} if details else {}
        )
        db.add(log_entry)
        await db.commit()


class PolicyManager:
    """Manage policies via API."""
    
    async def get_policies(self, tenant_id: str, db: AsyncSession) -> List[Policy]:
        query = select(Policy).where(Policy.tenant_id == tenant_id).order_by(Policy.created_at.desc())
        result = await db.execute(query)
        return list(result.scalars().all())
    
    async def create_policy(
        self,
        tenant_id: str,
        name: str,
        conditions: Dict[str, Any],
        actions: List[str],
        created_by: str,
        db: AsyncSession,
        description: str = "",
        cooldown_seconds: int = 300,
    ) -> Policy:
        policy = Policy(
            tenant_id=tenant_id,
            name=name,
            description=description,
            conditions=conditions,
            actions=actions,
            cooldown_seconds=cooldown_seconds,
            created_by=created_by,
        )
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
        return policy
    
    async def toggle_policy(
        self,
        policy_id: str,
        tenant_id: str,
        enabled: bool,
        db: AsyncSession,
    ) -> Policy:
        query = select(Policy).where(
            Policy.id == policy_id,
            Policy.tenant_id == tenant_id
        )
        result = await db.execute(query)
        policy = result.scalar_one_or_none()
        
        if policy:
            policy.enabled = enabled
            await db.commit()
        
        return policy
    
    async def get_default_policies(self, tenant_id: str, db: AsyncSession) -> List[Policy]:
        """Create default policies for new tenants."""
        defaults = [
            {
                "name": "Auto-Isolate Critical Malware",
                "description": "Automatically isolate devices with critical severity alerts",
                "conditions": {"severity": "critical"},
                "actions": ["isolate_device", "notify_admin"],
                "cooldown": 600,
            },
            {
                "name": "High Severity Alert Notification", 
                "description": "Notify admins when high severity alerts are detected",
                "conditions": {"severity": "high"},
                "actions": ["notify_admin"],
                "cooldown": 300,
            },
        ]
        
        created = []
        for cfg in defaults:
            policy = await self.create_policy(
                tenant_id=tenant_id,
                name=cfg["name"],
                description=cfg["description"],
                conditions=cfg["conditions"],
                actions=cfg["actions"],
                created_by="system",
                cooldown_seconds=cfg["cooldown"],
                db=db
            )
            created.append(policy)
        
        return created


policy_engine = PolicyEngine()
policy_manager = PolicyManager()