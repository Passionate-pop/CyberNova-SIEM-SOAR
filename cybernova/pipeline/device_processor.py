"""
CyberNova — Device Event Processor
Processes incoming device events (logs/alerts) through the pipeline.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from cybernova.database.redis import get_redis
from cybernova.streaming.streams import DEVICE_EVENTS_STREAM, STREAM_ALERTS
from cybernova.api.websocket import connection_manager, WebSocketMessage, EventType
from cybernova.policy_engine.engine import policy_engine

log = logging.getLogger("cybernova.device_processor")


class DeviceEventProcessor:
    """Process device events through pipeline."""
    
    def __init__(self):
        self._running = False
        self._redis = None
    
    async def start(self):
        """Start processing device events."""
        self._redis = await get_redis()
        self._running = True
        if self._redis:
            log.info("Device event processor starting (Redis connected)")
            asyncio.create_task(self._process_loop())
        else:
            log.warning("Device event processor started without Redis — background processing disabled")
        log.info("Device event processor running")
    
    async def stop(self):
        """Stop processing."""
        self._running = False
        log.info("Device event processor stopped")
    
    async def _process_loop(self):
        """Main event processing loop."""
        if not self._redis:
            return
        while self._running:
            try:
                events = await self._redis.xread(
                    {DEVICE_EVENTS_STREAM: "0"},
                    count=10,
                    block=5000
                )
                
                if events:
                    for stream, messages in events:
                        for msg_id, fields in messages:
                            await self._process_event(fields)
                            await self._redis.xdel(DEVICE_EVENTS_STREAM, msg_id)
                
            except Exception as e:
                log.error("Event processing error: %s", e)
                await asyncio.sleep(1)
    
    async def _process_event(self, event: Dict[str, Any]):
        """Process single event."""
        event_type = event.get("type", "log")
        tenant_id = event.get("tenant_id")
        event.get("device_id")
        
        if event_type == "alert":
            await self._handle_alert(event)
        else:
            await self._handle_log(event)
        
        if tenant_id:
            await self._broadcast(event, tenant_id)
    
    async def _handle_log(self, event: Dict[str, Any]):
        """Process log entry - detect threats."""
        message = event.get("message", "")
        event.get("level", "info")
        
        severity = "low"
        
        threat_patterns = {
            "critical": [
                "malware", "ransomware", "unauthorized access",
                "privilege escalation", "rootkit", "exploit"
            ],
            "high": [
                "failed login", "invalid password", "account locked",
                "suspicious process", "network scan"
            ],
            "medium": [
                "permission denied", "access denied", "firewall block"
            ],
        }
        
        msg_lower = message.lower()
        
        for pattern in threat_patterns["critical"]:
            if pattern in msg_lower:
                severity = "critical"
                break
        
        if severity == "low":
            for pattern in threat_patterns["high"]:
                if pattern in msg_lower:
                    severity = "high"
                    break
        
        if severity == "low":
            for pattern in threat_patterns["medium"]:
                if pattern in msg_lower:
                    severity = "medium"
                    break
        
        if severity in ["high", "critical"]:
            await self._create_alert_from_log(event, severity)
    
    async def _handle_alert(self, event: Dict[str, Any]):
        """Process alert - save to DB and evaluate policies."""
        import json
        from cybernova.database.postgres.models import Alert
        from cybernova.database.postgres.session import async_session_factory
        from cybernova.core.utils.helpers import new_id
        
        alert_message = event.get("message", "")
        device_id = event.get("device_id")
        tenant_id = event.get("tenant_id")
        severity = event.get("severity", "high")
        
        log.info("Device alert: %s", alert_message)
        
        async with async_session_factory() as db:
            try:
                alert_id = new_id()
                raw_event_for_storage = {k: v for k, v in event.items()}
                for k, v in raw_event_for_storage.items():
                    if isinstance(v, (dict, list)):
                        raw_event_for_storage[k] = json.dumps(v)
                extra_data = {
                    "source": event.get("source", "device_agent"),
                    "device_id": device_id,
                    "alert_type": event.get("alert_type", "unknown"),
                    "raw_event": raw_event_for_storage,
                }
                db_alert = Alert(
                    id=alert_id,
                    tenant_id=tenant_id,
                    device_id=device_id,
                    rule_name=event.get("alert_type", "device_alert"),
                    severity=severity,
                    risk_score=event.get("risk_score", 50.0),
                    description=alert_message,
                    status="new",
                    extra_data=extra_data,
                )
                db.add(db_alert)
                await db.commit()
                log.info("Saved device alert to DB: %s [%s]", alert_id, severity)
                
                if severity in ("critical", "high"):
                    alert_with_id = {
                        **event,
                        "alert_id": alert_id,
                        "device_id": device_id,
                        "tenant_id": tenant_id,
                    }
                    await policy_engine.evaluate(alert_with_id, tenant_id, db)
                    
            except Exception as e:
                log.error("Failed to save device alert: %s", e)
                await db.rollback()
    
    async def _create_alert_from_log(self, event: Dict[str, Any], severity: str):
        """Create alert from suspicious log."""
        alert = {
            "alert_id": f"device_{datetime.now(timezone.utc).timestamp()}",
            "type": "device_detection",
            "severity": severity,
            "source_ip": event.get("ip", ""),
            "destination_ip": "",
            "description": event.get("message", "Suspicious activity detected"),
            "rule_id": "DEVICE_THREAT",
            "affected_system": event.get("hostname", "unknown"),
            "device_id": event.get("device_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": event.get("tenant_id", ""),
        }
        
        if self._redis:
            await self._redis.xadd(STREAM_ALERTS, alert)
        log.info("Created alert: %s - %s", severity, alert.get('description', ''))
        
        from cybernova.database.postgres.session import async_session_factory
        try:
            async with async_session_factory() as db:
                if event.get("tenant_id"):
                    await policy_engine.evaluate(alert, event.get("tenant_id"), db)
        except Exception as e:
            log.warning("Policy evaluation failed: %s", e)
    
    async def _broadcast(self, event: Dict[str, Any], tenant_id: str):
        """Broadcast to WebSocket connections."""
        event_type = EventType.NEW_ALERT if event.get("type") == "alert" else EventType.PIPELINE_STATUS
        
        msg = WebSocketMessage(
            event_type=event_type,
            data=event,
            tenant_id=tenant_id
        )
        
        await connection_manager.send_to_tenant(tenant_id, msg)


class DeviceEventHandler:
    """Handler for direct device event submission."""
    
    def __init__(self):
        self._redis = None
    
    async def _get_redis(self):
        if not self._redis:
            self._redis = await get_redis()
        return self._redis
    
    async def submit_logs(self, device_id: str, tenant_id: str, logs: List[Dict[str, Any]]):
        """Submit logs from device."""
        import json
        redis = await self._get_redis()
        
        for entry in logs:
            entry.update({
                "type": "log",
                "device_id": device_id,
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            flat_entry = {}
            for k, v in entry.items():
                if isinstance(v, (dict, list)):
                    flat_entry[k] = json.dumps(v)
                else:
                    flat_entry[k] = v
            await redis.xadd(DEVICE_EVENTS_STREAM, flat_entry)
        
        log.info("Queued %d logs from %s", len(logs), device_id)
    
    async def submit_alerts(self, device_id: str, tenant_id: str, alerts: List[Dict[str, Any]]):
        """Submit alerts from device."""
        import json
        redis = await self._get_redis()
        
        for entry in alerts:
            entry.update({
                "type": "alert",
                "device_id": device_id,
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            flat_entry = {}
            for k, v in entry.items():
                if isinstance(v, (dict, list)):
                    flat_entry[k] = json.dumps(v)
                else:
                    flat_entry[k] = v
            await redis.xadd(DEVICE_EVENTS_STREAM, flat_entry)
        
        log.info("Queued %d alerts from %s", len(alerts), device_id)
    
    async def update_device_status(self, device_id: str, status: str, tenant_id: str):
        """Update device status and broadcast."""
        redis = await self._get_redis()
        
        status_event = {
            "type": "device_status",
            "device_id": device_id,
            "tenant_id": tenant_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        await redis.xadd(DEVICE_EVENTS_STREAM, status_event)
        
        msg = WebSocketMessage(
            event_type=EventType.SYSTEM_NOTIFICATION,
            data=status_event,
            tenant_id=tenant_id
        )
        await connection_manager.send_to_tenant(tenant_id, msg)


device_event_processor = DeviceEventProcessor()
device_event_handler = DeviceEventHandler()