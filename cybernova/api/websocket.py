"""
WebSocket manager for real-time frontend updates.
Per-tenant/IP limits, rate limiting, graceful shutdown.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Dict, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger("cybernova.websocket")

WS_SEND_TIMEOUT = 10.0
WS_MAX_PER_TENANT = 500
WS_MAX_PER_IP = 50
WS_MSG_RATE_LIMIT = 100  # max messages per second per connection
WS_HEARTBEAT_INTERVAL = 30


class EventType(Enum):
    NEW_ALERT = "new_alert"
    ALERT_UPDATED = "alert_updated"
    NEW_INCIDENT = "new_incident"
    INCIDENT_UPDATED = "incident_updated"
    SOAR_ACTION = "soar_action"
    PIPELINE_STATUS = "pipeline_status"
    SYSTEM_NOTIFICATION = "system_notification"
    DASHBOARD_SNAPSHOT = "dashboard_snapshot"


@dataclass
class WebSocketMessage:
    event_type: EventType
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tenant_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "type": self.event_type.value,
            "event_type": self.event_type.value,
            "data": self.data,
            "timestamp": self.timestamp,
            "tenant_id": self.tenant_id,
        })


class _RateLimiter:
    """Simple sliding-window rate limiter per WebSocket."""
    def __init__(self, max_per_second: int = WS_MSG_RATE_LIMIT):
        self.max_per_second = max_per_second
        self._window: float = 1.0
        self._timestamps: list[float] = []

    def check(self) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_per_second:
            return False
        self._timestamps.append(now)
        return True


class ConnectionManager:
    """
    Manages WebSocket connections with tenant isolation, resource limits, and rate limiting.
    """

    def __init__(self):
        self._connections: Dict[str, Set[WebSocket]] = {}
        self._ws_to_tenant: Dict[WebSocket, str] = {}
        self._ws_to_ip: Dict[WebSocket, str] = {}
        self._filters: Dict[WebSocket, Set[EventType]] = {}
        self._last_ping: Dict[WebSocket, float] = {}
        self._rate_limiters: Dict[WebSocket, _RateLimiter] = {}
        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()

    async def connect(
        self,
        websocket: WebSocket,
        tenant_id: str,
        client_ip: str = "",
        event_types: Optional[Set[EventType]] = None,
        subprotocol: Optional[str] = None,
    ) -> bool:
        """Accept a new WebSocket connection. Returns False if limits exceeded."""
        kwargs = {}
        if subprotocol:
            kwargs["subprotocol"] = subprotocol
        await websocket.accept(**kwargs)

        async with self._lock:
            # Per-tenant limit
            tenant_count = len(self._connections.get(tenant_id, set()))
            if tenant_count >= WS_MAX_PER_TENANT:
                log.warning("WS limit: tenant %s has %d connections (max %d)",
                            tenant_id, tenant_count, WS_MAX_PER_TENANT)
                await websocket.close(code=1013, reason="Too many connections for tenant")
                return False

            # Per-IP limit
            if client_ip:
                ip_count = sum(
                    1 for ip in self._ws_to_ip.values() if ip == client_ip
                )
                if ip_count >= WS_MAX_PER_IP:
                    log.warning("WS limit: IP %s has %d connections (max %d)",
                                client_ip, ip_count, WS_MAX_PER_IP)
                    await websocket.close(code=1013, reason="Too many connections from this IP")
                    return False

            if tenant_id not in self._connections:
                self._connections[tenant_id] = set()
            self._connections[tenant_id].add(websocket)
            self._ws_to_tenant[websocket] = tenant_id
            self._ws_to_ip[websocket] = client_ip
            self._filters[websocket] = event_types or set(EventType)
            self._last_ping[websocket] = time.monotonic()
            self._rate_limiters[websocket] = _RateLimiter()

        log.info("WS connect: tenant=%s ip=%s total=%d",
                 tenant_id, client_ip or "?", self.get_connection_count())
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            tenant_id = self._ws_to_tenant.pop(websocket, None)
            if tenant_id and websocket in self._connections.get(tenant_id, set()):
                self._connections[tenant_id].remove(websocket)
                if not self._connections[tenant_id]:
                    del self._connections[tenant_id]
            self._ws_to_ip.pop(websocket, None)
            self._filters.pop(websocket, None)
            self._last_ping.pop(websocket, None)
            self._rate_limiters.pop(websocket, None)

    async def send_to_tenant(
        self,
        tenant_id: str,
        message: WebSocketMessage,
        filter_types: Optional[Set[EventType]] = None,
    ) -> int:
        if message.event_type not in (filter_types or set(EventType)):
            return 0

        async with self._lock:
            connections = list(self._connections.get(tenant_id, set()))
            filters_copy = {ws: self._filters.get(ws, set()) for ws in connections}
            rate_limiters_copy = {ws: self._rate_limiters.get(ws) for ws in connections}

        if not connections:
            return 0

        async def _send_one(ws: WebSocket) -> bool:
            if filters_copy.get(ws) and message.event_type not in filters_copy[ws]:
                return False
            rl = rate_limiters_copy.get(ws)
            if rl and not rl.check():
                log.debug("WS rate limit hit for %s, dropping message", tenant_id)
                return False
            await asyncio.wait_for(
                ws.send_text(message.to_json()),
                timeout=WS_SEND_TIMEOUT,
            )
            return True

        results = await asyncio.gather(*[_send_one(ws) for ws in connections], return_exceptions=True)
        sent = sum(1 for r in results if r is True)

        dead = []
        for ws, result in zip(connections, results):
            if isinstance(result, Exception) and ws in self._ws_to_tenant:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._ws_to_tenant:
                        await self._disconnect_unsafe(ws)
        return sent

    async def _disconnect_unsafe(self, websocket: WebSocket) -> None:
        tenant_id = self._ws_to_tenant.pop(websocket, None)
        if tenant_id and websocket in self._connections.get(tenant_id, set()):
            self._connections[tenant_id].remove(websocket)
            if not self._connections[tenant_id]:
                del self._connections[tenant_id]
        self._ws_to_ip.pop(websocket, None)
        self._filters.pop(websocket, None)
        self._last_ping.pop(websocket, None)
        self._rate_limiters.pop(websocket, None)

    async def broadcast(
        self,
        message: WebSocketMessage,
        filter_types: Optional[Set[EventType]] = None,
    ) -> int:
        async with self._lock:
            tenant_ids = list(self._connections.keys())
        total = 0
        for tid in tenant_ids:
            total += await self.send_to_tenant(tid, message, filter_types)
        return total

    async def send_personal(
        self,
        websocket: WebSocket,
        message: WebSocketMessage,
    ) -> bool:
        try:
            await asyncio.wait_for(
                websocket.send_text(message.to_json()),
                timeout=WS_SEND_TIMEOUT,
            )
            return True
        except Exception as e:
            log.debug("WS send_personal failed: %s", e)
            return False

    async def ping_all(self) -> None:
        async with self._lock:
            all_connections = list(self._ws_to_tenant.keys())
        now = time.monotonic()
        ping_payload = json.dumps({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
        dead = []

        async def _ping_one(ws: WebSocket) -> bool:
            try:
                await asyncio.wait_for(ws.send_text(ping_payload), timeout=5.0)
                async with self._lock:
                    self._last_ping[ws] = now
                return True
            except Exception as e:
                log.debug("WS ping failed: %s", e)
                return False

        results = await asyncio.gather(*[_ping_one(ws) for ws in all_connections], return_exceptions=True)
        for ws, ok in zip(all_connections, results):
            if ok is not True:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._ws_to_tenant:
                        await self._disconnect_unsafe(ws)

    def check_rate_limit(self, websocket: WebSocket) -> bool:
        rl = self._rate_limiters.get(websocket)
        return rl is None or rl.check()

    def get_connection_count(self) -> int:
        return sum(len(conns) for conns in self._connections.values())

    def get_tenant_count(self) -> int:
        return len(self._connections)

    def get_tenant_ids(self) -> list:
        return list(self._connections.keys())


connection_manager = ConnectionManager()


class WebSocketHandler:
    """
    WebSocket handler with JWT auth, heartbeat, rate limiting, and tenant isolation.
    """

    def __init__(self):
        self._manager = connection_manager
        self._redis = None

    async def initialize(self) -> None:
        from cybernova.database.redis import get_redis
        self._redis = await get_redis()

    async def handle_connection(
        self,
        websocket: WebSocket,
        token: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        client_ip = websocket.client.host if websocket.client else ""
        heartbeat_task: Optional[asyncio.Task] = None

        try:
            if not token:
                await websocket.close(code=4001, reason="Authentication required (JWT token missing)")
                return

            payload = await self._validate_jwt_token(token)
            if not payload:
                await websocket.close(code=4001, reason="Authentication failed (invalid or expired JWT)")
                return

            jwt_tenant = payload.get("tenant_id") or (
                payload.get("sub", "").split("@")[0] if payload.get("sub") else None
            )
            if tenant_id and jwt_tenant and tenant_id != jwt_tenant:
                await websocket.close(code=4001, reason="Tenant mismatch between JWT and query parameter")
                return

            tenant_id = tenant_id or jwt_tenant
            if not tenant_id:
                await websocket.close(code=4001, reason="Authentication required (no tenant in JWT)")
                return

            accepted = await self._manager.connect(websocket, tenant_id, client_ip=client_ip, subprotocol=token)
            if not accepted:
                return

            await websocket.send_json({
                "type": "connected",
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "features": ["alerts", "incidents", "soar", "pipeline"],
            })

            heartbeat_task = asyncio.create_task(self._heartbeat_loop(websocket))

            async for raw_message in websocket.iter_text():
                if not self._manager.check_rate_limit(websocket):
                    await websocket.send_json({"type": "error", "message": "Rate limit exceeded"})
                    continue
                await self._handle_message(websocket, raw_message, tenant_id)

        except WebSocketDisconnect:
            pass
        except Exception as e:
            log.error("WS error: %s", e)
        finally:
            if heartbeat_task is not None and not heartbeat_task.done():
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self._manager.disconnect(websocket)

    async def _handle_message(
        self,
        websocket: WebSocket,
        raw_message: str,
        tenant_id: str,
    ) -> None:
        try:
            message = json.loads(raw_message)
            msg_type = message.get("type")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})

            elif msg_type == "subscribe":
                event_types = {EventType(et) for et in message.get("events", []) if et in [e.value for e in EventType]}
                connection_manager._filters[websocket] = event_types
                await websocket.send_json({"type": "subscribed", "events": [e.value for e in event_types]})

            elif msg_type == "unsubscribe":
                event_types = {EventType(et) for et in message.get("events", [])}
                current = connection_manager._filters.get(websocket, set())
                connection_manager._filters[websocket] = current - event_types
                await websocket.send_json({"type": "unsubscribed", "events": [e.value for e in event_types]})

            elif msg_type == "get_status":
                from cybernova.pipeline.unified_pipeline import unified_pipeline
                status = await unified_pipeline.get_metrics()
                await websocket.send_json({"type": "status", "data": status})

            elif msg_type == "ack":
                pass

        except json.JSONDecodeError:
            log.warning("WS invalid JSON from client: %.100s", raw_message)
        except Exception as e:
            log.error("WS message error: %s", e)

    async def _heartbeat_loop(self, websocket: WebSocket) -> None:
        try:
            while True:
                await asyncio.sleep(WS_HEARTBEAT_INTERVAL)
                try:
                    await asyncio.wait_for(
                        websocket.send_json({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()}),
                        timeout=5.0,
                    )
                except (RuntimeError, asyncio.TimeoutError) as e:
                    log.debug("WS heartbeat send failed: %s", e)
                    break
        except asyncio.CancelledError:
            pass

    async def _validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            from cybernova.security.encryption.jwt_handler import decode_access_token
            payload = decode_access_token(token)
            if payload and payload.get("type") == "access":
                return payload
            return None
        except (ValueError, TypeError, ImportError) as e:
            log.warning("WS JWT validation failed: %s", e)
            return None

    # public broadcast API

    async def broadcast_alert(
        self,
        alert: Dict[str, Any],
        tenant_id: str,
        event_type: EventType = EventType.NEW_ALERT,
    ) -> None:
        message = WebSocketMessage(
            event_type=event_type,
            data={"alert": alert},
            tenant_id=tenant_id,
        )
        await connection_manager.send_to_tenant(
            tenant_id, message,
            {EventType.NEW_ALERT, EventType.ALERT_UPDATED},
        )

    async def broadcast_incident(
        self,
        incident: Dict[str, Any],
        tenant_id: str,
        event_type: EventType = EventType.NEW_INCIDENT,
    ) -> None:
        message = WebSocketMessage(
            event_type=event_type,
            data={"incident": incident},
            tenant_id=tenant_id,
        )
        await connection_manager.send_to_tenant(
            tenant_id, message,
            {EventType.NEW_INCIDENT, EventType.INCIDENT_UPDATED},
        )

    async def broadcast_soar_action(
        self,
        action: Dict[str, Any],
        tenant_id: str,
    ) -> None:
        message = WebSocketMessage(
            event_type=EventType.SOAR_ACTION,
            data={"action": action},
            tenant_id=tenant_id,
        )
        await connection_manager.send_to_tenant(
            tenant_id, message, {EventType.SOAR_ACTION},
        )

    async def broadcast_pipeline_status(
        self,
        tenant_id: str,
    ) -> None:
        from cybernova.pipeline.unified_pipeline import unified_pipeline
        status = await unified_pipeline.get_metrics()
        message = WebSocketMessage(
            event_type=EventType.PIPELINE_STATUS,
            data=status,
            tenant_id=tenant_id,
        )
        await connection_manager.send_to_tenant(
            tenant_id, message, {EventType.PIPELINE_STATUS},
        )


    async def broadcast_dashboard_snapshot(self, tenant_id: str) -> None:
        """Push dashboard summary + throughput to connected clients."""
        from cybernova.dashboard.service import dashboard_service
        from cybernova.database.postgres.session import get_db_session

        summary = None
        throughput = None
        async for db in get_db_session():
            try:
                summary = await dashboard_service.get_summary(db, tenant_id)
                throughput = await dashboard_service.get_pipeline_throughput(db, tenant_id)
            except Exception as e:
                log.warning("Dashboard snapshot query failed: %s", e)
            break

        if summary is None:
            summary = {}
        if throughput is None:
            throughput = {}

        message = WebSocketMessage(
            event_type=EventType.DASHBOARD_SNAPSHOT,
            data={
                "summary": summary,
                "throughput": throughput,
            },
            tenant_id=tenant_id,
        )
        await connection_manager.send_to_tenant(
            tenant_id, message, {EventType.DASHBOARD_SNAPSHOT},
        )


ws_handler = WebSocketHandler()
