from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from cybernova.ingestion.agent.schemas import AgentConfiguration, SystemInfo, TelemetryBatch

log = logging.getLogger("cybernova.agent.manager")


class AgentState:
    def __init__(self, device_id: str, tenant_id: str, hostname: str):
        self.device_id = device_id
        self.tenant_id = tenant_id
        self.hostname = hostname
        self.last_heartbeat: Optional[datetime] = None
        self.first_seen: datetime = datetime.now(timezone.utc)
        self.system_info: Optional[SystemInfo] = None
        self.config: AgentConfiguration = AgentConfiguration()
        self.config_version: int = 1
        self.process_count: int = 0
        self.connection_count: int = 0
        self.events_ingested: int = 0
        self.errors: int = 0
        self.status: str = "active"
        self.ip_address: str = ""

    def mark_heartbeat(self) -> None:
        self.last_heartbeat = datetime.now(timezone.utc)

    @property
    def is_healthy(self) -> bool:
        if not self.last_heartbeat:
            return True
        return (datetime.now(timezone.utc) - self.last_heartbeat) < timedelta(seconds=90)

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.first_seen).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "tenant_id": self.tenant_id,
            "hostname": self.hostname,
            "status": self.status,
            "is_healthy": self.is_healthy,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "first_seen": self.first_seen.isoformat(),
            "uptime_seconds": self.uptime_seconds,
            "ip_address": self.ip_address,
            "os": f"{self.system_info.os_type} {self.system_info.os_version}" if self.system_info else "unknown",
            "process_count": self.process_count,
            "connection_count": self.connection_count,
            "events_ingested": self.events_ingested,
            "errors": self.errors,
        }


class AgentManager:
    def __init__(self):
        self._agents: Dict[str, AgentState] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("AgentManager started")

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        log.info("AgentManager stopped")

    async def register_or_update(
        self,
        device_id: str,
        tenant_id: str,
        hostname: str,
        ip_address: str,
        system_info: Optional[SystemInfo] = None,
    ) -> AgentState:
        async with self._lock:
            key = f"{tenant_id}:{device_id}"
            if key not in self._agents:
                agent = AgentState(device_id, tenant_id, hostname)
                self._agents[key] = agent
            else:
                agent = self._agents[key]
            agent.mark_heartbeat()
            agent.ip_address = ip_address
            agent.status = "active"
            if system_info:
                agent.system_info = system_info
            return agent

    async def process_telemetry(
        self,
        device_id: str,
        tenant_id: str,
        batch: TelemetryBatch,
    ) -> AgentConfiguration:
        key = f"{tenant_id}:{device_id}"
        async with self._lock:
            agent = self._agents.get(key)
            if not agent:
                agent = AgentState(device_id, tenant_id, batch.system.hostname if batch.system else "unknown")
                self._agents[key] = agent
            agent.mark_heartbeat()
            if batch.system:
                agent.system_info = batch.system
                agent.ip_address = batch.system.ip_addresses[0] if batch.system.ip_addresses else ""
            agent.process_count = len(batch.processes)
            agent.connection_count = len(batch.connections)
            agent.events_ingested += (
                len(batch.processes) + len(batch.connections) +
                len(batch.file_events) + len(batch.security_events)
            )
            return agent.config

    async def get_agent(self, tenant_id: str, device_id: str) -> Optional[AgentState]:
        async with self._lock:
            return self._agents.get(f"{tenant_id}:{device_id}")

    async def get_agents_by_tenant(self, tenant_id: str) -> list[AgentState]:
        async with self._lock:
            return [
                agent for key, agent in self._agents.items()
                if key.startswith(f"{tenant_id}:")
            ]

    async def get_all_agents(self) -> list[AgentState]:
        async with self._lock:
            return list(self._agents.values())

    async def get_metrics(self) -> Dict[str, Any]:
        async with self._lock:
            total = len(self._agents)
            healthy = sum(1 for a in self._agents.values() if a.is_healthy)
            total_events = sum(a.events_ingested for a in self._agents.values())
            return {
                "total_agents": total,
                "healthy_agents": healthy,
                "unhealthy_agents": total - healthy,
                "total_events_ingested": total_events,
                "agents": [a.to_dict() for a in self._agents.values()],
            }

    async def update_config(
        self,
        tenant_id: str,
        device_id: str,
        config: AgentConfiguration,
    ) -> bool:
        async with self._lock:
            key = f"{tenant_id}:{device_id}"
            agent = self._agents.get(key)
            if not agent:
                return False
            config.config_version = agent.config_version + 1
            config.updated_at = datetime.now(timezone.utc).isoformat()
            agent.config = config
            agent.config_version = config.config_version
            return True

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            async with self._lock:
                now = datetime.now(timezone.utc)
                stale_keys = []
                for key, agent in self._agents.items():
                    if agent.last_heartbeat and (now - agent.last_heartbeat) > timedelta(minutes=5):
                        agent.status = "offline"
                    if agent.last_heartbeat and (now - agent.last_heartbeat) > timedelta(hours=24):
                        stale_keys.append(key)
                for key in stale_keys:
                    log.info("Removing stale agent: %s", key)
                    del self._agents[key]


agent_manager = AgentManager()
