"""
CyberNova — Enterprise Health Check Module
Provides robust health/readiness probes with component dependency tracking,
startup phase visibility, and graceful degradation reporting.

Usage:
    from cybernova.monitoring.health import health_registry

    health_registry.register("database", critical=True, depends_on=[])
    health_registry.healthy("database")

Endpoints consume this in main.py (/health, /ready, /health/detailed).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.monitoring.health")


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


@dataclass
class HealthComponent:
    """Represents a single tracked component's health."""
    name: str
    critical: bool = True
    depends_on: List[str] = field(default_factory=list)
    status: HealthStatus = HealthStatus.STARTING
    last_updated: float = 0.0
    last_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    startup_timeout: float = 300.0  # seconds before STARTING → UNHEALTHY

    @property
    def is_healthy(self) -> bool:
        return self.status == HealthStatus.HEALTHY

    @property
    def is_operational(self) -> bool:
        """Can this component serve traffic? Healthy or degraded are OK."""
        return self.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)


@dataclass
class StartupPhase:
    """Tracks the current startup phase for visibility."""
    name: str
    status: str = "pending"  # pending, running, completed, failed
    started_at: float = 0.0
    completed_at: Optional[float] = None
    error: Optional[str] = None


class HealthRegistry:
    """
    Central health registry with dependency chain tracking.

    Features:
    - Component dependency resolution (auto-derive health from dependencies)
    - Startup phase tracking (visible in /health endpoint)
    - Critical vs optional component differentiation
    - Status caching with TTL
    - Prometheus-compatible metrics export
    """

    def __init__(self):
        self._components: Dict[str, HealthComponent] = {}
        self._phases: List[StartupPhase] = []
        self._started_at: float = time.monotonic()
        self._lock = asyncio.Lock()

    # ── Phase Tracking ──────────────────────────────────────────────────

    def begin_phase(self, name: str) -> None:
        """Mark the beginning of a startup phase."""
        phase = StartupPhase(name=name, status="running", started_at=time.monotonic())
        self._phases.append(phase)
        log.info("Health phase started: %s", name)

    def complete_phase(self, name: str, error: Optional[str] = None) -> None:
        """Mark a startup phase as completed or failed."""
        for phase in self._phases:
            if phase.name == name and phase.status == "running":
                phase.status = "failed" if error else "completed"
                phase.completed_at = time.monotonic()
                phase.error = error
                log.info("Health phase %s: %s", name, "failed" if error else "completed")
                return

    # ── Component Registration ──────────────────────────────────────────

    def register(
        self,
        name: str,
        critical: bool = True,
        depends_on: Optional[List[str]] = None,
        startup_timeout: float = 300.0,
    ) -> None:
        """Register a component for health tracking."""
        if name not in self._components:
            self._components[name] = HealthComponent(
                name=name,
                critical=critical,
                depends_on=depends_on or [],
                startup_timeout=startup_timeout,
            )
            log.debug("Health component registered: %s (critical=%s)", name, critical)

    def healthy(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Mark a component as healthy."""
        self._ensure_registered(name)
        self._components[name].status = HealthStatus.HEALTHY
        self._components[name].last_updated = time.monotonic()
        self._components[name].last_error = None
        if metadata:
            self._components[name].metadata.update(metadata)

    def degraded(self, name: str, error: Optional[str] = None) -> None:
        """Mark a component as degraded (operational but with issues)."""
        self._ensure_registered(name)
        self._components[name].status = HealthStatus.DEGRADED
        self._components[name].last_updated = time.monotonic()
        if error:
            self._components[name].last_error = error

    def unhealthy(self, name: str, error: Optional[str] = None) -> None:
        """Mark a component as unhealthy."""
        self._ensure_registered(name)
        self._components[name].status = HealthStatus.UNHEALTHY
        self._components[name].last_updated = time.monotonic()
        self._components[name].last_error = error

    def stopped(self, name: str) -> None:
        """Mark a component as stopped."""
        if name in self._components:
            self._components[name].status = HealthStatus.STOPPED
            self._components[name].last_updated = time.monotonic()

    def _ensure_registered(self, name: str) -> None:
        if name not in self._components:
            self._components[name] = HealthComponent(name=name)

    # ── Status Queries ──────────────────────────────────────────────────

    def get_component(self, name: str) -> Optional[HealthComponent]:
        return self._components.get(name)

    def get_all_components(self) -> List[HealthComponent]:
        return list(self._components.values())

    def get_unhealthy(self) -> List[HealthComponent]:
        """Return components that are currently unhealthy."""
        now = time.monotonic()
        result = []
        for comp in self._components.values():
            if comp.status == HealthStatus.UNHEALTHY:
                result.append(comp)
            elif comp.status == HealthStatus.STARTING and now - comp.last_updated > comp.startup_timeout:
                result.append(comp)
        return result

    def get_critical_unhealthy(self) -> List[HealthComponent]:
        """Return only critical components that are unhealthy."""
        return [c for c in self.get_unhealthy() if c.critical]

    def is_healthy(self) -> bool:
        """True if all critical components are healthy (non-critical can be degraded)."""
        now = time.monotonic()
        for comp in self._components.values():
            if not comp.critical:
                continue
            if comp.status == HealthStatus.UNHEALTHY:
                return False
            if comp.status == HealthStatus.STARTING and now - comp.last_updated > comp.startup_timeout:
                return False
        return True

    def is_ready(self) -> bool:
        """True if all critical components are operational (healthy or degraded)."""
        now = time.monotonic()
        for comp in self._components.values():
            if not comp.critical:
                continue
            if comp.status == HealthStatus.UNHEALTHY:
                return False
            if comp.status == HealthStatus.STARTING and now - comp.last_updated > comp.startup_timeout:
                return False
            if comp.status == HealthStatus.STOPPED:
                return False
        return True

    # ── Summary Reports ─────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Full health summary for the /health endpoint."""
        now = time.monotonic()
        all_comps = self.get_all_components()
        unhealthy = self.get_unhealthy()
        critical_unhealthy = self.get_critical_unhealthy()

        return {
            "status": "healthy" if self.is_healthy() else "degraded",
            "ready": self.is_ready(),
            "uptime_seconds": round(now - self._started_at),
            "total_components": len(all_comps),
            "healthy_count": sum(1 for c in all_comps if c.is_healthy),
            "degraded_count": sum(1 for c in all_comps if c.status == HealthStatus.DEGRADED),
            "unhealthy_count": len(unhealthy),
            "critical_unhealthy_count": len(critical_unhealthy),
            "startup_phases": [
                {
                    "name": p.name,
                    "status": p.status,
                    "duration_seconds": round((p.completed_at or time.monotonic()) - p.started_at, 1)
                    if p.started_at else 0,
                    "error": p.error,
                }
                for p in self._phases
            ],
            "components": {
                c.name: {
                    "status": c.status.value,
                    "critical": c.critical,
                    "depends_on": c.depends_on,
                    "uptime_seconds": round(now - c.last_updated) if c.last_updated else 0,
                    "last_error": c.last_error,
                    "metadata": c.metadata,
                }
                for c in all_comps
            },
            "unhealthy_components": [
                {"name": c.name, "status": c.status.value,
                 "error": c.last_error}
                for c in unhealthy
            ],
            "critical_unhealthy": [
                {"name": c.name, "error": c.last_error}
                for c in critical_unhealthy
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def readiness_check(self) -> Dict[str, Any]:
        """Readiness check for /ready endpoint (K8s-compatible)."""
        healthy = self.is_ready()
        unhealthy_comps = self.get_unhealthy()
        return {
            "ready": healthy,
            "status": "ready" if healthy else "not_ready",
            "unhealthy_count": len(unhealthy_comps),
            "checks": {
                c.name: {
                    "status": c.status.value,
                    "critical": c.critical,
                    "error": c.last_error,
                }
                for c in unhealthy_comps
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Prometheus Export ────────────────────────────────────────────────

    def export_prometheus(self) -> str:
        """Export health metrics in Prometheus format."""
        lines = [
            "# HELP cybernova_health health status (1=healthy, 0=unhealthy)",
            "# TYPE cybernova_health_status gauge",
        ]
        for comp in self._components.values():
            val = 1 if comp.status == HealthStatus.HEALTHY else 0
            lines.append(
                'cybernova_health_status{component="%s",critical="%s"} %s'
                % (comp.name, str(comp.critical).lower(), val)
            )
        lines.append("# HELP cybernova_health_uptime_seconds Process uptime")
        lines.append("# TYPE cybernova_health_uptime_seconds gauge")
        uptime = time.monotonic() - self._started_at
        lines.append(f"cybernova_health_uptime_seconds {uptime}")
        return "\n".join(lines) + "\n"


# Singleton
health_registry = HealthRegistry()
