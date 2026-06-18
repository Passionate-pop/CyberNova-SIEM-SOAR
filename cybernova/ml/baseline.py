from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import NormalizedEvent, EntityBaseline

log = logging.getLogger("cybernova.ml.baseline")

DEFAULT_WINDOW_DAYS = 30
MIN_EVENTS_FOR_BASELINE = 10


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = k - f
    if f + 1 < len(sorted_vals):
        return sorted_vals[f] * (1 - c) + sorted_vals[f + 1] * c
    return sorted_vals[-1]


def _compute_frequency_stats(
    hourly_counts: Dict[int, int],
) -> Dict[str, float]:
    if not hourly_counts:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    vals = list(hourly_counts.values())
    n = len(vals)
    mean = sum(vals) / n
    variance = sum((v - mean) ** 2 for v in vals) / n if n > 1 else 0.0
    s = sorted(vals)
    return {
        "mean": round(mean, 2),
        "std": round(variance ** 0.5, 2),
        "min": float(min(vals)),
        "max": float(max(vals)),
        "p50": _percentile(s, 50),
        "p95": _percentile(s, 95),
        "p99": _percentile(s, 99),
    }


def _compute_hourly_distribution(events_by_hour: Dict[int, int]) -> List[float]:
    total = sum(events_by_hour.values())
    if total == 0:
        return [0.0] * 24
    return [round(events_by_hour.get(h, 0) / total, 4) for h in range(24)]


def _compute_daily_distribution(events_by_day: Dict[int, int]) -> List[float]:
    total = sum(events_by_day.values())
    if total == 0:
        return [0.0] * 7
    return [round(events_by_day.get(d, 0) / total, 4) for d in range(7)]


def _compute_port_diversity(events: List[NormalizedEvent]) -> Dict[str, Any]:
    ports = defaultdict(int)
    for ev in events:
        if ev.dest_port is not None:
            ports[ev.dest_port] += 1
    if not ports:
        return {"unique_ports": 0, "mean": 0.0, "std": 0.0, "entropy": 0.0}
    counts = list(ports.values())
    n = len(counts)
    mean = sum(counts) / n
    variance = sum((c - mean) ** 2 for c in counts) / n if n > 1 else 0.0
    total = sum(counts)
    entropy = -sum((c / total) * __import__("math").log(c / total) for c in counts if c > 0)
    return {
        "unique_ports": n,
        "mean": round(mean, 2),
        "std": round(variance ** 0.5, 2),
        "entropy": round(entropy, 4),
    }


def _compute_ip_diversity(events: List[NormalizedEvent]) -> Dict[str, Any]:
    ips = defaultdict(int)
    for ev in events:
        if ev.dest_ip:
            ips[ev.dest_ip] += 1
    if not ips:
        return {"unique_ips": 0, "mean": 0.0, "std": 0.0, "entropy": 0.0}
    counts = list(ips.values())
    n = len(counts)
    mean = sum(counts) / n
    variance = sum((c - mean) ** 2 for c in counts) / n if n > 1 else 0.0
    total = sum(counts)
    entropy = -sum((c / total) * __import__("math").log(c / total) for c in counts if c > 0)
    return {
        "unique_ips": n,
        "mean": round(mean, 2),
        "std": round(variance ** 0.5, 2),
        "entropy": round(entropy, 4),
    }


def _compute_event_type_distribution(events: List[NormalizedEvent]) -> Dict[str, int]:
    dist: Dict[str, int] = defaultdict(int)
    for ev in events:
        dist[ev.event_type] += 1
    return dict(dist)


class BaselineComputer:
    """Computes per-entity statistical baselines from historical normalized events.

    Baselines cover event frequency, time-of-day patterns, port/IP diversity,
    and event type distribution — computed per tenant/source_ip/user.
    """

    def __init__(self, window_days: int = DEFAULT_WINDOW_DAYS):
        self.window_days = window_days

    async def compute_all(self, db: AsyncSession) -> Dict[str, int]:
        """Compute baselines for all tenants. Returns {entity_type: count}."""
        stmt = select(NormalizedEvent.tenant_id).distinct()
        result = await db.execute(stmt)
        tenant_ids = [row[0] for row in result]
        total = {"source_ip": 0, "user": 0}
        for tid in tenant_ids:
            counts = await self.compute_tenant_baselines(db, tid)
            for k, v in counts.items():
                total[k] += v
        log.info("Baselines computed for %d tenants: %s", len(tenant_ids), total)
        return total

    async def compute_tenant_baselines(
        self, db: AsyncSession, tenant_id: str,
    ) -> Dict[str, int]:
        """Compute baselines for a single tenant. Returns {entity_type: count}."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.window_days)
        stmt = (
            select(NormalizedEvent)
            .where(
                NormalizedEvent.tenant_id == tenant_id,
                NormalizedEvent.timestamp >= cutoff,
            )
            .order_by(NormalizedEvent.timestamp)
        )
        result = await db.execute(stmt)
        events = result.scalars().all()

        if not events:
            return {"source_ip": 0, "user": 0}

        # Group by source_ip
        by_ip: Dict[str, List[NormalizedEvent]] = defaultdict(list)
        # Group by user
        by_user: Dict[str, List[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.source_ip:
                by_ip[ev.source_ip].append(ev)
            if ev.user:
                by_user[ev.user].append(ev)

        ip_count = 0
        for ip_val, ip_events in by_ip.items():
            if len(ip_events) >= MIN_EVENTS_FOR_BASELINE:
                await self._upsert_baseline(db, tenant_id, "source_ip", ip_val, ip_events)
                ip_count += 1

        user_count = 0
        for user_val, user_events in by_user.items():
            if len(user_events) >= MIN_EVENTS_FOR_BASELINE:
                await self._upsert_baseline(db, tenant_id, "user", user_val, user_events)
                user_count += 1

        log.info(
            "Tenant %s: %d IP baselines, %d user baselines (%d total events, %d day window)",
            tenant_id, ip_count, user_count, len(events), self.window_days,
        )
        return {"source_ip": ip_count, "user": user_count}

    async def _upsert_baseline(
        self,
        db: AsyncSession,
        tenant_id: str,
        entity_type: str,
        entity_value: str,
        events: List[NormalizedEvent],
    ) -> None:
        events_by_hour: Dict[int, int] = defaultdict(int)
        events_by_day: Dict[int, int] = defaultdict(int)

        for ev in events:
            ts = ev.timestamp
            if ts:
                events_by_hour[ts.hour] += 1
                events_by_day[ts.weekday()] += 1

        # Remove previous baseline for this entity (avoid unique constraint violation)
        await db.execute(
            EntityBaseline.__table__.delete().where(
                and_(
                    EntityBaseline.tenant_id == tenant_id,
                    EntityBaseline.entity_type == entity_type,
                    EntityBaseline.entity_value == entity_value,
                )
            )
        )

        baseline = EntityBaseline(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_value=entity_value,
            window_days=self.window_days,
            total_events=len(events),
            event_frequency=_compute_frequency_stats(events_by_hour),
            hourly_distribution=_compute_hourly_distribution(events_by_hour),
            daily_distribution=_compute_daily_distribution(events_by_day),
            port_diversity=_compute_port_diversity(events),
            ip_diversity=_compute_ip_diversity(events),
            event_type_distribution=_compute_event_type_distribution(events),
            computed_at=datetime.now(timezone.utc),
        )

        db.add(baseline)

    async def get_baseline(
        self,
        db: AsyncSession,
        tenant_id: str,
        entity_type: str,
        entity_value: str,
    ) -> Optional[EntityBaseline]:
        """Retrieve the latest baseline for a given entity."""
        stmt = (
            select(EntityBaseline)
            .where(
                EntityBaseline.tenant_id == tenant_id,
                EntityBaseline.entity_type == entity_type,
                EntityBaseline.entity_value == entity_value,
            )
            .order_by(EntityBaseline.computed_at.desc())
            .limit(1)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_baseline_for_event(
        self,
        db: AsyncSession,
        event: NormalizedEvent,
    ) -> Dict[str, Optional[EntityBaseline]]:
        """Retrieve baselines matching an event's source_ip and user."""
        result: Dict[str, Optional[EntityBaseline]] = {}
        if event.source_ip:
            result["source_ip"] = await self.get_baseline(
                db, event.tenant_id, "source_ip", event.source_ip,
            )
        if event.user:
            result["user"] = await self.get_baseline(
                db, event.tenant_id, "user", event.user,
            )
        return result


baseline_computer = BaselineComputer()
