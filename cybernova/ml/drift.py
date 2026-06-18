from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import NormalizedEvent, EntityBaseline, DriftRecord
from cybernova.ml.baseline import baseline_computer

log = logging.getLogger("cybernova.ml.drift")

MOVING_WINDOW_MINUTES = 60
DRIFT_THRESHOLD = 0.5
MIN_EVENTS_FOR_DRIFT = 5

_SMOOTH = 1e-6


# ── Statistical Helpers ───────────────────────────────────────────────────────

def _kl_divergence(p: List[float], q: List[float]) -> float:
    """KL(P || Q) with smoothing to avoid log(0)."""
    kl = 0.0
    for pi, qi in zip(p, q):
        pi = pi + _SMOOTH
        qi = qi + _SMOOTH
        kl += pi * math.log(pi / qi)
    return kl


def _js_divergence(p: List[float], q: List[float]) -> float:
    """Jensen-Shannon divergence, bounded in [0, ln(2)]."""
    mid = [(pi + qi) / 2.0 for pi, qi in zip(p, q)]
    return (_kl_divergence(p, mid) + _kl_divergence(q, mid)) / 2.0


def _normalize_jsd(jsd: float) -> float:
    """Normalize JSD to [0, 1] by dividing by ln(2)."""
    return min(1.0, jsd / math.log(2)) if math.log(2) > 0 else 0.0


def _z_score_to_drift(z: float) -> float:
    """Map a z-score to a drift value in [0, 1]."""
    return min(1.0, abs(z) / 6.0)


def _ratio_drift(current: float, baseline: float) -> float:
    """Drift from ratio difference: |c-b| / max(c,b, 1)."""
    denom = max(abs(current), abs(baseline), 1.0)
    return min(1.0, abs(current - baseline) / denom)


# ── Moving Window Aggregation ─────────────────────────────────────────────────

async def _fetch_window_events(
    db: AsyncSession,
    tenant_id: str,
    entity_type: str,
    entity_value: str,
    window_minutes: int,
) -> List[NormalizedEvent]:
    """Fetch events for an entity in the moving time window."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    filter_col = NormalizedEvent.source_ip if entity_type == "source_ip" else NormalizedEvent.user
    stmt = (
        select(NormalizedEvent)
        .where(
            NormalizedEvent.tenant_id == tenant_id,
            filter_col == entity_value,
            NormalizedEvent.timestamp >= cutoff,
        )
        .order_by(NormalizedEvent.timestamp)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


def _aggregate_window(
    events: List[NormalizedEvent],
) -> Dict[str, Any]:
    """Compute current statistics for a set of events (mirrors baseline format)."""
    hourly_counts: Dict[int, int] = defaultdict(int)
    daily_counts: Dict[int, int] = defaultdict(int)
    ports: Dict[int, int] = defaultdict(int)
    ips: Dict[str, int] = defaultdict(int)
    event_types: Dict[str, int] = defaultdict(int)

    for ev in events:
        ts = ev.timestamp
        if ts:
            hourly_counts[ts.hour] += 1
            daily_counts[ts.weekday()] += 1
        if ev.dest_port is not None:
            ports[ev.dest_port] += 1
        if ev.dest_ip:
            ips[ev.dest_ip] += 1
        event_types[ev.event_type] += 1

    total = len(events)

    # Hourly distribution
    hourly_dist = [0.0] * 24
    if total > 0:
        for h, c in hourly_counts.items():
            hourly_dist[h] = round(c / total, 4)

    # Event type distribution (as proportions for comparison)
    et_dist: Dict[str, float] = {}
    if total > 0:
        for et, c in event_types.items():
            et_dist[et] = c / total

    return {
        "total_events": total,
        "hourly_distribution": hourly_dist,
        "unique_ports": len(ports),
        "unique_ips": len(ips),
        "event_type_proportions": et_dist,
    }


# ── Drift Score Computation ───────────────────────────────────────────────────

def _compute_frequency_drift(
    freq_stats: Dict[str, float],
) -> float:
    """Drift based on event frequency vs baseline mean/std."""
    mean = freq_stats.get("mean", 0.0)
    std = freq_stats.get("std", 1.0)
    if std < 0.01:
        return 0.0
    return _z_score_to_drift(mean / std)


def _compute_distribution_drift(
    current_dist: List[float],
    baseline_dist: List[float],
) -> float:
    """Drift between two probability distributions using JSD."""
    if not baseline_dist or not current_dist:
        return 0.0
    max_len = max(len(current_dist), len(baseline_dist))
    p = list(current_dist) + [0.0] * (max_len - len(current_dist))
    q = list(baseline_dist) + [0.0] * (max_len - len(baseline_dist))
    jsd = _js_divergence(p, q)
    return _normalize_jsd(jsd)


def _compute_diversity_drift(
    current_unique: int,
    baseline_unique: int,
) -> float:
    """Drift based on unique count difference."""
    return _ratio_drift(float(current_unique), float(baseline_unique))


def _compute_event_type_drift(
    current_props: Dict[str, float],
    baseline_props: Dict[str, int],
) -> float:
    """Drift in event type distribution using JSD."""
    all_types = set(current_props.keys()) | set(baseline_props.keys())
    baseline_total = max(sum(baseline_props.values()), 1)
    p = [current_props.get(t, 0.0) for t in sorted(all_types)]
    q = [baseline_props.get(t, 0) / baseline_total for t in sorted(all_types)]
    jsd = _js_divergence(p, q)
    return _normalize_jsd(jsd)


# ── Drift Detector ────────────────────────────────────────────────────────────

class DriftDetector:
    """Detects behavioral drift by comparing moving window statistics against baselines."""

    def __init__(
        self,
        window_minutes: int = MOVING_WINDOW_MINUTES,
        drift_threshold: float = DRIFT_THRESHOLD,
    ):
        self.window_minutes = window_minutes
        self.drift_threshold = drift_threshold

    async def check_entity(
        self,
        db: AsyncSession,
        baseline: EntityBaseline,
    ) -> Optional[DriftRecord]:
        """Check drift for a single entity against its baseline. Returns DriftRecord if drift >= threshold."""
        events = await _fetch_window_events(
            db, baseline.tenant_id, baseline.entity_type,
            baseline.entity_value, self.window_minutes,
        )
        if len(events) < MIN_EVENTS_FOR_DRIFT:
            return None

        window = _aggregate_window(events)
        b_freq = baseline.event_frequency or {}
        b_hourly = baseline.hourly_distribution or []
        b_port = baseline.port_diversity or {}
        b_ip = baseline.ip_diversity or {}
        b_et = baseline.event_type_distribution or {}

        freq_drift = _compute_frequency_drift(b_freq)
        hourly_drift = _compute_distribution_drift(
            window["hourly_distribution"], b_hourly,
        )
        port_drift = _compute_diversity_drift(
            window["unique_ports"], b_port.get("unique_ports", 0),
        )
        ip_drift = _compute_diversity_drift(
            window["unique_ips"], b_ip.get("unique_ips", 0),
        )
        et_drift = _compute_event_type_drift(
            window["event_type_proportions"], b_et,
        )

        weights = {"freq": 0.25, "hourly": 0.25, "port": 0.15, "ip": 0.15, "et": 0.20}
        drift_score = (
            weights["freq"] * freq_drift
            + weights["hourly"] * hourly_drift
            + weights["port"] * port_drift
            + weights["ip"] * ip_drift
            + weights["et"] * et_drift
        )

        if drift_score < self.drift_threshold:
            return None

        record = DriftRecord(
            tenant_id=baseline.tenant_id,
            entity_type=baseline.entity_type,
            entity_value=baseline.entity_value,
            drift_score=round(drift_score, 4),
            drift_metrics={
                "frequency_drift": round(freq_drift, 4),
                "hourly_drift": round(hourly_drift, 4),
                "port_drift": round(port_drift, 4),
                "ip_drift": round(ip_drift, 4),
                "event_type_drift": round(et_drift, 4),
                "weights": weights,
            },
            frequency_drift=round(freq_drift, 4),
            hourly_drift=round(hourly_drift, 4),
            port_drift=round(port_drift, 4),
            ip_drift=round(ip_drift, 4),
            event_type_drift=round(et_drift, 4),
            window_minutes=self.window_minutes,
            window_event_count=len(events),
            baseline_event_count=baseline.total_events,
            detected_at=datetime.now(timezone.utc),
        )
        return record

    async def check_all(self, db: AsyncSession) -> List[DriftRecord]:
        """Check drift for all entities with baselines. Returns list of detected drifts."""
        stmt = select(EntityBaseline).order_by(EntityBaseline.computed_at.desc())
        result = await db.execute(stmt)
        baselines = result.scalars().all()

        detected: List[DriftRecord] = []
        for bl in baselines:
            try:
                record = await self.check_entity(db, bl)
                if record:
                    db.add(record)
                    detected.append(record)
            except Exception as e:
                log.warning(
                    "Drift check failed for %s/%s/%s: %s",
                    bl.tenant_id, bl.entity_type, bl.entity_value, e,
                )

        if detected:
            await db.commit()
            log.info(
                "Drift scan complete: %d/%d entities flagged (threshold=%.2f)",
                len(detected), len(baselines), self.drift_threshold,
            )
        else:
            log.info("Drift scan complete: no drift detected (%d entities checked)", len(baselines))

        return detected

    async def check_event(
        self,
        db: AsyncSession,
        event: NormalizedEvent,
    ) -> Optional[DriftRecord]:
        """Inline drift check for a single event. Checks source_ip and user baselines."""
        baselines = await baseline_computer.get_baseline_for_event(db, event)
        for bl in baselines.values():
            if bl is None:
                continue
            record = await self.check_entity(db, bl)
            if record:
                db.add(record)
                await db.commit()
                return record
        return None


drift_detector = DriftDetector()
