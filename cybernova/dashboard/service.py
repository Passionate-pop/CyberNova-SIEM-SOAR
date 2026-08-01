"""
CyberNova — Dashboard Data Service
Aggregates real-time data from DB and pipeline for the frontend dashboard.
Passive replicas serve Redis-cached data when not the leader.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Optional

from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    Alert, Incident, Device, NormalizedEvent, BlockedIP, AuditLog,
)
from cybernova.database.redis import get_redis
from cybernova.ha.leader import leader_election
from cybernova.pipeline.unified_pipeline import unified_pipeline

log = logging.getLogger("cybernova.dashboard.service")

CACHE_TTL = 30
CACHE_PREFIX = "dashboard:cache"


class DashboardService:

    async def _cache_get(self, tenant_id: str, method: str) -> Optional[Any]:
        try:
            redis = await get_redis()
            if redis:
                key = f"{CACHE_PREFIX}:{tenant_id}:{method}"
                data = await redis.get(key)
                if data:
                    return json.loads(data)
        except Exception as e:
            log.debug("Dashboard cache get failed: %s", e)
        return None

    async def _cache_set(self, tenant_id: str, method: str, data: Any, ttl: int = CACHE_TTL) -> None:
        try:
            redis = await get_redis()
            if redis:
                key = f"{CACHE_PREFIX}:{tenant_id}:{method}"
                await redis.setex(key, ttl, json.dumps(data, default=str))
        except Exception as e:
            log.debug("Dashboard cache set failed: %s", e)

    async def _cached(self, tenant_id: str, method: str, fetch_fn: Callable, ttl: int = CACHE_TTL) -> Any:
        is_leader = leader_election.is_leader or leader_election._local_mode
        if not is_leader:
            cached = await self._cache_get(tenant_id, method)
            if cached is not None:
                return cached
        result = await fetch_fn()
        if is_leader:
            await self._cache_set(tenant_id, method, result, ttl)
        return result

    async def get_summary(self, db: AsyncSession, tenant_id: str) -> dict:
        async def _fetch():
            now = datetime.now(timezone.utc)
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

            total_alerts = (await db.execute(
                select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)
            )).scalar() or 0

            alerts_today = (await db.execute(
                select(func.count(Alert.id)).where(
                    Alert.tenant_id == tenant_id, Alert.created_at >= today_start
                )
            )).scalar() or 0

            active_threats = (await db.execute(
                select(func.count(Alert.id)).where(
                    Alert.tenant_id == tenant_id,
                    Alert.severity.in_(["critical", "high"]),
                    Alert.status == "new",
                )
            )).scalar() or 0

            total_devices = (await db.execute(
                select(func.count(Device.id)).where(Device.tenant_id == tenant_id)
            )).scalar() or 0

            devices_at_risk = (await db.execute(
                select(func.count(Device.id)).where(
                    Device.tenant_id == tenant_id, Device.is_isolated
                )
            )).scalar() or 0

            blocked_ips = (await db.execute(
                select(func.count(BlockedIP.id)).where(BlockedIP.tenant_id == tenant_id)
            )).scalar() or 0

            risk_score = min(100, (active_threats * 15) + (devices_at_risk * 10))

            return {
                "total_alerts": total_alerts,
                "alerts_today": alerts_today,
                "active_threats": active_threats,
                "total_devices": total_devices,
                "devices_at_risk": devices_at_risk,
                "blocked_ips": blocked_ips,
                "risk_score": risk_score,
                "system_health": max(0, 100 - risk_score),
                "threats_mitigated": max(0, total_alerts - active_threats),
            }
        return await self._cached(tenant_id, "summary", _fetch)

    async def get_alert_timeseries(
        self, db: AsyncSession, tenant_id: str,
        hours: int = 24, bucket_minutes: int = 60,
    ) -> list:
        async def _fetch():
            now = datetime.now(timezone.utc)
            since = now - timedelta(hours=hours)

            result = await db.execute(
                select(Alert).where(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= since,
                ).order_by(Alert.created_at.asc())
            )
            alerts = result.scalars().all()

            bucket_seconds = bucket_minutes * 60
            buckets = {}
            for a in alerts:
                if not a.created_at:
                    continue
                epoch = int(a.created_at.timestamp())
                bucket_key = (epoch // bucket_seconds) * bucket_seconds
                ts = datetime.fromtimestamp(bucket_key, tz=timezone.utc).isoformat()
                if ts not in buckets:
                    buckets[ts] = {"timestamp": ts, "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                buckets[ts]["count"] += 1
                sev = (a.severity or "low").lower()
                if sev in buckets[ts]:
                    buckets[ts][sev] += 1

            return [buckets[k] for k in sorted(buckets.keys())]

        return await self._cached(tenant_id, f"timeseries_{hours}_{bucket_minutes}", _fetch)

    async def get_severity_distribution(self, db: AsyncSession, tenant_id: str) -> dict:
        async def _fetch():
            result = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for sev in result:
                count = await db.execute(
                    select(func.count(Alert.id)).where(
                        Alert.tenant_id == tenant_id,
                        Alert.severity == sev,
                    )
                )
                result[sev] = count.scalar() or 0
            return result
        return await self._cached(tenant_id, "severity", _fetch)

    async def get_top_source_ips(self, db: AsyncSession, tenant_id: str, limit: int = 10) -> list:
        async def _fetch():
            severity_weight = case(
                (Alert.severity == "critical", 5),
                (Alert.severity == "high", 4),
                (Alert.severity == "medium", 3),
                (Alert.severity == "low", 2),
                (Alert.severity == "info", 1),
                else_=0,
            )
            weight_to_sev = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}

            result = await db.execute(
                select(
                    Alert.source_ip,
                    func.count(Alert.id).label("count"),
                    func.max(Alert.created_at).label("last_seen"),
                    func.max(severity_weight).label("max_sev_weight"),
                )
                .where(
                    Alert.tenant_id == tenant_id,
                    Alert.source_ip.isnot(None),
                    Alert.source_ip != "",
                )
                .group_by(Alert.source_ip)
                .order_by(func.count(Alert.id).desc())
                .limit(limit)
            )
            return [
                {
                    "ip": r.source_ip,
                    "count": r.count,
                    "max_severity": weight_to_sev.get(r.max_sev_weight, "low"),
                    "last_seen": r.last_seen.isoformat() if r.last_seen else "",
                }
                for r in result.all()
            ]
        return await self._cached(tenant_id, f"top_sources_{limit}", _fetch)

    async def get_top_alert_types(self, db: AsyncSession, tenant_id: str, limit: int = 10) -> list:
        async def _fetch():
            severity_weight = case(
                (Alert.severity == "critical", 5),
                (Alert.severity == "high", 4),
                (Alert.severity == "medium", 3),
                (Alert.severity == "low", 2),
                (Alert.severity == "info", 1),
                else_=0,
            )
            weight_to_sev = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}

            result = await db.execute(
                select(
                    Alert.rule_name,
                    func.count(Alert.id).label("count"),
                    func.max(severity_weight).label("max_sev_weight"),
                )
                .where(Alert.tenant_id == tenant_id)
                .group_by(Alert.rule_name)
                .order_by(func.count(Alert.id).desc())
                .limit(limit)
            )
            return [
                {
                    "rule_name": r.rule_name,
                    "count": r.count,
                    "max_severity": weight_to_sev.get(r.max_sev_weight, "low"),
                }
                for r in result.all()
            ]
        return await self._cached(tenant_id, f"top_alerts_{limit}", _fetch)

    async def get_recent_activity(self, db: AsyncSession, tenant_id: str, limit: int = 20) -> list:
        async def _fetch():
            alert_result = await db.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id)
                .order_by(Alert.created_at.desc())
                .limit(limit)
            )
            alerts = alert_result.scalars().all()

            audit_result = await db.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == tenant_id)
                .order_by(AuditLog.timestamp.desc())
                .limit(limit)
            )
            logs = audit_result.scalars().all()

            activities = []
            for a in alerts:
                activities.append({
                    "timestamp": a.created_at.isoformat() if a.created_at else "",
                    "type": "alert",
                    "description": a.description or a.rule_name,
                    "severity": a.severity,
                    "actor": a.source_ip or "system",
                })
            for log_entry in logs:
                activities.append({
                    "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else "",
                    "type": "audit",
                    "description": log_entry.action,
                    "severity": "info",
                    "actor": log_entry.user_id or "system",
                })

            activities.sort(key=lambda x: x["timestamp"], reverse=True)
            return activities[:limit]
        return await self._cached(tenant_id, f"activity_{limit}", _fetch)

    async def get_pipeline_throughput(self, db: AsyncSession, tenant_id: str) -> dict:
        async def _fetch():
            metrics = await unified_pipeline.get_metrics()

            five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
            recent_result = await db.execute(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.tenant_id == tenant_id,
                    NormalizedEvent.normalized_at >= five_min_ago,
                )
            )
            events_recent = recent_result.scalar() or 0

            return {
                "eps_current": round(events_recent / 300, 2),
                "eps_avg_5min": round(events_recent / 300, 2),
                "eps_peak": round(max(metrics.get("latency_ms") or [0]) or 0, 2),
                "total_ingested": metrics.get("ingested", 0),
                "total_processed": metrics.get("normalized", 0),
                "errors": metrics.get("errors", 0),
                "avg_latency_ms": metrics.get("avg_latency_ms", 0),
            }
        return await self._cached(tenant_id, "throughput", _fetch, ttl=15)

    async def get_threat_map_data(self, db: AsyncSession, tenant_id: str) -> list:
        async def _fetch():
            try:
                from cybernova.database.postgres.models import EnrichedEvent

                result = await db.execute(
                    select(EnrichedEvent.geo_data)
                    .where(
                        EnrichedEvent.tenant_id == tenant_id,
                        EnrichedEvent.geo_data.isnot(None),
                    )
                    .limit(100)
                )
                points = []
                seen = set()
                for row in result.all():
                    geo = row.geo_data or {}
                    lat = geo.get("latitude") or geo.get("lat")
                    lon = geo.get("longitude") or geo.get("lon")
                    key = f"{lat},{lon}"
                    if lat and lon and key not in seen:
                        seen.add(key)
                        points.append({
                            "lat": float(lat),
                            "lon": float(lon),
                            "severity": "medium",
                            "count": 1,
                        })
                return points
            except Exception as e:
                log.warning("Threat map data query failed: %s", e)
                return []
        return await self._cached(tenant_id, "threat_map", _fetch)

    async def get_rule_performance(self, db: AsyncSession, tenant_id: str) -> list:
        async def _fetch():
            result = await db.execute(
                select(
                    Alert.rule_name,
                    func.count(Alert.id).label("hits"),
                    func.avg(Alert.risk_score).label("avg_risk_score"),
                    func.max(Alert.created_at).label("last_triggered"),
                )
                .where(Alert.tenant_id == tenant_id)
                .group_by(Alert.rule_name)
                .order_by(func.count(Alert.id).desc())
            )
            return [
                {
                    "rule_name": r.rule_name,
                    "hits": r.hits,
                    "avg_risk_score": round(float(r.avg_risk_score), 2) if r.avg_risk_score else 0.0,
                    "last_triggered": r.last_triggered.isoformat() if r.last_triggered else "",
                }
                for r in result.all()
            ]
        return await self._cached(tenant_id, "rule_performance", _fetch)

    async def get_executive_summary(self, db: AsyncSession, tenant_id: str) -> dict:
        async def _fetch():
            now = datetime.now(timezone.utc)
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

            total_alerts = (await db.execute(
                select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)
            )).scalar() or 0

            alerts_today = (await db.execute(
                select(func.count(Alert.id)).where(
                    Alert.tenant_id == tenant_id, Alert.created_at >= today_start
                )
            )).scalar() or 0

            active_threats = (await db.execute(
                select(func.count(Alert.id)).where(
                    Alert.tenant_id == tenant_id,
                    Alert.severity.in_(["critical", "high"]),
                    Alert.status == "new",
                )
            )).scalar() or 0

            total_devices = (await db.execute(
                select(func.count(Device.id)).where(Device.tenant_id == tenant_id)
            )).scalar() or 0

            isolated_devices = (await db.execute(
                select(func.count(Device.id)).where(
                    Device.tenant_id == tenant_id, Device.is_isolated
                )
            )).scalar() or 0

            blocked_ips = (await db.execute(
                select(func.count(BlockedIP.id)).where(BlockedIP.tenant_id == tenant_id)
            )).scalar() or 0

            incidents_open = (await db.execute(
                select(func.count(Incident.id)).where(
                    Incident.tenant_id == tenant_id,
                    Incident.status.in_(["new", "open", "investigating"]),
                )
            )).scalar() or 0

            trend = []
            for i in range(6, -1, -1):
                day = today_start - timedelta(days=i)
                next_day = day + timedelta(days=1)
                day_count = (await db.execute(
                    select(func.count(Alert.id)).where(
                        Alert.tenant_id == tenant_id,
                        Alert.created_at >= day,
                        Alert.created_at < next_day,
                    )
                )).scalar() or 0
                trend.append({"date": day.strftime("%Y-%m-%d"), "count": day_count})

            risk_score = min(100, (active_threats * 15) + (isolated_devices * 10))
            throughput = await self.get_pipeline_throughput(db, tenant_id)
            severity = await self.get_severity_distribution(db, tenant_id)
            top_alerts = await self.get_top_alert_types(db, tenant_id, 5)

            return {
                "summary": {
                    "total_alerts": total_alerts,
                    "alerts_today": alerts_today,
                    "active_threats": active_threats,
                    "threats_mitigated": max(0, total_alerts - active_threats),
                    "total_devices": total_devices,
                    "active_devices": total_devices - isolated_devices,
                    "devices_at_risk": isolated_devices,
                    "blocked_ips": blocked_ips,
                    "incidents_open": incidents_open,
                    "risk_score": risk_score,
                    "system_health": max(0, 100 - risk_score),
                },
                "trend": trend,
                "severity_distribution": severity,
                "throughput": throughput,
                "top_alert_types": top_alerts,
            }
        return await self._cached(tenant_id, "executive_summary", _fetch)


dashboard_service = DashboardService()
