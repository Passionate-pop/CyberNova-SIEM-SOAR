"""
CyberNova — Analytics Service
Batched, async event tracking with insight evaluation.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from sqlalchemy import and_, select

from cybernova.database.postgres.models import AnalyticsEvent, UserSession, Insight
from cybernova.database.postgres.session import get_db_session
from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.analytics.service")

STREAM_NAME = "analytics:events"
BATCH_INTERVAL = 2.0


class AnalyticsService:
    def __init__(self):
        self._batch: List[dict] = []
        self._lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        if self._running:
            return
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_processor())
        log.info("✓ Analytics service started")

    async def stop(self):
        self._running = False
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
        await self._flush()
        log.info("✓ Analytics service stopped")

    async def track(
        self,
        tenant_id: str,
        event_name: str,
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        event_category: Optional[str] = None,
        metadata: dict = None,
    ):
        entry = {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "device_id": device_id,
            "event_name": event_name,
            "event_category": event_category or "general",
            "metadata": metadata or {},
        }

        async with self._lock:
            self._batch.append(entry)

        redis = await get_redis()
        if redis:
            try:
                await redis.xadd(STREAM_NAME, entry)
            except Exception as e:
                log.warning("Analytics Redis stream write failed: %s", e)

    async def _batch_processor(self):
        while self._running:
            await asyncio.sleep(BATCH_INTERVAL)
            await self._flush()

    async def _flush(self):
        async with self._lock:
            if not self._batch:
                return
            entries = self._batch.copy()
            self._batch.clear()

        try:
            async for db in get_db_session():
                events = [
                    AnalyticsEvent(
                        tenant_id=e["tenant_id"],
                        user_id=e["user_id"],
                        device_id=e["device_id"],
                        event_name=e["event_name"],
                        event_category=e["event_category"],
                        event_data=e["metadata"],
                    )
                    for e in entries
                ]
                db.add_all(events)
                await db.commit()
                log.debug(f"Flushed {len(events)} analytics events")
                break
        except Exception as e:
            log.error(f"Failed to flush analytics batch: {e}")

    async def calculate_ttfd(self, tenant_id: str, user_id: str) -> Optional[int]:
        async for db in get_db_session():
            result = await db.execute(
                select(AnalyticsEvent)
                .where(
                    and_(
                        AnalyticsEvent.tenant_id == tenant_id,
                        AnalyticsEvent.user_id == user_id,
                    )
                )
                .order_by(AnalyticsEvent.created_at.asc())
            )
            events = result.scalars().all()

        if not events:
            return None

        signup = None
        device_connected = None

        for e in events:
            if e.event_name == "signup_completed" and not signup:
                signup = e.created_at
            elif e.event_name == "device_connected" and not device_connected:
                device_connected = e.created_at

        if signup and device_connected:
            return int((device_connected - signup).total_seconds())
        return None

    async def record_session(
        self,
        tenant_id: str,
        user_id: str,
        ttf_device_seconds: Optional[int] = None,
    ):
        async for db in get_db_session():
            session = UserSession(
                tenant_id=tenant_id,
                user_id=user_id,
                ttf_device_seconds=ttf_device_seconds,
            )
            db.add(session)
            await db.commit()
            break

    async def evaluate_insights(self, tenant_id: str, days: int = 30):
        from sqlalchemy import and_, select, func
        from cybernova.analytics.routes import FUNNEL_STEPS

        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        new_insights = []

        async for db in get_db_session():
            funnel = {}
            for step in FUNNEL_STEPS:
                result = await db.execute(
                    select(func.count(AnalyticsEvent.id))
                    .where(
                        and_(
                            AnalyticsEvent.tenant_id == tenant_id,
                            AnalyticsEvent.event_name == step,
                            AnalyticsEvent.created_at >= start_date,
                        )
                    )
                )
                funnel[step] = result.scalar() or 0

            if funnel.get("signup_completed", 0) > 0:
                activation_rate = funnel.get("device_connected", 0) / funnel.get("signup_completed", 1)
                if activation_rate < 0.8:
                    insight = Insight(
                        tenant_id=tenant_id,
                        type="activation_drop",
                        severity="high",
                        message=f"Activation rate dropped to {activation_rate:.0%}.",
                        action="Review onboarding flow for friction points.",
                    )
                    db.add(insight)
                    new_insights.append(insight)

            for i in range(len(FUNNEL_STEPS) - 1):
                current_step = FUNNEL_STEPS[i]
                next_step = FUNNEL_STEPS[i + 1]
                if funnel.get(current_step, 0) > 0:
                    drop_rate = 1 - (funnel.get(next_step, 0) / funnel.get(current_step, 1))
                    if drop_rate > 0.5:
                        insight = Insight(
                            tenant_id=tenant_id,
                            type="step_drop",
                            severity="high" if drop_rate > 0.7 else "medium",
                            message=f"Step drop at '{next_step}': {drop_rate:.0%} users didn't complete.",
                            action=f"Improve guidance for {next_step}.",
                        )
                        db.add(insight)
                        new_insights.append(insight)

            result = await db.execute(
                select(func.avg(UserSession.ttf_device_seconds))
                .where(
                    and_(
                        UserSession.tenant_id == tenant_id,
                        UserSession.ttf_device_seconds.isnot(None),
                    )
                )
            )
            avg_ttfd = result.scalar()
            if avg_ttfd and avg_ttfd > 120:
                insight = Insight(
                    tenant_id=tenant_id,
                    type="slow_ttfd",
                    severity="medium",
                    message=f"Avg TTFD is {avg_ttfd:.0f}s (target: <120s).",
                    action="Simplify agent installation.",
                )
                db.add(insight)
                new_insights.append(insight)

            await db.commit()

        log.info(f"Generated {len(new_insights)} insights for tenant {tenant_id}")
        return new_insights


analytics_service = AnalyticsService()