"""
Analytics API. Funnel, TTFD, insights, drill-down.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.postgres.models import AnalyticsEvent, UserSession, Insight
from cybernova.auth.dependencies import RequirePermission
from cybernova.auth.rbac import Permission
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser

require_view = RequirePermission(Permission.ANALYTICS_VIEW)

log = logging.getLogger("cybernova.analytics.api")
router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])

FUNNEL_STEPS = [
    "signup_completed",
    "org_created",
    "org_key_viewed",
    "command_copied",
    "agent_started",
    "device_connected",
]


# event tracking

@router.post("/events", summary="Track analytics event")
async def track_event(
    event_name: str,
    event_category: Optional[str] = None,
    metadata: dict = {},
    user_id: Optional[str] = None,
    device_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """Track a user action event for analytics."""
    event = AnalyticsEvent(
        tenant_id=tenant_id,
        user_id=user_id or current_user.id,
        device_id=device_id,
        event_name=event_name,
        event_category=event_category or "general",
        event_data=metadata,
    )
    db.add(event)
    await db.commit()
    return {"status": "tracked", "event_id": event.id}


# funnel

@router.get("/funnel", summary="Get onboarding funnel")
async def get_funnel(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get onboarding funnel counts for each step."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
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

    return {"funnel": funnel, "period_days": days}


# ttfd

@router.get("/ttfd", summary="Get time-to-first-device metrics")
async def get_ttfd(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get TTFD distribution and averages."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(UserSession.ttf_device_seconds)
        .where(
            and_(
                UserSession.tenant_id == tenant_id,
                UserSession.ttf_device_seconds.isnot(None),
                UserSession.started_at >= start_date,
            )
        )
    )
    ttfd_values = [r[0] for r in result.all() if r[0] is not None]

    if not ttfd_values:
        return {"avg": None, "distribution": {"0-30": 0, "30-60": 0, "60-120": 0, "120+": 0}, "count": 0}

    avg = round(sum(ttfd_values) / len(ttfd_values), 1)
    distribution = {
        "0-30": sum(1 for v in ttfd_values if v <= 30),
        "30-60": sum(1 for v in ttfd_values if 30 < v <= 60),
        "60-120": sum(1 for v in ttfd_values if 60 < v <= 120),
        "120+": sum(1 for v in ttfd_values if v > 120),
    }

    return {"avg": avg, "distribution": distribution, "count": len(ttfd_values), "period_days": days}


# insights

@router.get("/insights", summary="Get auto-generated insights")
async def get_insights(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get AI-generated insights based on funnel + TTFD data."""
    result = await db.execute(
        select(Insight)
        .where(Insight.tenant_id == tenant_id)
        .order_by(Insight.created_at.desc())
        .limit(limit)
    )
    insights = result.scalars().all()

    return {
        "insights": [
            {
                "id": i.id,
                "type": i.type,
                "severity": i.severity,
                "message": i.message,
                "action": i.action,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in insights
        ]
    }


@router.post("/insights/generate", summary="Run insight engine")
async def generate_insights(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Run the auto-insight engine to analyze funnel and generate insights."""

    days = 30
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    new_insights = []

    # Get funnel data
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

    # Rule 1: Activation Drop (device_connected vs signup)
    if funnel.get("signup_completed", 0) > 0:
        activation_rate = funnel.get("device_connected", 0) / funnel.get("signup_completed", 1)
        if activation_rate < 0.8:
            insight = Insight(
                tenant_id=tenant_id,
                type="activation_drop",
                severity="high",
                message=f"Activation rate dropped to {activation_rate:.0%}. Only {funnel.get('device_connected', 0)} of {funnel.get('signup_completed', 0)} users connected a device.",
                action="Review onboarding flow for friction points. Check if agent install instructions are clear.",
            )
            db.add(insight)
            new_insights.append(insight)

    # Rule 2: Step Drops
    for i in range(len(FUNNEL_STEPS) - 1):
        current_step = FUNNEL_STEPS[i]
        next_step = FUNNEL_STEPS[i + 1]
        if funnel.get(current_step, 0) > 0:
            drop_rate = 1 - (funnel.get(next_step, 0) / funnel.get(current_step, 1))
            if drop_rate > 0.5:
                step_name = next_step.replace("_", " ").title()
                insight = Insight(
                    tenant_id=tenant_id,
                    type="step_drop",
                    severity="high" if drop_rate > 0.7 else "medium",
                    message=f"Step drop at '{step_name}': {drop_rate:.0%} of users didn't complete this step.",
                    action=f"Improve guidance for {step_name}. Consider adding tooltips or simplifying the step.",
                )
                db.add(insight)
                new_insights.append(insight)

    # Rule 3: Slow TTFD
    result = await db.execute(
        select(func.avg(UserSession.ttf_device_seconds))
        .where(
            and_(
                UserSession.tenant_id == tenant_id,
                UserSession.ttf_device_seconds.isnot(None),
                UserSession.started_at >= start_date,
            )
        )
    )
    avg_ttfd = result.scalar()
    if avg_ttfd and avg_ttfd > 120:
        insight = Insight(
            tenant_id=tenant_id,
            type="slow_ttfd",
            severity="medium",
            message=f"Users taking average {avg_ttfd:.0f}s to connect their first device (target: <120s).",
            action="Simplify agent installation. Pre-fill commands where possible.",
        )
        db.add(insight)
        new_insights.append(insight)

    await db.commit()

    return {
        "status": "complete",
        "insights_generated": len(new_insights),
        "insights": [{"id": i.id, "type": i.type, "message": i.message} for i in new_insights],
    }


# drill-down: users stuck

@router.get("/users-stuck", summary="Get users stuck at a step")
async def get_users_stuck(
    step: str = Query(..., description="Step name where users are stuck"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Find users who completed the step before but didn't complete 'step'."""
    step_idx = FUNNEL_STEPS.index(step) if step in FUNNEL_STEPS else 0
    if step_idx == 0:
        return {"users": []}

    previous_step = FUNNEL_STEPS[step_idx - 1]

    result = await db.execute(
        text("""
            WITH completed_previous AS (
                SELECT DISTINCT user_id, tenant_id
                FROM analytics_events
                WHERE event_name = :previous_step
                  AND tenant_id = :tenant_id
            ),
            stuck_users AS (
                SELECT DISTINCT user_id, tenant_id
                FROM analytics_events
                WHERE event_name = :step
                  AND tenant_id = :tenant_id
            )
            SELECT cp.user_id, ae.last_event, ae.time_spent
            FROM completed_previous cp
            LEFT JOIN stuck_users su ON cp.user_id = su.user_id AND cp.tenant_id = su.tenant_id
            LEFT JOIN LATERAL (
                SELECT event_name as last_event,
                       EXTRACT(EPOCH FROM (created_at - (SELECT MAX(created_at) FROM analytics_events ae2 WHERE ae2.user_id = cp.user_id AND ae2.tenant_id = cp.tenant_id AND ae2.event_name = :previous_step))) as time_spent
                FROM analytics_events
                WHERE user_id = cp.user_id AND tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT 1
            ) ae ON true
            WHERE su.user_id IS NULL
            LIMIT 50
        """),
        {"previous_step": previous_step, "step": step, "tenant_id": tenant_id},
    )
    rows = result.all()
    users = [{"user_id": r[0], "last_event": r[1], "time_spent_seconds": r[2]} for r in rows]

    return {"step": step, "users_stuck": users, "count": len(users)}


# drill-down: user session timeline

@router.get("/session/{user_id}", summary="Get user session timeline")
async def get_user_session(
    user_id: str,
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get full event timeline for a user (session replay)."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(AnalyticsEvent)
        .where(
            and_(
                AnalyticsEvent.tenant_id == tenant_id,
                AnalyticsEvent.user_id == user_id,
                AnalyticsEvent.created_at >= start_date,
            )
        )
        .order_by(AnalyticsEvent.created_at.asc())
    )
    events = result.scalars().all()

    timeline = [
        {
            "event_id": e.id,
            "event_name": e.event_name,
            "category": e.event_category,
            "timestamp": e.created_at.isoformat() if e.created_at else None,
            "time_offset_seconds": int((e.created_at - events[0].created_at).total_seconds()) if events and e.created_at and events[0].created_at else 0,
            "metadata": e.event_data,
        }
        for e in events
    ]

    return {"user_id": user_id, "timeline": timeline, "event_count": len(timeline)}


# dashboard summary

@router.get("/summary", summary="Get dashboard summary")
async def get_analytics_summary(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_view),
    tenant_id: str = Depends(get_tenant_id),
):
    """Get summary metrics for the analytics dashboard."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    # Total events
    result = await db.execute(
        select(func.count(AnalyticsEvent.id))
        .where(
            and_(
                AnalyticsEvent.tenant_id == tenant_id,
                AnalyticsEvent.created_at >= start_date,
            )
        )
    )
    total_events = result.scalar() or 0

    # Active users
    result = await db.execute(
        select(func.count(func.distinct(AnalyticsEvent.user_id)))
        .where(
            and_(
                AnalyticsEvent.tenant_id == tenant_id,
                AnalyticsEvent.created_at >= start_date,
            )
        )
    )
    active_users = result.scalar() or 0

    # Devices connected
    result = await db.execute(
        select(func.count(AnalyticsEvent.id))
        .where(
            and_(
                AnalyticsEvent.tenant_id == tenant_id,
                AnalyticsEvent.event_name == "device_connected",
                AnalyticsEvent.created_at >= start_date,
            )
        )
    )
    devices_connected = result.scalar() or 0

    # Avg TTFD
    result = await db.execute(
        select(func.avg(UserSession.ttf_device_seconds))
        .where(
            and_(
                UserSession.tenant_id == tenant_id,
                UserSession.ttf_device_seconds.isnot(None),
                UserSession.started_at >= start_date,
            )
        )
    )
    avg_ttfd = result.scalar()

    # Recent insights
    result = await db.execute(
        select(Insight)
        .where(Insight.tenant_id == tenant_id)
        .order_by(Insight.created_at.desc())
        .limit(3)
    )
    recent_insights = result.scalars().all()

    return {
        "period_days": days,
        "total_events": total_events,
        "active_users": active_users,
        "devices_connected": devices_connected,
        "avg_ttfd_seconds": round(avg_ttfd, 1) if avg_ttfd else None,
        "recent_insights": [
            {"id": i.id, "type": i.type, "severity": i.severity, "message": i.message}
            for i in recent_insights
        ],
    }