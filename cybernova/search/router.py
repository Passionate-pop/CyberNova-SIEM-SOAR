"""
CyberNova — SIEM Search API Router
Endpoints for executing search queries, exploring data, and filtering alerts/events.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_alerts_view
from cybernova.search.query_parser import parse_query
from cybernova.search.service import search_service

router = APIRouter(prefix="/api/v1/search", tags=["Search"])


class SearchRequest(BaseModel):
    query: str = ""
    index: str = "alerts"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = 100
    offset: int = 0


class AlertSearchRequest(BaseModel):
    severity: Optional[List[str]] = None
    status: Optional[str] = None
    rule_name: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    free_text: Optional[str] = None
    limit: int = 100
    offset: int = 0


class EventSearchRequest(BaseModel):
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    severity: Optional[List[str]] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    free_text: Optional[str] = None
    limit: int = 100
    offset: int = 0


class ExploreRequest(BaseModel):
    query: str = ""
    limit: int = 100
    offset: int = 0


def _build_query_from_request(body: SearchRequest) -> Any:
    parsed = parse_query(body.query)
    parsed.limit = min(body.limit, 1000)
    parsed.offset = body.offset

    if body.start_time or body.end_time:
        if parsed.time_range is None:
            from cybernova.search.query_parser import TimeRange
            parsed.time_range = TimeRange()
        if body.start_time:
            parsed.time_range.start = _parse_dt(body.start_time)
        if body.end_time:
            parsed.time_range.end = _parse_dt(body.end_time)

    # If no terms or filters were parsed, the query is either empty or free-form
    if not parsed.text_terms and not parsed.field_filters and not parsed.aggregation:
        if body.query:
            parsed.text_terms.append(body.query)

    return parsed


def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1]
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@router.post("/query")
async def execute_query(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_alerts_view),
    tenant_id: str = Depends(get_tenant_id),
):
    query = _build_query_from_request(body)

    if body.index and body.index != "all":
        query.field_filters.insert(0, type("_", (), {"field": "_index", "value": body.index, "operator": "eq"})())

    result = await search_service.search(query, tenant_id, db)
    return result


@router.post("/alerts")
async def search_alerts(
    body: AlertSearchRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_alerts_view),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.search.query_parser import SearchQuery, FieldFilter, TimeRange

    query = SearchQuery()
    query.limit = min(body.limit, 1000)
    query.offset = body.offset

    if body.severity:
        for sev in body.severity:
            query.field_filters.append(FieldFilter(field="severity", operator="eq", value=sev))
    if body.status:
        query.field_filters.append(FieldFilter(field="status", operator="eq", value=body.status))
    if body.rule_name:
        query.field_filters.append(FieldFilter(field="rule_name", operator="like", value=body.rule_name))
    if body.source_ip:
        query.field_filters.append(FieldFilter(field="source_ip", operator="eq", value=body.source_ip))
    if body.user:
        query.field_filters.append(FieldFilter(field="user", operator="eq", value=body.user))
    if body.risk_score_min is not None:
        query.field_filters.append(FieldFilter(field="risk_score", operator="gte", value=body.risk_score_min))
    if body.risk_score_max is not None:
        query.field_filters.append(FieldFilter(field="risk_score", operator="lte", value=body.risk_score_max))

    if body.start_time or body.end_time:
        query.time_range = TimeRange()
        if body.start_time:
            query.time_range.start = _parse_dt(body.start_time)
        if body.end_time:
            query.time_range.end = _parse_dt(body.end_time)

    if body.free_text:
        query.text_terms.append(body.free_text)

    results = await search_service.search_alerts(query, tenant_id, db)
    return {"results": results, "total": len(results), "took_ms": 0}


@router.post("/events")
async def search_events(
    body: EventSearchRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_alerts_view),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.search.query_parser import SearchQuery, FieldFilter, TimeRange

    query = SearchQuery()
    query.limit = min(body.limit, 1000)
    query.offset = body.offset

    if body.event_type:
        query.field_filters.append(FieldFilter(field="event_type", operator="eq", value=body.event_type))
    if body.source_ip:
        query.field_filters.append(FieldFilter(field="source_ip", operator="eq", value=body.source_ip))
    if body.dest_ip:
        query.field_filters.append(FieldFilter(field="dest_ip", operator="eq", value=body.dest_ip))
    if body.source_port is not None:
        query.field_filters.append(FieldFilter(field="source_port", operator="eq", value=body.source_port))
    if body.dest_port is not None:
        query.field_filters.append(FieldFilter(field="dest_port", operator="eq", value=body.dest_port))
    if body.protocol:
        query.field_filters.append(FieldFilter(field="protocol", operator="eq", value=body.protocol))
    if body.user:
        query.field_filters.append(FieldFilter(field="user", operator="eq", value=body.user))
    if body.severity:
        for sev in body.severity:
            query.field_filters.append(FieldFilter(field="severity", operator="eq", value=sev))

    if body.start_time or body.end_time:
        query.time_range = TimeRange()
        if body.start_time:
            query.time_range.start = _parse_dt(body.start_time)
        if body.end_time:
            query.time_range.end = _parse_dt(body.end_time)

    if body.free_text:
        query.text_terms.append(body.free_text)

    results = await search_service.search_events(query, tenant_id, db)
    return {"results": results, "total": len(results), "took_ms": 0}


@router.post("/explore")
async def explore(
    body: ExploreRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_alerts_view),
    tenant_id: str = Depends(get_tenant_id),
):
    query = parse_query(body.query)
    query.limit = min(body.limit, 1000)
    query.offset = body.offset

    result = await search_service.search(query, tenant_id, db)
    result["index"] = "all"
    return result
