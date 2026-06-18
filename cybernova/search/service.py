"""
CyberNova — SIEM Search Execution Service
Executes SearchQuery against Alert, NormalizedEvent, Incident, AuditLog tables.
"""
from __future__ import annotations

import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import Integer, select, func, or_, Text, cast
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    Alert, NormalizedEvent, Incident, AuditLog, RawEvent,
)
from cybernova.search.query_parser import (
    SearchQuery, FieldFilter, TimeRange, Aggregation,
)

log = logging.getLogger("cybernova.search")


class SearchService:
    """Executes SIEM search queries against the database."""

    # Map of common field names to their column references per model
    FIELD_MAP: Dict[str, Dict[Any, Any]] = {
        "source_ip": {Alert: Alert.source_ip, NormalizedEvent: NormalizedEvent.source_ip},
        "dest_ip": {Alert: Alert.dest_ip, NormalizedEvent: NormalizedEvent.dest_ip},
        "user": {Alert: Alert.user, NormalizedEvent: NormalizedEvent.user},
        "severity": {Alert: Alert.severity, NormalizedEvent: Alert.severity, Incident: Incident.severity},
        "risk_score": {Alert: Alert.risk_score, Incident: Incident.risk_score},
        "status": {Alert: Alert.status, Incident: Incident.status},
        "event_type": {Alert: Alert.event_type, NormalizedEvent: NormalizedEvent.event_type},
        "rule_name": {Alert: Alert.rule_name},
        "description": {Alert: Alert.description, Incident: Incident.description},
        "message": {NormalizedEvent: NormalizedEvent.message},
        "source_port": {NormalizedEvent: NormalizedEvent.source_port},
        "dest_port": {NormalizedEvent: NormalizedEvent.dest_port},
        "protocol": {NormalizedEvent: NormalizedEvent.protocol},
        "mitre_tactic": {Alert: Alert.mitre_tactic},
        "mitre_technique": {Alert: Alert.mitre_technique},
        "action": {AuditLog: AuditLog.action},
        "resource_type": {AuditLog: AuditLog.resource_type},
        "ip_address": {AuditLog: AuditLog.ip_address},
    }

    # Text-searchable columns per model
    TEXT_FIELDS: Dict[Any, List[Any]] = {
        Alert: [Alert.rule_name, Alert.description, Alert.source_ip, Alert.dest_ip, Alert.user, Alert.event_type],
        NormalizedEvent: [NormalizedEvent.message, NormalizedEvent.user, NormalizedEvent.source_ip, NormalizedEvent.dest_ip, NormalizedEvent.event_type],
        Incident: [Incident.title, Incident.description],
        AuditLog: [AuditLog.action, AuditLog.resource_type, cast(AuditLog.details, Text), AuditLog.ip_address],
    }

    # Mapping for agg/time columns per model
    TIME_COLUMN: Dict[Any, Any] = {
        Alert: Alert.created_at,
        NormalizedEvent: NormalizedEvent.timestamp,
        Incident: Incident.created_at,
        AuditLog: AuditLog.timestamp,
    }

    def _get_column(self, model: Any, field: str) -> Optional[Any]:
        if field in self.FIELD_MAP and model in self.FIELD_MAP[field]:
            return self.FIELD_MAP[field][model]
        return getattr(model, field, None)

    def _apply_field_filter(self, stmt: Any, model: Any, ff: FieldFilter) -> Tuple[Any, List[str]]:
        warnings = []
        col = self._get_column(model, ff.field)
        if col is None:
            warnings.append(f"Field '{ff.field}' not found on {model.__name__}")
            return stmt, warnings

        try:
            if ff.operator == 'eq':
                stmt = stmt.where(col == ff.value)
            elif ff.operator == 'neq':
                stmt = stmt.where(col != ff.value)
            elif ff.operator == 'gt':
                stmt = stmt.where(col > self._coerce_value(col, ff.value))
            elif ff.operator == 'gte':
                stmt = stmt.where(col >= self._coerce_value(col, ff.value))
            elif ff.operator == 'lt':
                stmt = stmt.where(col < self._coerce_value(col, ff.value))
            elif ff.operator == 'lte':
                stmt = stmt.where(col <= self._coerce_value(col, ff.value))
            elif ff.operator == 'like':
                pattern = ff.value.replace('*', '%').replace('?', '_')
                stmt = stmt.where(col.ilike(pattern))
            elif ff.operator == 'range':
                start, end = ff.value
                if start != '*':
                    stmt = stmt.where(col >= self._coerce_value(col, start))
                if end != '*':
                    stmt = stmt.where(col <= self._coerce_value(col, end))
            elif ff.operator == 'cidr':
                prefix = ff.value.rsplit('/', 1)[0]
                stmt = stmt.where(col.ilike(f"{prefix}%"))
        except Exception as e:
            warnings.append(f"Error applying filter '{ff.field} {ff.operator} {ff.value}': {e}")

        return stmt, warnings

    def _coerce_value(self, col: Any, value: Any) -> Any:
        col_type = str(col.type).lower()
        if 'float' in col_type or 'integer' in col_type or 'numeric' in col_type:
            try:
                return float(value)
            except (ValueError, TypeError):
                return value
        if 'datetime' in col_type:
            parsed = self._parse_dt(value)
            if parsed:
                return parsed
        return value

    def _parse_dt(self, s: str) -> Optional[datetime]:
        if isinstance(s, datetime):
            return s
        s = str(s).strip()
        if s.endswith('Z'):
            s = s[:-1]
        for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _apply_text_terms(self, stmt: Any, model: Any, text_terms: List[str], negate: bool = False) -> Any:
        if not text_terms:
            return stmt
        text_fields = self.TEXT_FIELDS.get(model, [])
        if not text_fields:
            return stmt

        for term in text_terms:
            pattern = f"%{term}%"
            conditions = [f.ilike(pattern) for f in text_fields]
            if negate:
                stmt = stmt.where(~or_(*conditions))
            else:
                stmt = stmt.where(or_(*conditions))
        return stmt

    def _apply_time_range(self, stmt: Any, model: Any, tr: Optional[TimeRange]) -> Any:
        if tr is None:
            return stmt
        tc = self.TIME_COLUMN.get(model)
        if tc is None:
            return stmt
        if tr.start:
            stmt = stmt.where(tc >= tr.start)
        if tr.end:
            stmt = stmt.where(tc <= tr.end)
        return stmt

    async def search_alerts(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> List[Dict[str, Any]]:
        stmt = select(Alert).where(Alert.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, Alert, query.time_range)

        for ff in query.field_filters:
            if ff.operator == 'neq' and ff.field == '_text':
                stmt = self._apply_text_terms(stmt, Alert, [ff.value], negate=True)
            else:
                stmt, _ = self._apply_field_filter(stmt, Alert, ff)

        stmt = self._apply_text_terms(stmt, Alert, query.text_terms)

        if query.sort:
            col = self._get_column(Alert, query.sort)
            if col:
                stmt = stmt.order_by(col.desc() if query.order == 'desc' else col.asc())
        else:
            stmt = stmt.order_by(Alert.created_at.desc())

        if query.limit:
            stmt = stmt.limit(query.limit)
        if query.offset:
            stmt = stmt.offset(query.offset)

        result = await db.execute(stmt)
        return [self._alert_to_dict(a) for a in result.scalars().all()]

    async def search_events(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> List[Dict[str, Any]]:
        stmt = select(NormalizedEvent).where(NormalizedEvent.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, NormalizedEvent, query.time_range)

        for ff in query.field_filters:
            if ff.operator == 'neq' and ff.field == '_text':
                stmt = self._apply_text_terms(stmt, NormalizedEvent, [ff.value], negate=True)
            else:
                stmt, _ = self._apply_field_filter(stmt, NormalizedEvent, ff)

        stmt = self._apply_text_terms(stmt, NormalizedEvent, query.text_terms)

        if query.sort:
            col = self._get_column(NormalizedEvent, query.sort)
            if col:
                stmt = stmt.order_by(col.desc() if query.order == 'desc' else col.asc())
        else:
            stmt = stmt.order_by(NormalizedEvent.timestamp.desc())

        if query.limit:
            stmt = stmt.limit(query.limit)
        if query.offset:
            stmt = stmt.offset(query.offset)

        result = await db.execute(stmt)
        return [self._event_to_dict(e) for e in result.scalars().all()]

    async def search_incidents(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> List[Dict[str, Any]]:
        stmt = select(Incident).where(Incident.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, Incident, query.time_range)

        for ff in query.field_filters:
            if ff.operator == 'neq' and ff.field == '_text':
                stmt = self._apply_text_terms(stmt, Incident, [ff.value], negate=True)
            else:
                stmt, _ = self._apply_field_filter(stmt, Incident, ff)

        stmt = self._apply_text_terms(stmt, Incident, query.text_terms)

        if query.sort:
            col = self._get_column(Incident, query.sort)
            if col:
                stmt = stmt.order_by(col.desc() if query.order == 'desc' else col.asc())
        else:
            stmt = stmt.order_by(Incident.created_at.desc())

        if query.limit:
            stmt = stmt.limit(query.limit)
        if query.offset:
            stmt = stmt.offset(query.offset)

        result = await db.execute(stmt)
        return [self._incident_to_dict(i) for i in result.scalars().all()]

    async def search_audit_logs(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> List[Dict[str, Any]]:
        stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, AuditLog, query.time_range)

        for ff in query.field_filters:
            if ff.operator == 'neq' and ff.field == '_text':
                stmt = self._apply_text_terms(stmt, AuditLog, [ff.value], negate=True)
            else:
                stmt, _ = self._apply_field_filter(stmt, AuditLog, ff)

        stmt = self._apply_text_terms(stmt, AuditLog, query.text_terms)

        if query.sort:
            col = self._get_column(AuditLog, query.sort)
            if col:
                stmt = stmt.order_by(col.desc() if query.order == 'desc' else col.asc())
        else:
            stmt = stmt.order_by(AuditLog.timestamp.desc())

        if query.limit:
            stmt = stmt.limit(query.limit)
        if query.offset:
            stmt = stmt.offset(query.offset)

        result = await db.execute(stmt)
        return [self._audit_log_to_dict(a) for a in result.scalars().all()]

    async def search_raw_events(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> List[Dict[str, Any]]:
        stmt = select(RawEvent).where(RawEvent.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, RawEvent, query.time_range)
        if query.text_terms:
            conditions = [RawEvent.source.ilike(f"%{t}%") for t in query.text_terms]
            stmt = stmt.where(or_(*conditions))
        if query.limit:
            stmt = stmt.limit(query.limit)
        if query.offset:
            stmt = stmt.offset(query.offset)
        stmt = stmt.order_by(RawEvent.received_at.desc())
        result = await db.execute(stmt)
        return [self._raw_event_to_dict(r) for r in result.scalars().all()]

    async def aggregate(
        self, agg: Aggregation, base_query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        if not agg:
            return {}

        if agg.agg_type == 'stats':
            return await self._aggregate_stats(agg, base_query, tenant_id, db)
        elif agg.agg_type in ('top', 'rare'):
            return await self._aggregate_top_rare(agg, base_query, tenant_id, db)
        elif agg.agg_type == 'timechart':
            return await self._aggregate_timechart(agg, base_query, tenant_id, db)
        return {}

    async def _aggregate_stats(
        self, agg: Aggregation, base_query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        model = self._pick_model(base_query)
        if model is None:
            return {}

        self.TIME_COLUMN.get(model)
        stmt = select(model).where(model.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, model, base_query.time_range)
        for ff in base_query.field_filters:
            stmt, _ = self._apply_field_filter(stmt, model, ff)
        stmt = self._apply_text_terms(stmt, model, base_query.text_terms)

        by_col = self._get_column(model, agg.by_field)
        if by_col is None:
            return {}

        if agg.field:
            agg_col = self._get_column(model, agg.field)
            if agg_col is None:
                return {}
            select_expr = func.avg(agg_col).label('value')
        else:
            select_expr = func.count('*').label('value')

        subq = stmt.subquery()
        agg_stmt = select(getattr(subq.c, by_col.name, by_col).label('key'), select_expr)
        agg_stmt = agg_stmt.group_by(by_col)
        agg_stmt = agg_stmt.order_by(func.count('*').desc())
        agg_stmt = agg_stmt.limit(agg.limit or 10)

        result = await db.execute(agg_stmt)
        rows = result.all()
        buckets = [{"key": str(r[0]), "count": float(r[1]) if r[1] is not None else 0} for r in rows]
        return {"buckets": buckets, "agg_type": "stats"}

    async def _aggregate_top_rare(
        self, agg: Aggregation, base_query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        model = self._pick_model(base_query)
        if model is None:
            return {}

        stmt = select(model).where(model.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, model, base_query.time_range)
        for ff in base_query.field_filters:
            stmt, _ = self._apply_field_filter(stmt, model, ff)
        stmt = self._apply_text_terms(stmt, model, base_query.text_terms)

        col = self._get_column(model, agg.field)
        if col is None:
            return {}

        subq = stmt.subquery()
        c = getattr(subq.c, col.name, col)
        agg_stmt = select(c.label('key'), func.count('*').label('count'))
        agg_stmt = agg_stmt.group_by(c)

        if agg.agg_type == 'top':
            agg_stmt = agg_stmt.order_by(func.count('*').desc())
        else:
            agg_stmt = agg_stmt.order_by(func.count('*').asc())

        agg_stmt = agg_stmt.limit(agg.limit or 10)

        result = await db.execute(agg_stmt)
        rows = result.all()
        buckets = [{"key": str(r[0]), "count": int(r[1])} for r in rows]
        return {"buckets": buckets, "agg_type": agg.agg_type}

    async def _aggregate_timechart(
        self, agg: Aggregation, base_query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        model = self._pick_model(base_query)
        if model is None:
            return {}

        col = self._get_column(model, agg.by_field)
        if col is None:
            return {}

        tc = self.TIME_COLUMN.get(model)
        stmt = select(model).where(model.tenant_id == tenant_id)
        stmt = self._apply_time_range(stmt, model, base_query.time_range)
        for ff in base_query.field_filters:
            stmt, _ = self._apply_field_filter(stmt, model, ff)
        stmt = self._apply_text_terms(stmt, model, base_query.text_terms)

        try:
            span_seconds = self._parse_span(agg.span or '1h')
            epoch = func.extract('epoch', tc).cast(Integer)
            (epoch / span_seconds).cast(Integer) * span_seconds

            subq = stmt.subquery()
            ts_col = getattr(subq.c, tc.name, tc)
            s_epoch = func.extract('epoch', ts_col).cast(Integer)
            s_bucket = (s_epoch / span_seconds).cast(Integer) * span_seconds
            timecol = func.to_timestamp(s_bucket).label('time')

            agg_col = None
            if agg.field:
                agg_col = getattr(subq.c, agg.field, None)

            by_col = getattr(subq.c, col.name, col)

            if agg_col is not None and agg.field:
                select_expr = func.avg(agg_col).label('value')
            else:
                select_expr = func.count('*').label('value')

            chart_stmt = select(timecol, by_col.label('key'), select_expr)
            chart_stmt = chart_stmt.group_by(s_bucket, by_col)
            chart_stmt = chart_stmt.order_by(s_bucket)
            chart_stmt = chart_stmt.limit(agg.limit or 50)

            result = await db.execute(chart_stmt)
            rows = result.all()
            series = {}
            for r in rows:
                t = r[0].isoformat() if r[0] else ''
                k = str(r[1]) if r[1] else 'null'
                v = float(r[2]) if r[2] is not None else 0
                if k not in series:
                    series[k] = []
                series[k].append({"time": t, "value": v})

            return {"series": series, "agg_type": "timechart"}
        except Exception as e:
            log.warning("Timechart aggregation failed: %s", e)
            return {"series": {}, "agg_type": "timechart", "error": str(e)}

    def _parse_span(self, span: str) -> int:
        span = span.strip()
        unit = span[-1]
        val = int(span[:-1]) if len(span) > 1 else 1
        multiplier = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
        return val * multiplier.get(unit, 3600)

    def _pick_model(self, query: SearchQuery) -> Any:
        return Alert

    async def search(
        self, query: SearchQuery, tenant_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        start_ms = time.monotonic()

        results = []
        index_types = set()
        for ff in query.field_filters:
            if ff.field == '_index':
                for t in str(ff.value).split(','):
                    index_types.add(t.strip())

        if not index_types:
            index_types = {'alerts', 'events', 'incidents', 'audit'}

        if 'alerts' in index_types:
            alerts = await self.search_alerts(query, tenant_id, db)
            for a in alerts:
                a['_source_type'] = 'alert'
            results.extend(alerts)

        if 'events' in index_types:
            events = await self.search_events(query, tenant_id, db)
            for e in events:
                e['_source_type'] = 'event'
            results.extend(events)

        if 'incidents' in index_types:
            incidents = await self.search_incidents(query, tenant_id, db)
            for i in incidents:
                i['_source_type'] = 'incident'
            results.extend(incidents)

        if 'audit' in index_types:
            audit = await self.search_audit_logs(query, tenant_id, db)
            for a in audit:
                a['_source_type'] = 'audit'
            results.extend(audit)

        results.sort(key=lambda r: r.get('timestamp', r.get('created_at', '')), reverse=True)

        total = len(results)
        took_ms = int((time.monotonic() - start_ms) * 1000)

        aggregations = None
        if query.aggregation:
            aggregations = await self.aggregate(query.aggregation, query, tenant_id, db)

        if query.limit and len(results) > query.limit:
            results = results[:query.limit]

        return {
            "results": results,
            "total": total,
            "took_ms": took_ms,
            "aggregations": aggregations,
            "warnings": query.warnings,
        }

    def _alert_to_dict(self, a: Alert) -> Dict[str, Any]:
        return {
            "id": a.id,
            "tenant_id": a.tenant_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "description": a.description,
            "status": a.status,
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip,
            "user": a.user,
            "event_type": a.event_type,
            "mitre_tactic": a.mitre_tactic,
            "mitre_technique": a.mitre_technique,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
            "extra_data": a.extra_data,
        }

    def _event_to_dict(self, e: NormalizedEvent) -> Dict[str, Any]:
        return {
            "id": e.id,
            "tenant_id": e.tenant_id,
            "event_type": e.event_type,
            "severity": e.severity,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "source_port": e.source_port,
            "dest_port": e.dest_port,
            "protocol": e.protocol,
            "user": e.user,
            "message": e.message,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "normalized_at": e.normalized_at.isoformat() if e.normalized_at else None,
            "extra_data": e.extra_data,
        }

    def _incident_to_dict(self, i: Incident) -> Dict[str, Any]:
        return {
            "id": i.id,
            "tenant_id": i.tenant_id,
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "risk_score": i.risk_score,
            "description": i.description,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        }

    def _audit_log_to_dict(self, a: AuditLog) -> Dict[str, Any]:
        return {
            "id": a.id,
            "tenant_id": a.tenant_id,
            "user_id": a.user_id,
            "action": a.action,
            "resource_type": a.resource_type,
            "resource_id": a.resource_id,
            "details": a.details,
            "ip_address": a.ip_address,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        }

    def _raw_event_to_dict(self, r: RawEvent) -> Dict[str, Any]:
        return {
            "id": r.id,
            "tenant_id": r.tenant_id,
            "source": r.source,
            "source_type": r.source_type,
            "payload": r.payload,
            "received_at": r.received_at.isoformat() if r.received_at else None,
        }


search_service = SearchService()
