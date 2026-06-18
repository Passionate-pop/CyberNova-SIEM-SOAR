"""
CyberNova — SIEM Search Query Parser
Parses Splunk/Kibana-like query strings into structured SearchQuery objects.
Robust: returns partial results with warnings on malformed input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, List, Optional, Tuple


@dataclass
class FieldFilter:
    field: str
    operator: str  # eq, neq, gt, gte, lt, lte, like, range, cidr
    value: Any


@dataclass
class TimeRange:
    start: Optional[datetime] = None
    end: Optional[datetime] = None


@dataclass
class Aggregation:
    agg_type: str  # count, avg, sum, top, rare, timechart
    field: Optional[str] = None
    by_field: Optional[str] = None
    limit: int = 10
    span: Optional[str] = None


@dataclass
class SearchQuery:
    text_terms: List[str] = field(default_factory=list)
    field_filters: List[FieldFilter] = field(default_factory=list)
    time_range: Optional[TimeRange] = None
    aggregation: Optional[Aggregation] = None
    sort: Optional[str] = None
    order: str = "desc"
    limit: int = 100
    offset: int = 0
    warnings: List[str] = field(default_factory=list)


_RE_FIELD_COMPARE = re.compile(
    r'^([\w.@]+)\s*:\s*(>=|<=|!=|>|<|)\s*(.+)$'
)
_RE_FIELD_BASIC = re.compile(r'^([\w.@]+)\s*:\s*(.+)$')
_RE_RANGE = re.compile(r'^\s*\[(.+?)\s+TO\s+(.+?)\]\s*$')
_RE_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
_RE_WILDCARD = re.compile(r'[*?]')
_RE_QUOTED = re.compile(r'"([^"]*)"')
_RE_TIME_LAST = re.compile(r'^last_(\d+)([mhdw])$')
_RE_TIME_RANGE_DOTDOT = re.compile(
    r'^(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?)'
    r'\.\.'
    r'(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?)$'
)
_RE_AGG_STATS = re.compile(
    r'^\s*stats\s+(?:count|avg|sum)\(([\w.@]+)\)\s+by\s+([\w.@]+)\s*$'
)
_RE_AGG_STATS_NO_FIELD = re.compile(
    r'^\s*stats\s+count\s+by\s+([\w.@]+)\s*$'
)
_RE_AGG_TOP = re.compile(
    r'^\s*(top|rare)\s+([\w.@]+)(?:\s+limit\s*=\s*(\d+))?\s*$'
)
_RE_AGG_TIMECHART = re.compile(
    r'^\s*timechart\s+(?:count|avg|sum)\(([\w.@]+)\)\s+by\s+([\w.@]+)(?:\s+span\s*=\s*([\w]+))?\s*$'
)
_RE_AGG_TIMECHART_COUNT = re.compile(
    r'^\s*timechart\s+count\s+by\s+([\w.@]+)(?:\s+span\s*=\s*([\w]+))?\s*$'
)
_RE_SORT = re.compile(
    r'^\s*sort\s+(-)?\s*([\w.@]+)\s*$'
)


def _parse_datetime(s: str) -> Optional[datetime]:
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1]
    for fmt in (
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M',
        '%Y-%m-%d',
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_time_value(value: str) -> Optional[TimeRange]:
    m = _RE_TIME_LAST.match(value)
    if m:
        num = int(m.group(1))
        unit = m.group(2)
        now = datetime.now(timezone.utc)
        if unit == 'm':
            start = now - timedelta(minutes=num)
        elif unit == 'h':
            start = now - timedelta(hours=num)
        elif unit == 'd':
            start = now - timedelta(days=num)
        elif unit == 'w':
            start = now - timedelta(weeks=num)
        else:
            return None
        return TimeRange(start=start, end=now)

    m = _RE_TIME_RANGE_DOTDOT.match(value)
    if m:
        start = _parse_datetime(m.group(1))
        end = _parse_datetime(m.group(2))
        if start and end:
            return TimeRange(start=start, end=end)

    return None


def _parse_field_value(field: str, value: str) -> FieldFilter:
    if field == '@time':
        return None

    range_m = _RE_RANGE.match(value)
    if range_m:
        return FieldFilter(field=field, operator='range', value=(range_m.group(1).strip(), range_m.group(2).strip()))

    if _RE_CIDR.match(value):
        return FieldFilter(field=field, operator='cidr', value=value)

    if _RE_WILDCARD.search(value):
        return FieldFilter(field=field, operator='like', value=value)

    return FieldFilter(field=field, operator='eq', value=value)


def _parse_aggregation(pipe_part: str) -> Optional[Aggregation]:
    pipe_part = pipe_part.strip()

    m = _RE_AGG_STATS.match(pipe_part)
    if m:
        return Aggregation(agg_type='stats', field=m.group(1), by_field=m.group(2))

    m = _RE_AGG_STATS_NO_FIELD.match(pipe_part)
    if m:
        return Aggregation(agg_type='stats', field=None, by_field=m.group(1))

    m = _RE_AGG_TOP.match(pipe_part)
    if m:
        agg_type = m.group(1)
        field = m.group(2)
        limit = int(m.group(3)) if m.group(3) else 10
        return Aggregation(agg_type=agg_type, field=field, limit=limit)

    m = _RE_AGG_TIMECHART.match(pipe_part)
    if m:
        return Aggregation(agg_type='timechart', field=m.group(1), by_field=m.group(2), span=m.group(3))

    m = _RE_AGG_TIMECHART_COUNT.match(pipe_part)
    if m:
        return Aggregation(agg_type='timechart', field=None, by_field=m.group(1), span=m.group(2))

    return None


def _parse_sort(pipe_part: str) -> Optional[Tuple[Optional[str], str]]:
    m = _RE_SORT.match(pipe_part)
    if m:
        order = 'asc' if m.group(1) else 'desc'
        return m.group(2), order
    return None


def parse_query(query_string: str) -> SearchQuery:
    result = SearchQuery()

    if not query_string or not query_string.strip():
        return result

    remaining = query_string.strip()

    pipe_idx = remaining.find('|')
    if pipe_idx >= 0:
        query_part = remaining[:pipe_idx].strip()
        pipe_part = remaining[pipe_idx + 1:].strip()

        agg = _parse_aggregation(pipe_part)
        if agg:
            result.aggregation = agg
        else:
            sort_result = _parse_sort(pipe_part)
            if sort_result:
                result.sort, result.order = sort_result
            else:
                result.warnings.append(f"Unrecognized pipe clause: {pipe_part}")
    else:
        query_part = remaining

    if not query_part:
        return result

    tokens = _tokenize(query_part)
    negate_next = False
    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.upper() == 'AND':
            negate_next = False
            i += 1
            continue
        elif token.upper() == 'OR':
            negate_next = False
            i += 1
            continue
        elif token.upper() == 'NOT':
            negate_next = True
            i += 1
            continue

        field_match = _RE_FIELD_COMPARE.match(token)
        if field_match:
            field = field_match.group(1)
            comp_op = field_match.group(2)
            value = field_match.group(3).strip()

            value = _strip_quotes(value)

            if field == '@time':
                tr = _parse_time_value(value)
                if tr:
                    result.time_range = tr
                else:
                    result.warnings.append(f"Could not parse @time value: {value}")
                i += 1
                continue

            if comp_op in ('>=', '<=', '>', '<', '!='):
                op_map = {'>=': 'gte', '<=': 'lte', '>': 'gt', '<': 'lt', '!=': 'neq'}
                ff = FieldFilter(field=field, operator=op_map[comp_op], value=value)
                if negate_next:
                    if ff.operator == 'eq':
                        ff.operator = 'neq'
                    else:
                        result.warnings.append(f"Cannot negate comparison filter: {token}")
                    negate_next = False
                result.field_filters.append(ff)
                i += 1
                continue

            ff = _parse_field_value(field, value)
            if ff is not None:
                if negate_next:
                    ff.operator = 'neq' if ff.operator == 'eq' else ff.operator
                    negate_next = False
                result.field_filters.append(ff)
            i += 1
            continue

        field_match = _RE_FIELD_BASIC.match(token)
        if field_match:
            field = field_match.group(1)
            value = field_match.group(2).strip()
            value = _strip_quotes(value)

            if field == '@time':
                tr = _parse_time_value(value)
                if tr:
                    result.time_range = tr
                else:
                    result.warnings.append(f"Could not parse @time value: {value}")
                i += 1
                continue

            ff = _parse_field_value(field, value)
            if ff is not None:
                if negate_next:
                    ff.operator = 'neq' if ff.operator == 'eq' else ff.operator
                    negate_next = False
                result.field_filters.append(ff)
            i += 1
            continue

        text = _strip_quotes(token)
        if negate_next:
            result.field_filters.append(FieldFilter(field='_text', operator='neq', value=text))
            negate_next = False
        else:
            result.text_terms.append(text)
        i += 1

    return result


def _tokenize(text: str) -> List[str]:
    tokens = []
    i = 0
    while i < len(text):
        if text[i] in (' ', '\t'):
            i += 1
            continue

        if text[i] == '"':
            end = text.find('"', i + 1)
            if end == -1:
                tokens.append(text[i:])
                break
            tokens.append(text[i:end + 1])
            i = end + 1
            continue

        if text[i] == '(' or text[i] == ')':
            tokens.append(text[i])
            i += 1
            continue

        end = i
        while end < len(text) and text[end] not in (' ', '\t', '"', '(', ')'):
            end += 1
        tokens.append(text[i:end])
        i = end

    return tokens

def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


class QueryParser:
    """Query parser singleton wrapping parse_query and SearchQuery."""

    def parse(self, query_string: str) -> SearchQuery:
        return parse_query(query_string)

    def tokenize(self, text: str) -> List[str]:
        return _tokenize(text)


# Module-level singleton for clean API access
query_parser = QueryParser()

