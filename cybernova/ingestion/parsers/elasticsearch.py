"""
CyberNova — Elasticsearch Audit / Query Log Parser
Parses Elasticsearch audit logs, search/query logs, and security events.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.elasticsearch")

ES_EVENT_ACTIONS = {
    "indices:data/read/search": "es_search",
    "indices:data/read/msearch": "es_msearch",
    "indices:data/read/scroll": "es_scroll",
    "indices:data/write/index": "es_index",
    "indices:data/write/bulk": "es_bulk",
    "indices:data/write/update": "es_update",
    "indices:data/write/delete": "es_delete",
    "indices:admin/create": "es_index_create",
    "indices:admin/delete": "es_index_delete",
    "indices:admin/mapping/put": "es_mapping_update",
    "indices:admin/settings/update": "es_settings_update",
    "indices:admin/refresh": "es_refresh",
    "indices:admin/flush": "es_flush",
    "cluster:admin/snapshot/create": "es_snapshot_create",
    "cluster:admin/snapshot/delete": "es_snapshot_delete",
    "cluster:admin/snapshot/restore": "es_snapshot_restore",
    "cluster:admin/reroute": "es_reroute",
    "cluster:monitor/health": "es_health",
    "cluster:monitor/stats": "es_stats",
    "cluster:admin/xpack/security/user/put": "es_user_create",
    "cluster:admin/xpack/security/user/delete": "es_user_delete",
    "cluster:admin/xpack/security/role/put": "es_role_create",
    "cluster:admin/xpack/security/role/delete": "es_role_delete",
}

DANGEROUS_ACTIONS = {
    "indices:data/write/delete", "indices:admin/delete",
    "cluster:admin/snapshot/delete",
    "cluster:admin/xpack/security/user/put",
    "cluster:admin/xpack/security/user/delete",
    "cluster:admin/xpack/security/role/put",
    "cluster:admin/xpack/security/role/delete",
    "cluster:admin/reroute",
}

SENSITIVE_INDICES = {
    ".security", ".kibana", ".elasticsearch", ".monitoring",
    ".watches", ".triggered_watches", ".alerting",
    "logstash-", "filebeat-", "metricbeat-", "auditbeat-",
    "winlogbeat-", "packetbeat-", "heartbeat-",
    "apm-", "endpoint-",
}


def _classify_es_severity(action: str, index: str, status: int) -> str:
    if action in DANGEROUS_ACTIONS:
        return "high"
    if status >= 500:
        return "medium"
    if status == 403:
        return "high"
    if status == 401:
        return "medium"
    for prefix in SENSITIVE_INDICES:
        if index and index.startswith(prefix):
            return "medium"
    writes = {"index", "update", "bulk", "delete"}
    action_short = action.split("/")[-1] if "/" in action else action
    if action_short in writes:
        return "medium"
    return "low"


def parse_elasticsearch_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("ES JSON parse failed: %s", exc)
            return {"event_type": "elasticsearch", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "elasticsearch", "severity": "info", "message": str(raw)}

    layer = raw.get("layer", raw.get("type", "unknown"))
    event_action = raw.get("action", raw.get("event_action", raw.get("event_type", "")))
    mapped_action = ES_EVENT_ACTIONS.get(event_action, f"es_{event_action.replace(':', '_')}")

    status = raw.get("status", raw.get("http_status", raw.get("response_code", 0)))
    if isinstance(status, str):
        try:
            status = int(status)
        except (ValueError, TypeError):
            status = 0
    request = raw.get("request", raw.get("url", raw.get("path", "")))
    method = raw.get("method", raw.get("http_method", raw.get("request_method", "")))
    index = raw.get("indices", raw.get("index", raw.get("resource", "")))
    if isinstance(index, list):
        index = ",".join(index)
    cluster_name = raw.get("cluster_name", raw.get("cluster", ""))

    principal = raw.get("principal", raw.get("user", raw.get("authenticated_user", raw.get("auth_user", ""))))

    source_ip = raw.get("source_ip", raw.get("remote_address", raw.get("origin_address", raw.get("client_ip", ""))))
    if source_ip and ":" in source_ip and not source_ip.count(".") == 3:
        if "/" in source_ip:
            source_ip = source_ip.split("/")[0]

    ts = raw.get("@timestamp", raw.get("timestamp", raw.get("time", raw.get("event_time", ""))))

    severity = _classify_es_severity(event_action, index, status)

    body = raw.get("body", raw.get("request_body", raw.get("query", "")))
    if isinstance(body, dict):
        body_str = str(body)[:500]
    elif isinstance(body, str):
        body_str = body[:500]
    else:
        body_str = ""

    took = raw.get("took", raw.get("execution_time", raw.get("duration", 0)))
    total_shards = raw.get("total_shards", raw.get("shards", {}).get("total", 0))
    failed_shards = raw.get("failed_shards", raw.get("shards", {}).get("failed", 0))

    return {
        "event_type": "elasticsearch",
        "event_action": mapped_action,
        "action_raw": event_action,
        "severity": severity,
        "status_code": status,
        "method": method,
        "index": index,
        "cluster_name": cluster_name,
        "user": principal,
        "source_ip": source_ip,
        "timestamp": ts,
        "request": request,
        "message": f"ES {mapped_action} on {index or 'cluster'} by {principal or 'unknown'} -> {status}",
        "metadata": {
            "took_ms": took,
            "total_shards": total_shards,
            "failed_shards": failed_shards,
            "query_body": body_str,
            "layer": layer,
            "node_name": raw.get("node_name", ""),
            "request_id": raw.get("request_id", raw.get("trace_id", "")),
            "transport_type": raw.get("transport_type", raw.get("type", "")),
        },
    }


PARSER_REGISTRY_KEY = "elasticsearch"
