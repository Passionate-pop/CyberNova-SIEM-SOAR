"""
CyberNova — MongoDB Audit Log Parser
Parses MongoDB audit logs and slow query logs.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.mongodb")

MONGO_ACTIONS = {
    "authenticate": "mongo_auth",
    "renameCollection": "mongo_rename",
    "dropDatabase": "mongo_drop_db",
    "dropCollection": "mongo_drop_collection",
    "createCollection": "mongo_create_collection",
    "createIndex": "mongo_create_index",
    "dropIndex": "mongo_drop_index",
    "createUser": "mongo_create_user",
    "dropUser": "mongo_drop_user",
    "updateUser": "mongo_update_user",
    "grantRolesToUser": "mongo_grant_role",
    "revokeRolesFromUser": "mongo_revoke_role",
    "grantRolesToRole": "mongo_grant_role",
    "revokeRolesFromRole": "mongo_revoke_role",
    "createRole": "mongo_create_role",
    "dropRole": "mongo_drop_role",
    "updateRole": "mongo_update_role",
    "shutdown": "mongo_shutdown",
    "setParameter": "mongo_set_parameter",
    "enableSharding": "mongo_enable_sharding",
    "addShard": "mongo_add_shard",
    "removeShard": "mongo_remove_shard",
    "replSetReconfig": "mongo_reconfig",
    "replSetInitiate": "mongo_repl_init",
    "appendOplogNote": "mongo_oplog",
    "find": "mongo_query",
    "insert": "mongo_insert",
    "update": "mongo_update",
    "delete": "mongo_delete",
    "aggregate": "mongo_aggregate",
    "count": "mongo_count",
    "distinct": "mongo_distinct",
    "mapReduce": "mongo_map_reduce",
    "getMore": "mongo_cursor",
    "killCursors": "mongo_kill_cursors",
    "listCollections": "mongo_list_collections",
    "listIndexes": "mongo_list_indexes",
    "listDatabases": "mongo_list_databases",
    "collStats": "mongo_coll_stats",
    "dbStats": "mongo_db_stats",
    "serverStatus": "mongo_server_status",
    "buildInfo": "mongo_build_info",
}

DESTRUCTIVE_ACTIONS = {
    "mongo_drop_db", "mongo_drop_collection", "mongo_drop_index",
    "mongo_drop_user", "mongo_drop_role",
    "mongo_rename", "mongo_shutdown",
    "mongo_reconfig",
}

ADMIN_ACTIONS = {
    "mongo_create_user", "mongo_create_role",
    "mongo_grant_role", "mongo_revoke_role",
    "mongo_update_user", "mongo_update_role",
    "mongo_set_parameter", "mongo_enable_sharding",
    "mongo_add_shard", "mongo_remove_shard",
    "mongo_repl_init",
}

SENSITIVE_COLLECTIONS = {
    "system.users", "system.roles", "system.version",
    "system.keys", "system.profile",
}


def _classify_mongo_severity(action: str, ns: str) -> str:
    if action in DESTRUCTIVE_ACTIONS:
        return "high"
    if action in ADMIN_ACTIONS:
        return "medium"
    if ns and any(ns.endswith(sc) for sc in SENSITIVE_COLLECTIONS):
        return "medium"
    cmd = action.split("_")[-1] if "_" in action else action
    if cmd in ("find", "insert", "update", "delete", "aggregate"):
        return "medium"
    return "low"


def parse_mongodb_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("MongoDB JSON parse failed: %s", exc)
            return {"event_type": "mongodb", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "mongodb", "severity": "info", "message": str(raw)}

    log_type = raw.get("atype", raw.get("action", raw.get("type", raw.get("msg", ""))))
    mapped_action = MONGO_ACTIONS.get(log_type, f"mongo_{log_type}")

    ts = raw.get("ts", raw.get("timestamp", raw.get("time", raw.get("@timestamp", ""))))
    local_ip = raw.get("local", raw.get("ip", raw.get("host", raw.get("hostname", ""))))
    remote = raw.get("remote", raw.get("client", raw.get("source_ip", raw.get("addr", ""))))

    param = raw.get("param", raw.get("params", raw.get("attr", raw)))
    if isinstance(param, dict):
        user = param.get("user", param.get("username", ""))
        ns = param.get("ns", param.get("namespace", param.get("db", "")))
        collection = ""
        if ns and "." in ns:
            parts = ns.split(".", 1)
            db = parts[0]
            collection = parts[1]
        else:
            db = ns or ""
            collection = ""
        query = param.get("query", param.get("filter", {}))
        docs = param.get("documents", param.get("document", {}))
        duration = param.get("durationMillis", param.get("millis", param.get("duration", 0)))
        docs_returned = param.get("nreturned", param.get("docs_returned", 0))
        cursor_id = param.get("cursorid", param.get("cursor_id", 0))
        roles = param.get("roles", [])
        if isinstance(roles, list):
            roles = ", ".join(roles)
        key_name = param.get("key", param.get("name", ""))
    else:
        user = raw.get("user", raw.get("username", ""))
        ns = raw.get("db", raw.get("namespace", ""))
        db = ns if ns else ""
        collection = raw.get("collection", "")
        query = raw.get("query", {})
        docs = {}
        duration = raw.get("durationMillis", raw.get("millis", 0))
        docs_returned = 0
        cursor_id = 0
        roles = ""
        key_name = ""

    severity = _classify_mongo_severity(mapped_action, ns)

    result_ns = f"{db}.{collection}" if db and collection else ns

    return {
        "event_type": "mongodb",
        "action": mapped_action,
        "action_raw": log_type,
        "severity": severity,
        "user": user,
        "source_ip": remote,
        "hostname": local_ip,
        "database": db,
        "collection": collection,
        "namespace": result_ns,
        "timestamp": ts,
        "duration_ms": duration,
        "docs_returned": docs_returned,
        "message": f"MongoDB {mapped_action} on {result_ns or 'unknown'} by {user or 'unknown'}",
        "metadata": {
            "query": str(query)[:500] if query else "",
            "documents": str(docs)[:500] if docs else "",
            "cursor_id": cursor_id,
            "roles": roles,
            "index_name": key_name,
            "log_type": log_type,
        },
    }


PARSER_REGISTRY_KEY = "mongodb"
