"""
CyberNova — Kubernetes Audit / Event Log Parser
Parses Kubernetes API server audit logs and cluster events.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.kubernetes")

K8S_VERBS = {
    "create": "create", "update": "update", "patch": "patch",
    "delete": "delete", "deletecollection": "delete_collection",
    "get": "read", "list": "read", "watch": "read",
    "exec": "exec", "connect": "connect", "proxy": "proxy",
}

PRIVILEGED_RESOURCES = {
    "pods/exec", "pods/attach", "pods/portforward",
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "secrets", "configmaps", "serviceaccounts",
    "nodes", "persistentvolumes",
    "podsecuritypolicies", "networkpolicies",
    "customresourcedefinitions", "validatingwebhookconfigurations",
    "mutatingwebhookconfigurations",
}

K8S_EVENT_REASONS = {
    "Failed": "high", "Killing": "high", "FailedMount": "high",
    "FailedCreate": "medium", "FailedDelete": "medium",
    "Unhealthy": "medium", "ProbeWarning": "medium",
    "ExceededGracePeriod": "medium",
    "NodeNotReady": "high", "NodeReady": "low",
    "Rebooted": "medium",
    "BackOff": "medium", "CrashLoopBackOff": "high",
    "Error": "high", "OOMKilling": "high",
}


def _parse_object_ref(raw: Dict[str, Any]) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {
        "resource": raw.get("resource", ""),
        "api_group": raw.get("apiGroup", raw.get("api_group", "")),
        "namespace": raw.get("namespace", ""),
        "name": raw.get("name", ""),
        "uid": raw.get("uid", ""),
    }


def _parse_user_info(raw: Dict[str, Any]) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    result: Dict[str, str] = {}
    result["username"] = raw.get("username", "")
    result["uid"] = raw.get("uid", "")
    groups = raw.get("groups", [])
    if groups:
        result["groups"] = ",".join(groups)
    extra = raw.get("extra", {})
    if extra:
        result["extra"] = str(extra)
    return result


def _classify_k8s_severity(verb: str, resource: str, response_code: int) -> str:
    base_key = f"{resource.split('/')[0]}/" if "/" in resource else resource
    if base_key in PRIVILEGED_RESOURCES:
        if verb in ("delete", "update", "patch"):
            return "high"
        return "medium"
    if verb in ("delete", "create"):
        return "medium"
    if response_code >= 500:
        return "medium"
    if response_code == 403:
        return "high"
    if response_code == 401:
        return "medium"
    return "info"


def parse_kubernetes_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("K8s JSON parse failed: %s", exc)
            return {"event_type": "kubernetes", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "kubernetes", "severity": "info", "message": str(raw)}

    kind = raw.get("kind", raw.get("type", ""))
    if kind in ("Event", "event"):
        return _parse_k8s_event(raw)
    return _parse_k8s_audit(raw)


def _parse_k8s_audit(raw: Dict[str, Any]) -> Dict[str, Any]:
    verb = raw.get("verb", "").lower()
    mapped_verb = K8S_VERBS.get(verb, verb)
    object_ref_raw = raw.get("objectRef", raw.get("object_ref", {}))
    object_ref = _parse_object_ref(object_ref_raw if isinstance(object_ref_raw, dict) else {})
    user_raw = raw.get("user", raw.get("userInfo", raw.get("user_info", {})))
    user_info = _parse_user_info(user_raw if isinstance(user_raw, dict) else {})

    response_code = raw.get("responseStatus", raw.get("response_status", {}))
    if isinstance(response_code, dict):
        status_code = response_code.get("code", 0)
        status_reason = response_code.get("reason", "")
        status_message = response_code.get("status", "")
    else:
        status_code = raw.get("status_code", 0)
        status_reason = raw.get("reason", "")
        status_message = raw.get("status_message", "")

    request_uri = raw.get("requestURI", raw.get("request_uri", ""))
    source_ips = raw.get("sourceIPs", raw.get("source_ips", []))
    if isinstance(source_ips, list) and source_ips:
        source_ip = source_ips[0]
    else:
        source_ip = raw.get("source_ip", "")

    stage = raw.get("stage", "")
    level = raw.get("level", "Metadata")

    resource = object_ref.get("resource", raw.get("resource", ""))
    namespace = object_ref.get("namespace", raw.get("namespace", ""))
    name = object_ref.get("name", raw.get("name", ""))

    severity = _classify_k8s_severity(verb, resource, status_code)

    request_object = raw.get("requestObject", raw.get("request_object", {}))
    response_object = raw.get("responseObject", raw.get("response_object", {}))

    ts = raw.get("requestReceivedTimestamp", raw.get("timestamp", raw.get("time", "")))

    return {
        "event_type": "kubernetes_audit",
        "severity": severity,
        "verb": verb,
        "mapped_verb": mapped_verb,
        "resource": resource,
        "namespace": namespace,
        "name": name,
        "user": user_info.get("username", ""),
        "user_uid": user_info.get("uid", ""),
        "source_ip": source_ip,
        "timestamp": ts,
        "status_code": status_code,
        "status_reason": status_reason,
        "stage": stage,
        "audit_level": level,
        "request_uri": request_uri,
        "message": f"K8s {verb} {resource}/{name} in {namespace or 'cluster'} by {user_info.get('username', 'unknown')}",
        "metadata": {
            "user_groups": user_info.get("groups", ""),
            "object_uid": object_ref.get("uid", ""),
            "api_group": object_ref.get("api_group", ""),
            "status_message": status_message,
            "has_request_object": bool(request_object),
            "has_response_object": bool(response_object),
        },
    }


def _parse_k8s_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    event_type = raw.get("type", "Normal")
    reason = raw.get("reason", "")
    message = raw.get("message", "")
    involved = raw.get("involvedObject", raw.get("regarding", {}))
    if isinstance(involved, dict):
        resource = involved.get("kind", "") + "/" + involved.get("name", "")
        namespace = involved.get("namespace", "")
    else:
        resource = raw.get("resource", "")
        namespace = raw.get("namespace", "")

    severity = K8S_EVENT_REASONS.get(reason, "medium" if event_type == "Warning" else "low")

    source = raw.get("source", {})
    if isinstance(source, dict):
        host = source.get("host", source.get("component", ""))
    else:
        host = ""

    count = raw.get("count", 1)
    first_ts = raw.get("firstTimestamp", raw.get("first_timestamp", ""))
    last_ts = raw.get("lastTimestamp", raw.get("last_timestamp", ""))
    ts = last_ts or first_ts

    return {
        "event_type": "kubernetes_event",
        "severity": severity,
        "event_reason": reason,
        "event_type_k8s": event_type,
        "resource": resource,
        "namespace": namespace,
        "message": message,
        "timestamp": ts,
        "count": count,
        "metadata": {
            "host": host,
            "first_timestamp": first_ts,
            "component": source.get("component", "") if isinstance(source, dict) else "",
        },
    }


PARSER_REGISTRY_KEY = "kubernetes"
