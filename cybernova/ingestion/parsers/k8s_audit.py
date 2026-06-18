"""
CyberNova — Kubernetes API Server Audit Log Parser
Parses K8s audit Event JSON (audit.k8s.io/v1).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.k8s_audit")

SENSITIVE_RESOURCES = {
    "secrets", "secret",
    "configmaps", "configmap",
    "serviceaccounts", "serviceaccount",
    "rolebindings", "rolebinding",
    "clusterrolebindings", "clusterrolebinding",
    "roles", "role",
    "clusterroles", "clusterrole",
    "podsecuritypolicies", "podsecuritypolicy",
    "networkpolicies", "networkpolicy",
    "tokenreviews", "tokenreview",
    "subjectaccessreviews", "subjectaccessreview",
    "selfsubjectaccessreviews", "selfsubjectaccessreview",
    "selfsubjectrulesreviews", "selfsubjectrulesreview",
    "localsubjectaccessreviews", "localsubjectaccessreview",
}

PRIVILEGED_VERBS = {"create", "update", "patch", "delete", "deletecollection"}

EXEC_VERBS = {"create"}
EXEC_RESOURCES = {"pods", "pod"}

SENSITIVE_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease",
    "istio-system", "knative-serving", "cert-manager",
    "velero", "monitoring", "logging",
}

SYSTEM_GROUPS = {"system:masters", "system:admin", "system:node", "system:node-proxier"}

DANGEROUS_VERB_RESOURCE = {
    ("create", "pods"): "pod_created",
    ("delete", "pods"): "pod_deleted",
    ("create", "deployments"): "deployment_created",
    ("delete", "deployments"): "deployment_deleted",
    ("create", "services"): "service_created",
    ("delete", "services"): "service_deleted",
    ("create", "namespaces"): "namespace_created",
    ("delete", "namespaces"): "namespace_deleted",
    ("create", "secrets"): "secret_created",
    ("delete", "secrets"): "secret_deleted",
    ("create", "configmaps"): "configmap_created",
    ("delete", "configmaps"): "configmap_deleted",
    ("create", "rolebindings"): "rolebinding_created",
    ("delete", "rolebindings"): "rolebinding_deleted",
    ("create", "clusterroles"): "clusterrole_created",
    ("delete", "clusterroles"): "clusterrole_deleted",
    ("create", "clusterrolebindings"): "clusterrolebinding_created",
    ("delete", "clusterrolebindings"): "clusterrolebinding_deleted",
    ("create", "serviceaccounts"): "serviceaccount_created",
    ("delete", "serviceaccounts"): "serviceaccount_deleted",
    ("create", "persistentvolumes"): "pv_created",
    ("delete", "persistentvolumes"): "pv_deleted",
    ("create", "persistentvolumeclaims"): "pvc_created",
    ("delete", "persistentvolumeclaims"): "pvc_deleted",
    ("create", "nodes"): "node_created",
    ("delete", "nodes"): "node_deleted",
}

VERB_EVENT_TYPE = {
    "get": "k8s_read",
    "list": "k8s_list",
    "watch": "k8s_watch",
    "create": "k8s_create",
    "update": "k8s_update",
    "patch": "k8s_patch",
    "delete": "k8s_delete",
    "deletecollection": "k8s_delete_collection",
    "proxy": "k8s_proxy",
    "connect": "k8s_connect",
}

STAGE_SEVERITY_BOOST = {
    "ResponseComplete": 0,
    "ResponseStarted": 0,
    "Panic": 2,
}

HTTP_SEVERITY = {
    200: "info", 201: "info", 202: "info", 204: "info",
    301: "info", 302: "info",
    400: "medium", 401: "high", 403: "high", 404: "low",
    405: "medium", 409: "medium", 422: "medium", 429: "medium",
    500: "high", 502: "high", 503: "high", 504: "high",
}


def _resolver_user(user_obj: Any) -> Dict[str, Any]:
    if not isinstance(user_obj, dict):
        return {"username": "", "uid": "", "groups": [], "extra": {}}
    return {
        "username": user_obj.get("username", ""),
        "uid": user_obj.get("uid", ""),
        "groups": user_obj.get("groups", []),
        "extra": user_obj.get("extra", {}),
    }


def _resolve_object_ref(obj_ref: Any) -> Dict[str, str]:
    if not isinstance(obj_ref, dict):
        return {"resource": "", "namespace": "", "name": "", "api_group": "", "api_version": "", "subresource": ""}
    return {
        "resource": obj_ref.get("resource", ""),
        "namespace": obj_ref.get("namespace", ""),
        "name": obj_ref.get("name", ""),
        "api_group": obj_ref.get("apiGroup", ""),
        "api_version": obj_ref.get("apiVersion", ""),
        "subresource": obj_ref.get("subresource", ""),
    }


def _get_request_uri_verb(request_uri: str) -> str:
    if "/exec" in request_uri:
        return "exec"
    if "/attach" in request_uri:
        return "attach"
    if "/portforward" in request_uri or "/port-forward" in request_uri:
        return "portforward"
    if "/proxy" in request_uri:
        return "proxy"
    if "/log" in request_uri:
        return "log"
    return ""


def parse_k8s_audit_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            try:
                raw = json.loads(raw)
            except (ValueError, json.JSONDecodeError) as exc:
                log.debug("K8s audit JSON decode failed: %s", exc)
                return {"event_type": "k8s_audit", "severity": "info", "message": raw}
        else:
            return {"event_type": "k8s_audit", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "k8s_audit", "severity": "info", "message": str(raw)}

    kind = raw.get("kind", "")
    if kind not in ("Event", "event", "AuditEvent"):
        return {"event_type": "k8s_audit", "severity": "info", "message": str(raw), "metadata": {"kind": kind}}

    verb = raw.get("verb", "").lower()
    stage = raw.get("stage", "")
    level = raw.get("level", "Metadata")
    audit_id = raw.get("auditID", raw.get("auditId", raw.get("id", "")))
    request_uri = raw.get("requestURI", raw.get("requestUri", ""))

    user_info = _resolver_user(raw.get("user", {}))
    impersonated_user = raw.get("impersonatedUser", {})
    source_ips = raw.get("sourceIPs", raw.get("sourceIps", []))
    user_agent = raw.get("userAgent", raw.get("user_agent", ""))

    obj_ref = _resolve_object_ref(raw.get("objectRef", raw.get("objectRef", {})))
    resource = obj_ref["resource"]
    namespace = obj_ref["namespace"]
    name = obj_ref["name"]
    api_group = obj_ref["api_group"]
    subresource = obj_ref["subresource"]

    resp_status = raw.get("responseStatus", raw.get("responseStatus", {}))
    if isinstance(resp_status, dict):
        resp_code = resp_status.get("code", 0)
        resp_reason = resp_status.get("reason", resp_status.get("status", ""))
    else:
        resp_code = 0
        resp_reason = ""

    raw.get("responseStatus", raw.get("responseStatus", {}))

    annotations = raw.get("annotations", raw.get("Annotations", {}))

    ts_req = raw.get("requestReceivedTimestamp", raw.get("requestReceivedTimestamp", ""))
    ts_stage = raw.get("stageTimestamp", raw.get("stageTimestamp", ""))

    timestamp = ts_req or ts_stage
    if isinstance(timestamp, (int, float)):
        from datetime import datetime, timezone
        timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()

    base_event_type = VERB_EVENT_TYPE.get(verb, "k8s_unknown")
    specific_key = (verb, resource)
    if specific_key in DANGEROUS_VERB_RESOURCE:
        specific_type = "k8s_" + DANGEROUS_VERB_RESOURCE[specific_key]
    else:
        specific_type = f"{base_event_type}_{resource}" if resource else base_event_type

    if not resource and "namespaces" in request_uri and verb == "create":
        specific_type = "k8s_namespace_created"

    if subresource:
        pass

    exec_type = _get_request_uri_verb(request_uri)
    if exec_type == "exec":
        specific_type = "k8s_pod_exec"
    elif exec_type == "attach":
        specific_type = "k8s_pod_attach"
    elif exec_type == "portforward":
        specific_type = "k8s_pod_portforward"
    elif exec_type == "proxy":
        specific_type = "k8s_resource_proxy"

    severity = HTTP_SEVERITY.get(resp_code, "medium")
    if verb in ("delete", "deletecollection"):
        severity = "medium"
    if resp_code >= 500:
        severity = "high"
    if resp_code in (401, 403):
        if resource in SENSITIVE_RESOURCES:
            severity = "critical"

    if verb in ("create", "update", "patch") and resource in SENSITIVE_RESOURCES:
        if severity in ("info", "low"):
            severity = "medium"

    if verb in ("create", "delete") and namespace in SENSITIVE_NAMESPACES:
        severity = "high"

    user_groups = user_info.get("groups", [])
    if isinstance(user_groups, list) and any(g in SYSTEM_GROUPS for g in user_groups):
        if verb in PRIVILEGED_VERBS:
            if severity in ("info", "low", "medium"):
                severity = "medium"
            if verb == "delete" and resource:
                severity = "high"

    if subresource in ("exec", "attach", "portforward", "log"):
        severity = "high"

    if stage == "Panic":
        severity = "critical"

    if verb in ("get", "list") and resource in SENSITIVE_RESOURCES:
        severity = "medium"

    username = user_info.get("username", "")
    if impersonated_user:
        imp_user = impersonated_user.get("username", "")
        impersonated_user.get("groups", [])
        severity = "high"
        username = f"{username} (impersonating {imp_user})"

    message_parts = [
        f"K8s audit: {verb}",
        f"{resource}/{name}" if name else resource,
        f"ns={namespace}" if namespace else "",
        f"by {username}" if username else "",
        f"code={resp_code}" if resp_code else "",
    ]
    message = " ".join(p for p in message_parts if p)

    result = {
        "event_type": specific_type,
        "severity": severity,
        "source_ip": source_ips[0] if source_ips else "",
        "user": username,
        "timestamp": timestamp,
        "message": message,
        "metadata": {
            "audit_id": audit_id,
            "verb": verb,
            "stage": stage,
            "level": level,
            "request_uri": request_uri,
            "resource": resource,
            "namespace": namespace,
            "name": name,
            "api_group": api_group,
            "subresource": subresource,
            "response_code": resp_code,
            "response_reason": resp_reason,
            "user_agent": user_agent,
            "source_ips": source_ips,
            "user_uid": user_info.get("uid", ""),
            "user_groups": user_groups,
            "impersonated_user": impersonated_user.get("username", "") if impersonated_user else "",
            "impersonated_groups": impersonated_user.get("groups", []) if impersonated_user else [],
            "annotations": annotations if isinstance(annotations, dict) else {},
        },
    }

    return result


PARSER_REGISTRY_KEY = "k8s_audit"
