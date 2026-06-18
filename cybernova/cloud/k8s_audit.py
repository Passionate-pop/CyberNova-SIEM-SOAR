from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cybernova.pipeline.unified_pipeline import unified_pipeline

log = logging.getLogger("cybernova.cloud.k8s_audit")

K8S_HIGH_RISK_VERBS = {"create", "update", "patch", "delete", "impersonate", "escalate", "bind"}
K8S_HIGH_RISK_RESOURCES = {
    "secrets", "configmaps", "roles", "clusterroles", "rolebindings",
    "clusterrolebindings", "serviceaccounts", "pods/exec", "pods/attach",
    "pods/portforward", "nodes", "persistentvolumes",
}
K8S_SENSITIVE_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class KubernetesAuditIngestion:
    """
    Ingests Kubernetes audit log events (from API server audit webhook or file).
    Normalizes into CyberNova pipeline for detection and correlation with
    cloud and network events.
    """

    def __init__(self):
        self._stats = {"k8s_events_ingested": 0, "errors": 0}

    async def ingest_audit_event(self, raw_event: Dict[str, Any], tenant_id: str = "default") -> str:
        normalized = self._normalize_k8s_audit(raw_event)
        event_id = await unified_pipeline.ingest(
            raw_data=normalized,
            tenant_id=tenant_id,
            source="kubernetes_audit",
            source_type="k8s_audit_event",
        )
        self._stats["k8s_events_ingested"] += 1
        return event_id

    async def ingest_audit_batch(self, events: List[Dict[str, Any]], tenant_id: str = "default") -> int:
        count = 0
        for event in events:
            try:
                await self.ingest_audit_event(event, tenant_id)
                count += 1
            except Exception as e:
                log.warning("K8s audit ingest error: %s", e)
                self._stats["errors"] += 1
        return count

    async def ingest_from_webhook(self, body: Dict[str, Any], tenant_id: str = "default") -> Dict[str, Any]:
        items = body.get("items", [])
        count = await self.ingest_audit_batch(items, tenant_id)
        return {"accepted": count, "total": len(items)}

    def _normalize_k8s_audit(self, event: Dict[str, Any]) -> Dict[str, Any]:
        verb = event.get("verb", "")
        object_ref = event.get("objectRef", {}) or {}
        resource = object_ref.get("resource", "")
        namespace = object_ref.get("namespace", "")
        name = object_ref.get("name", "")
        user = event.get("user", {}) or {}
        source_ips = event.get("sourceIPs", [])
        response_status = event.get("responseStatus", {}) or {}
        stage = event.get("stage", "")

        severity = "info"
        risk_score = 10

        if response_status.get("code", 0) >= 400:
            severity = "high"
            risk_score = 70

        if verb in K8S_HIGH_RISK_VERBS:
            if severity != "high":
                severity = "medium"
                risk_score = 40

        if resource in K8S_HIGH_RISK_RESOURCES:
            if verb in K8S_HIGH_RISK_VERBS:
                severity = "high"
                risk_score = 75

        if namespace in K8S_SENSITIVE_NAMESPACES and verb in ("create", "update", "patch", "delete"):
            severity = "critical"
            risk_score = 90

        if verb == "impersonate":
            severity = "critical"
            risk_score = 95

        annotations = event.get("annotations", {}) or {}

        return {
            "event_type": "k8s_audit_event",
            "severity": severity,
            "source_ip": source_ips[0] if source_ips else "",
            "user": user.get("username", ""),
            "user_groups": user.get("groups", []),
            "user_uid": user.get("uid", ""),
            "impersonated_user": user.get("impersonatedUser", {}),
            "verb": verb,
            "resource": resource,
            "resource_name": name,
            "namespace": namespace,
            "api_group": object_ref.get("apiGroup", ""),
            "api_version": object_ref.get("apiVersion", ""),
            "subresource": object_ref.get("subresource", ""),
            "request_uri": event.get("requestURI", ""),
            "response_code": response_status.get("code", 0),
            "response_reason": response_status.get("reason", ""),
            "response_status": response_status.get("status", ""),
            "stage": stage,
            "annotations": annotations,
            "request_received_timestamp": event.get("requestReceivedTimestamp", ""),
            "stage_timestamp": event.get("stageTimestamp", ""),
            "audit_id": event.get("auditID", ""),
            "level": event.get("level", ""),
            "message": f"K8s {verb} {resource}/{name} by {user.get('username', 'unknown')} in {namespace or 'cluster-scope'} [{stage}]",
            "risk_score": risk_score,
            "timestamp": event.get("requestReceivedTimestamp", datetime.now(timezone.utc).isoformat()),
            "raw": event,
        }

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def get_detection_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "K8s Secret Access",
                "description": "Access to Kubernetes secrets detected",
                "rule": "resource == 'secrets'",
                "severity": "high",
                "risk_score": 75,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials (T1552)",
            },
            {
                "name": "K8s Privilege Escalation",
                "description": "Attempt to escalate privileges via RBAC modification",
                "rule": "verb in ('create', 'update', 'patch') and resource in ('roles', 'clusterroles', 'rolebindings', 'clusterrolebindings')",
                "severity": "critical",
                "risk_score": 90,
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism (T1548)",
            },
            {
                "name": "K8s Pod Exec",
                "description": "Exec into running pod detected",
                "rule": "verb == 'create' and subresource == 'exec'",
                "severity": "high",
                "risk_score": 80,
                "mitre_tactic": "Execution",
                "mitre_technique": "Container Administration Command (T1609)",
            },
            {
                "name": "K8s Impersonation",
                "description": "User impersonation detected in Kubernetes audit",
                "rule": "verb == 'impersonate'",
                "severity": "critical",
                "risk_score": 95,
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Valid Accounts (T1078)",
            },
            {
                "name": "K8s API Access Failure",
                "description": "Repeated API access failures may indicate scanning",
                "rule": "response_code >= 401",
                "severity": "medium",
                "risk_score": 40,
                "mitre_tactic": "Discovery",
                "mitre_technique": "Container and Resource Discovery (T1613)",
            },
            {
                "name": "K8s Sensitive Namespace Modification",
                "description": "Modification to kube-system or other sensitive namespace",
                "rule": "namespace in ('kube-system', 'kube-public') and verb in ('create', 'update', 'patch', 'delete')",
                "severity": "critical",
                "risk_score": 90,
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Deploy Container (T1610)",
            },
        ]


k8s_audit_ingestion = KubernetesAuditIngestion()
