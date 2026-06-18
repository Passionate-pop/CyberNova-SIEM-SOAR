"""
CyberNova — Kubernetes Attack Detection Rules
Detects common Kubernetes attack patterns based on audit log events.
"""
from __future__ import annotations

import logging
from typing import List

from cybernova.detection.rules_engine.rules import DetectionRule, rule_engine

log = logging.getLogger("cybernova.detection.kubernetes")

K8S_RULES: List[DetectionRule] = [
    # ── Privilege Escalation ──────────────────────────────────────
    DetectionRule(
        "k8s_privileged_pod_created",
        "critical",
        {"event_type": "privileged_pod_created", "source": "kubernetes_audit"},
        92.0,
        "Privileged pod created in cluster — container breakout risk",
        mitre_tactic="TA0004",
        mitre_technique="T1611",
    ),
    DetectionRule(
        "k8s_cluster_admin_binding",
        "critical",
        {"event_type": "cluster_admin_binding", "source": "kubernetes_audit"},
        95.0,
        "Cluster-admin RoleBinding/ClusterRoleBinding created — privilege escalation",
        mitre_tactic="TA0004",
        mitre_technique="T1078",
    ),
    DetectionRule(
        "k8s_host_network_pod",
        "high",
        {"event_type": "host_network_pod", "source": "kubernetes_audit"},
        80.0,
        "Pod with hostNetwork=true created — possible lateral movement",
        mitre_tactic="TA0005",
        mitre_technique="T1611",
    ),
    DetectionRule(
        "k8s_host_path_mount",
        "high",
        {"event_type": "host_path_mount", "source": "kubernetes_audit"},
        85.0,
        "Pod with hostPath volume mount created — node file system access",
        mitre_tactic="TA0005",
        mitre_technique="T1611",
    ),
    # ── Credential Access ─────────────────────────────────────────
    DetectionRule(
        "k8s_secrets_access",
        "high",
        {"event_type": "secrets_list_access", "source": "kubernetes_audit"},
        78.0,
        "Secrets list/get operation — possible credential harvesting",
        mitre_tactic="TA0006",
        mitre_technique="T1552",
    ),
    DetectionRule(
        "k8s_configmap_dump",
        "medium",
        {"event_type": "configmap_dump", "source": "kubernetes_audit"},
        60.0,
        "ConfigMap list/get across namespaces — config reconnaissance",
        mitre_tactic="TA0006",
        mitre_technique="T1552",
    ),
    DetectionRule(
        "k8s_service_account_token",
        "high",
        {"event_type": "service_account_token_access", "source": "kubernetes_audit"},
        75.0,
        "Service account token accessed — possible lateral movement",
        mitre_tactic="TA0006",
        mitre_technique="T1528",
    ),
    # ── Persistence ────────────────────────────────────────────────
    DetectionRule(
        "k8s_anonymous_auth_enabled",
        "critical",
        {"event_type": "anonymous_auth_enabled", "source": "kubernetes_audit"},
        90.0,
        "Anonymous authentication enabled on cluster — defense evasion",
        mitre_tactic="TA0005",
        mitre_technique="T1562",
    ),
    DetectionRule(
        "k8s_cronjob_created",
        "medium",
        {"event_type": "cronjob_created", "source": "kubernetes_audit"},
        55.0,
        "CronJob created — possible persistence mechanism",
        mitre_tactic="TA0003",
        mitre_technique="T1053.005",
    ),
    DetectionRule(
        "k8s_daemonset_created",
        "high",
        {"event_type": "daemonset_created", "source": "kubernetes_audit"},
        70.0,
        "DaemonSet created — possible deployment to all nodes",
        mitre_tactic="TA0003",
        mitre_technique="T1543",
    ),
    # ── Discovery ─────────────────────────────────────────────────
    DetectionRule(
        "k8s_api_discovery",
        "medium",
        {"event_type": "api_discovery", "source": "kubernetes_audit"},
        45.0,
        "API resource discovery — attacker enumerating capabilities",
        mitre_tactic="TA0007",
        mitre_technique="T1592",
    ),
    DetectionRule(
        "k8s_pod_list_across_namespaces",
        "high",
        {"event_type": "pod_list_cross_namespace", "source": "kubernetes_audit"},
        65.0,
        "Pod list across multiple namespaces — cluster reconnaissance",
        mitre_tactic="TA0007",
        mitre_technique="T1046",
    ),
    DetectionRule(
        "k8s_node_list",
        "medium",
        {"event_type": "node_list", "source": "kubernetes_audit"},
        55.0,
        "Node list call — infrastructure reconnaissance",
        mitre_tactic="TA0007",
        mitre_technique="T1082",
    ),
    # ── Lateral Movement ──────────────────────────────────────────
    DetectionRule(
        "k8s_exec_into_pod",
        "high",
        {"event_type": "exec_into_pod", "source": "kubernetes_audit"},
        85.0,
        "Exec into pod — interactive container access",
        mitre_tactic="TA0008",
        mitre_technique="T1609",
    ),
    DetectionRule(
        "k8s_port_forward",
        "high",
        {"event_type": "port_forward", "source": "kubernetes_audit"},
        78.0,
        "Port forward to pod — tunneling into container",
        mitre_tactic="TA0008",
        mitre_technique="T1572",
    ),
    DetectionRule(
        "k8s_attach_to_pod",
        "high",
        {"event_type": "attach_to_pod", "source": "kubernetes_audit"},
        80.0,
        "Attach to pod — interactive session into container",
        mitre_tactic="TA0008",
        mitre_technique="T1609",
    ),
    # ── Impact ────────────────────────────────────────────────────
    DetectionRule(
        "k8s_node_drain",
        "high",
        {"event_type": "node_drain", "source": "kubernetes_audit"},
        75.0,
        "Node drain command — possible DoS or cluster disruption",
        mitre_tactic="TA0040",
        mitre_technique="T1499",
    ),
    DetectionRule(
        "k8s_pod_deleted_bulk",
        "high",
        {"event_type": "bulk_pod_deletion", "source": "kubernetes_audit"},
        80.0,
        "Bulk pod deletion — possible DoS or sabotage",
        mitre_tactic="TA0040",
        mitre_technique="T1499",
    ),
    DetectionRule(
        "k8s_namespace_deleted",
        "high",
        {"event_type": "namespace_deleted", "source": "kubernetes_audit"},
        85.0,
        "Namespace deleted — significant resource destruction",
        mitre_tactic="TA0040",
        mitre_technique="T1485",
    ),
    # ── Defense Evasion ───────────────────────────────────────────
    DetectionRule(
        "k8s_audit_log_disabled",
        "critical",
        {"event_type": "audit_log_disabled", "source": "kubernetes_audit"},
        95.0,
        "Kubernetes audit log policy disabled or modified — logging evasion",
        mitre_tactic="TA0005",
        mitre_technique="T1562",
    ),
    DetectionRule(
        "k8s_webhook_mutated",
        "critical",
        {"event_type": "webhook_config_modified", "source": "kubernetes_audit"},
        92.0,
        "MutatingAdmissionWebhook or ValidatingAdmissionWebhook modified — security control bypass",
        mitre_tactic="TA0005",
        mitre_technique="T1562",
    ),
    DetectionRule(
        "k8s_rolebinding_modified",
        "high",
        {"event_type": "rolebinding_modified", "source": "kubernetes_audit"},
        82.0,
        "RoleBinding/Role modified in sensitive namespace — privilege escalation",
        mitre_tactic="TA0004",
        mitre_technique="T1098",
    ),
    DetectionRule(
        "k8s_secret_created",
        "high",
        {"event_type": "secret_created", "source": "kubernetes_audit"},
        75.0,
        "Secret created in cluster — possible credential injection or data staging",
        mitre_tactic="TA0003",
        mitre_technique="T1098",
    ),
    DetectionRule(
        "k8s_pod_created_kube_system",
        "high",
        {"event_type": "pod_created_kube_system", "source": "kubernetes_audit"},
        85.0,
        "Pod created in kube-system namespace — possible cluster compromise",
        mitre_tactic="TA0003",
        mitre_technique="T1543",
    ),
    DetectionRule(
        "k8s_persistent_volume_claim_created",
        "medium",
        {"event_type": "persistent_volume_claim_created", "source": "kubernetes_audit"},
        60.0,
        "PersistentVolumeClaim created — possible data access or exfiltration preparation",
        mitre_tactic="TA0010",
        mitre_technique="T1530",
    ),
    DetectionRule(
        "k8s_network_policy_deleted",
        "high",
        {"event_type": "network_policy_deleted", "source": "kubernetes_audit"},
        78.0,
        "NetworkPolicy deleted — container network segmentation removed",
        mitre_tactic="TA0005",
        mitre_technique="T1562",
    ),
    DetectionRule(
        "k8s_resource_quota_modified",
        "medium",
        {"event_type": "resource_quota_modified", "source": "kubernetes_audit"},
        65.0,
        "ResourceQuota modified — possible resource exhaustion preparation",
        mitre_tactic="TA0040",
        mitre_technique="T1499",
    ),
    DetectionRule(
        "k8s_service_account_created",
        "medium",
        {"event_type": "service_account_created", "source": "kubernetes_audit"},
        55.0,
        "ServiceAccount created — review for unauthorized identity",
        mitre_tactic="TA0003",
        mitre_technique="T1136",
    ),
    DetectionRule(
        "k8s_cluster_role_modified",
        "high",
        {"event_type": "cluster_role_modified", "source": "kubernetes_audit"},
        80.0,
        "ClusterRole modified — cluster-wide privilege escalation risk",
        mitre_tactic="TA0004",
        mitre_technique="T1098",
    ),
    DetectionRule(
        "k8s_host_pid_pod_created",
        "high",
        {"event_type": "host_pid_pod_created", "source": "kubernetes_audit"},
        82.0,
        "Pod with hostPID=true created — container escape risk via process access",
        mitre_tactic="TA0004",
        mitre_technique="T1611",
    ),
]


def register_k8s_rules() -> int:
    for rule in K8S_RULES:
        rule_engine.register_rule(rule)
    log.info("Registered %d Kubernetes detection rules", len(K8S_RULES))
    return len(K8S_RULES)


K8S_SOURCES = {
    "kubernetes_audit",
    "k8s_audit",
    "kubernetes",
    "kube_api",
}


def is_k8s_event(event: dict) -> bool:
    source = event.get("source", "")
    event_type = event.get("event_type", "")
    if source in K8S_SOURCES:
        return True
    if event_type.startswith("k8s_"):
        return True
    if any(kw in source for kw in ("kubernetes", "kube", "k8s")):
        return True
    return False
