"""CyberNova — Kubernetes Attack Detection"""
from cybernova.detection.kubernetes.k8s_detections import (
    K8S_RULES,
    register_k8s_rules,
    is_k8s_event,
)
__all__ = ["K8S_RULES", "register_k8s_rules", "is_k8s_event"]
