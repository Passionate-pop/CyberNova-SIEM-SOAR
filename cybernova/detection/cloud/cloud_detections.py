"""
CyberNova — K8s Audit Attack Detections
Cloud provider (AWS/Azure/GCP) detection rules removed for $0 local deployment.
Kubernetes audit rules are defined in cybernova.cloud.k8s_audit instead.
"""
from __future__ import annotations

import logging
from typing import List

from cybernova.detection.rules_engine.rules import DetectionRule

log = logging.getLogger("cybernova.detection.cloud")

# Cloud provider (AWS/Azure/GCP) rules excluded for $0 local/GitHub deployment.
# Kubernetes audit rules live in cybernova.cloud.k8s_audit.
CLOUD_RULES: List[DetectionRule] = []


def register_cloud_rules() -> int:
    log.info("Cloud provider rules skipped (local deployment)")
    return 0


CLOUD_SOURCES = set()


def is_cloud_event(event: dict) -> bool:
    return False


def extract_cloud_provider(event: dict) -> str:
    return "unknown"
