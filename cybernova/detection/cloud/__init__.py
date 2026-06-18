"""CyberNova — Cloud Attack Detection (AWS / Azure / GCP)"""
from cybernova.detection.cloud.cloud_detections import (
    CLOUD_RULES,
    register_cloud_rules,
    is_cloud_event,
    extract_cloud_provider,
)
__all__ = ["CLOUD_RULES", "register_cloud_rules", "is_cloud_event", "extract_cloud_provider"]
