"""CyberNova — Detection Module: Rule engine, correlation, enrichment, Sigma, MITRE, Cloud, K8s."""
from cybernova.detection.services.detection_service import DetectionService, detection_service
from cybernova.detection.rules_engine.rules import DetectionRule, RuleEngine, rule_engine
from cybernova.detection.sigma.sigma_parser import SigmaParser, sigma_parser
from cybernova.detection.sigma.sigma_converter import SigmaConverter, sigma_converter
from cybernova.detection.sigma.sigma_loader import SigmaLoader, sigma_loader
from cybernova.detection.mitre.mitre import (
    MITRE_TACTICS, MITRE_TECHNIQUES,
    get_tactic_name, get_technique_name,
    get_techniques_for_tactic, get_tactic_for_technique,
)
from cybernova.detection.mitre.mitre_coverage import MitreCoverage, mitre_coverage
from cybernova.detection.cloud.cloud_detections import (
    CLOUD_RULES, register_cloud_rules, is_cloud_event, extract_cloud_provider,
)
from cybernova.detection.kubernetes.k8s_detections import (
    K8S_RULES, register_k8s_rules, is_k8s_event,
)

__all__ = [
    "DetectionService", "detection_service",
    "DetectionRule", "RuleEngine", "rule_engine",
    "SigmaParser", "sigma_parser",
    "SigmaConverter", "sigma_converter",
    "SigmaLoader", "sigma_loader",
    "MITRE_TACTICS", "MITRE_TECHNIQUES",
    "get_tactic_name", "get_technique_name",
    "get_techniques_for_tactic", "get_tactic_for_technique",
    "MitreCoverage", "mitre_coverage",
    "CLOUD_RULES", "register_cloud_rules", "is_cloud_event", "extract_cloud_provider",
    "K8S_RULES", "register_k8s_rules", "is_k8s_event",
]
