from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.cspm.scanner")


class CloudProvider(str, Enum):
    KUBERNETES = "kubernetes"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CSPMFinding:
    id: str
    provider: CloudProvider
    service: str
    resource_type: str
    resource_id: str
    region: str
    check_id: str
    check_name: str
    description: str
    severity: FindingSeverity
    status: str
    remediation: str
    framework_mappings: List[str] = field(default_factory=list)
    discovered_at: str = ""


CSPM_RULES: List[Dict[str, Any]] = [
    {
        "id": "k8s-rbac-cluster-admin",
        "provider": "kubernetes",
        "service": "rbac",
        "name": "Restrict Cluster Admin Bindings",
        "description": "Ensure cluster-admin role is not bound to service accounts or users without justification",
        "severity": "critical",
        "remediation": "Review and remove unnecessary cluster-admin role bindings",
        "frameworks": ["pci_dss", "soc2"],
    },
    {
        "id": "k8s-pod-security",
        "provider": "kubernetes",
        "service": "pod",
        "name": "Pod Security Standards Enforced",
        "description": "Ensure pods run with restricted security contexts",
        "severity": "high",
        "remediation": "Apply Pod Security Admission or OPA/Gatekeeper policies",
        "frameworks": ["pci_dss", "soc2"],
    },
    {
        "id": "k8s-network-policies",
        "provider": "kubernetes",
        "service": "networking",
        "name": "Network Policies Defined",
        "description": "Ensure Kubernetes NetworkPolicies are defined for namespace isolation",
        "severity": "medium",
        "remediation": "Define NetworkPolicy resources for each namespace",
        "frameworks": ["pci_dss", "soc2"],
    },
    {
        "id": "k8s-container-resource-limits",
        "provider": "kubernetes",
        "service": "pod",
        "name": "Container Resource Limits Defined",
        "description": "Ensure containers have CPU and memory limits defined",
        "severity": "high",
        "remediation": "Set resource requests and limits for all containers",
        "frameworks": ["soc2"],
    },
    {
        "id": "k8s-non-root-containers",
        "provider": "kubernetes",
        "service": "pod",
        "name": "Containers Run as Non-Root",
        "description": "Ensure containers do not run as root user",
        "severity": "high",
        "remediation": "Set securityContext.runAsNonRoot: true in pod specs",
        "frameworks": ["pci_dss", "soc2"],
    },
    {
        "id": "k8s-readonly-root-fs",
        "provider": "kubernetes",
        "service": "pod",
        "name": "Read-Only Root Filesystem",
        "description": "Ensure containers have read-only root filesystems",
        "severity": "medium",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true",
        "frameworks": ["pci_dss", "soc2"],
    },
    {
        "id": "k8s-secrets-encrypted",
        "provider": "kubernetes",
        "service": "secrets",
        "name": "Secrets Encrypted at Rest",
        "description": "Ensure Kubernetes secrets are encrypted at rest",
        "severity": "high",
        "remediation": "Enable KMS encryption for etcd or use secrets store CSI driver",
        "frameworks": ["pci_dss", "hipaa", "gdpr"],
    },
]


class CSPMScanner:
    """
    Cloud Security Posture Management scanner.
    Evaluates Kubernetes infrastructure against security best practices.
    Cloud provider (AWS/Azure/GCP) scanning removed for $0 local deployment.
    """

    def __init__(self):
        self._findings: List[CSPMFinding] = []
        self._scan_history: List[Dict[str, Any]] = []

    def get_rules(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        if provider:
            return [r for r in CSPM_RULES if r["provider"] == provider]
        return list(CSPM_RULES)

    def get_providers(self) -> List[Dict[str, Any]]:
        providers = {}
        for r in CSPM_RULES:
            p = r["provider"]
            if p not in providers:
                providers[p] = 0
            providers[p] += 1
        return [{"provider": k, "rule_count": v, "name": CloudProvider(k).name} for k, v in providers.items()]

    async def run_scan(self, provider: str = "kubernetes", region: str = "local") -> Dict[str, Any]:
        """Run a CSPM scan for the given provider and region."""
        log.info("Starting CSPM scan: provider=%s region=%s", provider, region)
        rules = [r for r in CSPM_RULES if r["provider"] == provider]
        findings: List[CSPMFinding] = []

        for rule in rules:
            loop = asyncio.get_running_loop()
            finding = await loop.run_in_executor(None, self._evaluate_rule, rule, region)
            if finding:
                findings.append(finding)

        scan_result = {
            "scan_id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "provider": provider,
            "region": region,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_rules": len(rules),
            "passed": sum(1 for f in findings if f.status == "passed"),
            "failed": sum(1 for f in findings if f.status == "failed"),
            "findings": [
                {
                    "check_id": f.check_id,
                    "check_name": f.check_name,
                    "resource_id": f.resource_id,
                    "service": f.service,
                    "severity": f.severity.value,
                    "status": f.status,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
        self._scan_history.append(scan_result)
        return scan_result

    _SCANNER_DISPATCH: Dict[str, str] = {
        "k8s-rbac-cluster-admin": "cybernova.cspm.scanners.kubernetes.rbac:check_k8s_rbac_cluster_admin",
        "k8s-pod-security": "cybernova.cspm.scanners.kubernetes.pod:check_k8s_pod_security",
        "k8s-container-resource-limits": "cybernova.cspm.scanners.kubernetes.pod:check_k8s_container_resource_limits",
        "k8s-non-root-containers": "cybernova.cspm.scanners.kubernetes.pod:check_k8s_non_root_containers",
        "k8s-readonly-root-fs": "cybernova.cspm.scanners.kubernetes.pod:check_k8s_readonly_root_fs",
        "k8s-secrets-encrypted": "cybernova.cspm.scanners.kubernetes.secrets:check_k8s_secrets_encrypted",
        "k8s-network-policies": "cybernova.cspm.scanners.kubernetes.network:check_k8s_network_policies",
    }

    def _evaluate_rule(self, rule: Dict[str, Any], region: str) -> Optional[CSPMFinding]:
        check_id = rule["id"]
        check_name = rule["name"]
        description = rule["description"]
        severity = FindingSeverity(rule["severity"])
        remediation = rule["remediation"]
        provider = CloudProvider(rule["provider"])
        service = rule["service"]
        frameworks = rule.get("frameworks", [])

        status = "failed"
        resource_id = f"check/{check_id}"

        dispatch_path = self._SCANNER_DISPATCH.get(check_id)
        if dispatch_path:
            try:
                module_path, func_name = dispatch_path.split(":", 1)
                import importlib
                module = importlib.import_module(module_path)
                func = getattr(module, func_name)
                result = func()
                status = result.get("status", "failed")
                resource_id = result.get("resource_id", resource_id)
            except Exception as exc:
                log.error("Scanner for check %s failed: %s", check_id, exc)
                status = "error"
        else:
            log.warning("No scanner registered for check: %s", check_id)

        return CSPMFinding(
            id=f"{check_id}-{region}",
            provider=provider,
            service=service,
            resource_type=service,
            resource_id=resource_id,
            region=region,
            check_id=check_id,
            check_name=check_name,
            description=description,
            severity=severity,
            status=status,
            remediation=remediation,
            framework_mappings=frameworks,
            discovered_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_scan_history(self) -> List[Dict[str, Any]]:
        return list(self._scan_history)

    def get_stats(self) -> Dict[str, Any]:
        total_findings = sum(len(h.get("findings", [])) for h in self._scan_history)
        total_passed = sum(h.get("passed", 0) for h in self._scan_history)
        total_failed = sum(h.get("failed", 0) for h in self._scan_history)
        return {
            "total_scans": len(self._scan_history),
            "total_findings": total_findings,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "last_scan": self._scan_history[-1]["timestamp"] if self._scan_history else None,
            "available_rules": len(CSPM_RULES),
        }


cspm_scanner = CSPMScanner()
