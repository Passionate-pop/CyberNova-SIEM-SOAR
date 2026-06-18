from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class ComplianceStandard(str, Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"


class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    NOT_CHECKED = "not_checked"
    WARNING = "warning"


@dataclass
class ComplianceControl:
    id: str
    name: str
    description: str
    standard: ComplianceStandard
    category: str
    severity: str
    evidence_required: List[str]
    remediation: str


@dataclass
class ControlResult:
    control_id: str
    status: ControlStatus
    evidence: Dict[str, Any] = field(default_factory=dict)
    details: str = ""
    checked_at: str = ""


@dataclass
class ComplianceReport:
    id: str
    tenant_id: str
    standard: ComplianceStandard
    generated_at: str
    period_start: str
    period_end: str
    overall_score: float
    control_results: List[ControlResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


PCI_DSS_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        id="pci_1_1", name="Firewall Configuration",
        description="Firewalls must be configured to restrict traffic between trusted and untrusted networks.",
        standard=ComplianceStandard.PCI_DSS, category="network_security",
        severity="critical", evidence_required=["blocked_ips"],
        remediation="Configure firewall rules and maintain a documented rule set.",
    ),
    ComplianceControl(
        id="pci_2_1", name="System Configurations",
        description="System configurations must be hardened and managed.",
        standard=ComplianceStandard.PCI_DSS, category="system_hardening",
        severity="high", evidence_required=["devices"],
        remediation="Establish configuration standards and manage system configurations.",
    ),
    ComplianceControl(
        id="pci_3_1", name="Protect Stored Cardholder Data",
        description="Protect stored cardholder data through retention and disposal policies.",
        standard=ComplianceStandard.PCI_DSS, category="data_protection",
        severity="critical", evidence_required=["retention_policies"],
        remediation="Implement data retention and disposal policies for cardholder data.",
    ),
    ComplianceControl(
        id="pci_4_1", name="Encrypt Transmission",
        description="Encrypt cardholder data transmitted over open/public networks.",
        standard=ComplianceStandard.PCI_DSS, category="encryption",
        severity="critical", evidence_required=["encryption_settings"],
        remediation="Use strong cryptography (TLS 1.2+) for all data transmission.",
    ),
    ComplianceControl(
        id="pci_5_1", name="Protect Against Malware",
        description="Deploy anti-malware mechanisms and detect malicious activity.",
        standard=ComplianceStandard.PCI_DSS, category="malware_protection",
        severity="high", evidence_required=["detection_rules", "alerts"],
        remediation="Deploy and maintain anti-malware solutions with regular updates.",
    ),
    ComplianceControl(
        id="pci_6_1", name="Develop Secure Systems",
        description="Ensure systems are patched and updated to address vulnerabilities.",
        standard=ComplianceStandard.PCI_DSS, category="patch_management",
        severity="high", evidence_required=["devices"],
        remediation="Establish a patch management process and keep systems updated.",
    ),
    ComplianceControl(
        id="pci_7_1", name="Restrict Access by Need-to-Know",
        description="Restrict access to cardholder data based on business need-to-know.",
        standard=ComplianceStandard.PCI_DSS, category="access_control",
        severity="critical", evidence_required=["rbac", "users"],
        remediation="Implement role-based access control with least privilege principle.",
    ),
    ComplianceControl(
        id="pci_8_1", name="Identify and Authenticate Users",
        description="Assign unique IDs and authenticate all system users.",
        standard=ComplianceStandard.PCI_DSS, category="authentication",
        severity="critical", evidence_required=["user_management"],
        remediation="Implement MFA and unique user identification for all access.",
    ),
    ComplianceControl(
        id="pci_9_1", name="Restrict Physical Access",
        description="Restrict physical access to cardholder data environments.",
        standard=ComplianceStandard.PCI_DSS, category="physical_security",
        severity="medium", evidence_required=[],
        remediation="N/A for SaaS environments — physical access is managed by cloud provider.",
    ),
    ComplianceControl(
        id="pci_10_1", name="Track and Monitor Access",
        description="Log all access to network resources and cardholder data.",
        standard=ComplianceStandard.PCI_DSS, category="audit_logging",
        severity="critical", evidence_required=["audit_logs"],
        remediation="Implement comprehensive audit logging for all system components.",
    ),
    ComplianceControl(
        id="pci_10_2", name="Audit Trails",
        description="Retain audit trail history for at least 12 months.",
        standard=ComplianceStandard.PCI_DSS, category="audit_logging",
        severity="high", evidence_required=["audit_log_retention"],
        remediation="Configure audit log retention of minimum 12 months with 3 months online.",
    ),
    ComplianceControl(
        id="pci_11_1", name="Test Security Systems",
        description="Regularly test security systems and detection mechanisms.",
        standard=ComplianceStandard.PCI_DSS, category="testing",
        severity="high", evidence_required=["detection_rules", "alerts"],
        remediation="Run regular vulnerability scans and penetration tests.",
    ),
    ComplianceControl(
        id="pci_12_1", name="Security Policy",
        description="Maintain an information security policy addressing incident response.",
        standard=ComplianceStandard.PCI_DSS, category="incident_response",
        severity="high", evidence_required=["incidents", "playbooks"],
        remediation="Establish, publish, and maintain a security policy with incident response procedures.",
    ),
]

HIPAA_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        id="hipaa_164_308_a_1", name="Risk Analysis",
        description="Conduct an accurate and thorough assessment of risks to ePHI.",
        standard=ComplianceStandard.HIPAA, category="risk_management",
        severity="critical", evidence_required=["alerts", "incidents"],
        remediation="Implement a formal risk analysis process to identify and mitigate ePHI risks.",
    ),
    ComplianceControl(
        id="hipaa_164_308_a_3", name="Workforce Security",
        description="Ensure proper authorization and oversight of workforce access to ePHI.",
        standard=ComplianceStandard.HIPAA, category="access_control",
        severity="high", evidence_required=["rbac", "users"],
        remediation="Implement role-based access controls and authorize workforce members appropriately.",
    ),
    ComplianceControl(
        id="hipaa_164_308_a_5", name="Security Awareness",
        description="Provide security awareness training to all workforce members.",
        standard=ComplianceStandard.HIPAA, category="training",
        severity="medium", evidence_required=["users"],
        remediation="Conduct regular security awareness training for all personnel.",
    ),
    ComplianceControl(
        id="hipaa_164_308_a_6", name="Incident Response",
        description="Identify and respond to security incidents related to ePHI.",
        standard=ComplianceStandard.HIPAA, category="incident_response",
        severity="critical", evidence_required=["incidents", "alerts", "playbooks"],
        remediation="Establish incident response procedures to address ePHI security incidents.",
    ),
    ComplianceControl(
        id="hipaa_164_312_a_1", name="Access Control",
        description="Implement technical policies to allow only authorized ePHI access.",
        standard=ComplianceStandard.HIPAA, category="access_control",
        severity="critical", evidence_required=["users", "blocked_ips"],
        remediation="Deploy unique user IDs, automatic logoff, and emergency access procedures.",
    ),
    ComplianceControl(
        id="hipaa_164_312_b", name="Audit Controls",
        description="Record and examine activity in systems containing ePHI.",
        standard=ComplianceStandard.HIPAA, category="audit_logging",
        severity="high", evidence_required=["audit_logs"],
        remediation="Implement hardware, software, and procedural mechanisms to record ePHI access.",
    ),
    ComplianceControl(
        id="hipaa_164_312_c", name="Integrity Controls",
        description="Protect ePHI from improper alteration or destruction.",
        standard=ComplianceStandard.HIPAA, category="data_integrity",
        severity="high", evidence_required=["retention_policies"],
        remediation="Implement policies to ensure ePHI is not improperly altered or destroyed.",
    ),
    ComplianceControl(
        id="hipaa_164_312_d", name="Person Authentication",
        description="Verify the identity of persons seeking access to ePHI.",
        standard=ComplianceStandard.HIPAA, category="authentication",
        severity="high", evidence_required=["user_management"],
        remediation="Implement unique user identification and multi-factor authentication.",
    ),
    ComplianceControl(
        id="hipaa_164_312_e_1", name="Transmission Security",
        description="Guard against unauthorized ePHI access over networks.",
        standard=ComplianceStandard.HIPAA, category="encryption",
        severity="critical", evidence_required=["encryption_settings"],
        remediation="Implement encryption for all ePHI transmitted over networks.",
    ),
]

SOC2_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        id="soc2_security_1", name="Access Controls",
        description="Logical and physical access controls to prevent unauthorized access.",
        standard=ComplianceStandard.SOC2, category="access_control",
        severity="critical", evidence_required=["rbac", "blocked_ips", "users"],
        remediation="Implement logical access controls and monitor for unauthorized access attempts.",
    ),
    ComplianceControl(
        id="soc2_security_2", name="Logical Access",
        description="Restrict logical access to systems and data.",
        standard=ComplianceStandard.SOC2, category="access_control",
        severity="critical", evidence_required=["users", "audit_logs"],
        remediation="Enforce least privilege and review access rights regularly.",
    ),
    ComplianceControl(
        id="soc2_availability_1", name="Availability",
        description="Ensure system availability meets commitments and SLAs.",
        standard=ComplianceStandard.SOC2, category="availability",
        severity="high", evidence_required=["incidents"],
        remediation="Monitor system uptime and implement redundancy measures.",
    ),
    ComplianceControl(
        id="soc2_processing_1", name="Processing Integrity",
        description="Ensure data processing is complete, valid, accurate, and timely.",
        standard=ComplianceStandard.SOC2, category="processing_integrity",
        severity="high", evidence_required=["alerts", "audit_logs"],
        remediation="Monitor data processing pipelines for errors and anomalies.",
    ),
    ComplianceControl(
        id="soc2_confidentiality_1", name="Confidentiality",
        description="Protect confidential data through encryption and retention controls.",
        standard=ComplianceStandard.SOC2, category="data_protection",
        severity="critical", evidence_required=["encryption_settings", "retention_policies"],
        remediation="Encrypt confidential data at rest and in transit; enforce retention policies.",
    ),
    ComplianceControl(
        id="soc2_privacy_1", name="Privacy",
        description="Collect, use, retain, and disclose PII in accordance with commitments.",
        standard=ComplianceStandard.SOC2, category="privacy",
        severity="high", evidence_required=["retention_policies", "users", "audit_logs"],
        remediation="Establish and communicate privacy practices; manage PII lifecycle.",
    ),
]

GDPR_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        id="gdpr_art_5", name="Lawful Processing",
        description="Process personal data lawfully, fairly, and transparently.",
        standard=ComplianceStandard.GDPR, category="data_governance",
        severity="critical", evidence_required=["retention_policies"],
        remediation="Document lawful bases for data processing and maintain records of processing.",
    ),
    ComplianceControl(
        id="gdpr_art_15", name="Data Subject Access",
        description="Enable data subjects to access their personal data.",
        standard=ComplianceStandard.GDPR, category="data_subject_rights",
        severity="high", evidence_required=["users", "audit_logs"],
        remediation="Implement processes to respond to data subject access requests within 30 days.",
    ),
    ComplianceControl(
        id="gdpr_art_17", name="Right to Erasure",
        description="Enable data subjects to request deletion of personal data.",
        standard=ComplianceStandard.GDPR, category="data_subject_rights",
        severity="high", evidence_required=["retention_policies", "users"],
        remediation="Implement processes to delete personal data upon request within legal timelines.",
    ),
    ComplianceControl(
        id="gdpr_art_25", name="Data Protection by Design",
        description="Implement data protection principles from the design stage.",
        standard=ComplianceStandard.GDPR, category="data_governance",
        severity="high", evidence_required=["encryption_settings", "rbac"],
        remediation="Embed data protection into processing activities and system design.",
    ),
    ComplianceControl(
        id="gdpr_art_32", name="Security of Processing",
        description="Implement appropriate technical measures to secure personal data.",
        standard=ComplianceStandard.GDPR, category="security",
        severity="critical", evidence_required=["encryption_settings", "audit_logs", "detection_rules"],
        remediation="Implement encryption, access controls, and monitoring for personal data.",
    ),
    ComplianceControl(
        id="gdpr_art_33", name="Breach Notification",
        description="Notify supervisory authority of personal data breaches within 72 hours.",
        standard=ComplianceStandard.GDPR, category="incident_response",
        severity="critical", evidence_required=["incidents", "alerts", "playbooks"],
        remediation="Establish breach detection and notification procedures with defined SLAs.",
    ),
    ComplianceControl(
        id="gdpr_art_35", name="Data Protection Impact Assessment",
        description="Conduct DPIAs for high-risk processing activities.",
        standard=ComplianceStandard.GDPR, category="risk_management",
        severity="medium", evidence_required=["incidents", "alerts"],
        remediation="Perform DPIAs for processing activities that pose high risks to data subjects.",
    ),
]

CONTROL_REGISTRY: Dict[ComplianceStandard, List[ComplianceControl]] = {
    ComplianceStandard.PCI_DSS: PCI_DSS_CONTROLS,
    ComplianceStandard.HIPAA: HIPAA_CONTROLS,
    ComplianceStandard.SOC2: SOC2_CONTROLS,
    ComplianceStandard.GDPR: GDPR_CONTROLS,
    ComplianceStandard.ISO_27001: [],
}


class ControlFramework:
    def get_controls(self, standard: ComplianceStandard) -> List[ComplianceControl]:
        return CONTROL_REGISTRY.get(standard, [])

    def get_all_standards(self) -> List[Dict[str, Any]]:
        standards_info = []
        for standard in ComplianceStandard:
            controls = self.get_controls(standard)
            standards_info.append({
                "id": standard.value,
                "name": standard.name,
                "control_count": len(controls),
            })
        return standards_info


ComplianceFramework = ControlFramework
