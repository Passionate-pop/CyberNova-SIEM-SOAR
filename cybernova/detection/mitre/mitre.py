"""
CyberNova — MITRE ATT&CK Framework Data
Enterprise ATT&CK v14 tactics and commonly detected techniques.
"""
from __future__ import annotations

from typing import Dict, List, Optional

MITRE_TACTICS: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    # Initial Access
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001"},
    "T1566": {"name": "Phishing", "tactic": "TA0001"},
    "T1091": {"name": "Replication Through Removable Media", "tactic": "TA0001"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1059.001": {"name": "PowerShell", "tactic": "TA0002"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "TA0002"},
    "T1059.005": {"name": "Visual Basic", "tactic": "TA0002"},
    "T1204": {"name": "User Execution", "tactic": "TA0002"},
    "T1106": {"name": "Native API", "tactic": "TA0002"},
    "T1569": {"name": "System Services", "tactic": "TA0002"},
    "T1569.002": {"name": "Service Execution", "tactic": "TA0002"},
    # Persistence
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "TA0003"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "TA0003"},
    "T1543.003": {"name": "Windows Service", "tactic": "TA0003"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "TA0003"},
    "T1136": {"name": "Create Account", "tactic": "TA0003"},
    "T1505": {"name": "Server Software Component", "tactic": "TA0003"},
    "T1546": {"name": "Event Triggered Execution", "tactic": "TA0003"},
    "T1546.003": {"name": "Windows Management Instrumentation Event Subscription", "tactic": "TA0003"},
    "T1098": {"name": "Account Manipulation", "tactic": "TA0003"},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "TA0004"},
    "T1055": {"name": "Process Injection", "tactic": "TA0004"},
    "T1078.003": {"name": "Local Accounts", "tactic": "TA0004"},
    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "TA0005"},
    "T1562.004": {"name": "Disable or Modify System Firewall", "tactic": "TA0005"},
    "T1070": {"name": "Indicator Removal on Host", "tactic": "TA0005"},
    "T1070.004": {"name": "File Deletion", "tactic": "TA0005"},
    "T1070.006": {"name": "Timestomp", "tactic": "TA0005"},
    "T1036": {"name": "Masquerading", "tactic": "TA0005"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1027.010": {"name": "Command Obfuscation", "tactic": "TA0005"},
    "T1480": {"name": "Execution Guardrails", "tactic": "TA0005"},
    "T1553": {"name": "Subvert Trust Controls", "tactic": "TA0005"},
    "T1202": {"name": "Indirect Command Execution", "tactic": "TA0005"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "TA0006"},
    "T1003.002": {"name": "Security Account Manager", "tactic": "TA0006"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006"},
    "T1056": {"name": "Input Capture", "tactic": "TA0006"},
    "T1056.001": {"name": "Keylogging", "tactic": "TA0006"},
    "T1212": {"name": "Exploitation for Credential Access", "tactic": "TA0006"},
    # Discovery
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007"},
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "TA0007"},
    "T1057": {"name": "Process Discovery", "tactic": "TA0007"},
    "T1012": {"name": "Query Registry", "tactic": "TA0007"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1518": {"name": "Software Discovery", "tactic": "TA0007"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "TA0007"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "TA0008"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "TA0008"},
    "T1021.004": {"name": "SSH", "tactic": "TA0008"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "TA0008"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "TA0009"},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "TA0009"},
    "T1114": {"name": "Email Collection", "tactic": "TA0009"},
    "T1113": {"name": "Screen Capture", "tactic": "TA0009"},
    "T1125": {"name": "Video Capture", "tactic": "TA0009"},
    "T1056.003": {"name": "Web Portal Capture", "tactic": "TA0009"},
    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "TA0010"},
    "T1020": {"name": "Automated Exfiltration", "tactic": "TA0010"},
    "T1030": {"name": "Data Transfer Size Limits", "tactic": "TA0010"},
    "T1052": {"name": "Exfiltration Over Physical Medium", "tactic": "TA0010"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1071.001": {"name": "Web Protocols", "tactic": "TA0011"},
    "T1071.004": {"name": "DNS", "tactic": "TA0011"},
    "T1090": {"name": "Proxy", "tactic": "TA0011"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "TA0011"},
    "T1573": {"name": "Encrypted Channel", "tactic": "TA0011"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011"},
    "T1102": {"name": "Web Service", "tactic": "TA0011"},
    "T1008": {"name": "Fallback Channels", "tactic": "TA0011"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1485": {"name": "Data Destruction", "tactic": "TA0040"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040"},
    "T1529": {"name": "System Shutdown/Reboot", "tactic": "TA0040"},
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "TA0043"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "TA0043"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "TA0043"},
    # Resource Development
    "T1583": {"name": "Acquire Infrastructure", "tactic": "TA0042"},
    "T1588": {"name": "Obtain Capabilities", "tactic": "TA0042"},
}


def get_tactic_name(tactic_id: str) -> str:
    return MITRE_TACTICS.get(tactic_id, tactic_id)


def get_technique_name(technique_id: str) -> str:
    entry = MITRE_TECHNIQUES.get(technique_id)
    return entry["name"] if entry else technique_id


def get_techniques_for_tactic(tactic_id: str) -> List[Dict[str, str]]:
    return [
        {"id": tid, "name": info["name"]}
        for tid, info in MITRE_TECHNIQUES.items()
        if info["tactic"] == tactic_id
    ]


def get_tactic_for_technique(technique_id: str) -> Optional[str]:
    entry = MITRE_TECHNIQUES.get(technique_id)
    return entry["tactic"] if entry else None


def get_technique_id(name_or_id: str) -> Optional[str]:
    name_lower = name_or_id.lower()
    for tid, info in MITRE_TECHNIQUES.items():
        if tid.lower() == name_lower or info["name"].lower() == name_lower:
            return tid
    return None
