"""
CyberNova — Playbook Definitions
Predefined response playbooks matched by severity/rule/risk score.

Severity-Based Response Actions:
- LOW: UI only (no actions) - logs for monitoring
- MEDIUM: UI only (no actions) - logs for monitoring  
- HIGH: App notification for investigation
- CRITICAL: Automated action + notification
"""
from __future__ import annotations
from typing import Any, Dict, List

PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "pb_critical_incident",
        "name": "Critical Incident Response",
        "priority": 1,
        "severity_action": "automated",
        "condition": {"severity": ["critical"], "min_risk_score": 80},
        "actions": [
            {"type": "isolate_host", "params": {}},
            {"type": "block_ip", "params": {}},
            {"type": "pagerduty_trigger", "params": {}},
            {"type": "opsgenie_trigger", "params": {}},
            {"type": "jira_create", "params": {}},
            {"type": "servicenow_create", "params": {}},
            {"type": "email_alert", "params": {"to": ""}},
            {"type": "notify_soc", "params": {"channel": "pagerduty"}},
        ],
        "automated": True,
    },
    {
        "id": "pb_high_alert",
        "name": "High Alert Response",
        "priority": 2,
        "severity_action": "notification",
        "condition": {"severity": ["high"], "min_risk_score": 60},
        "actions": [
            {"type": "log_alert", "params": {}},
        ],
        "automated": False,
    },
    {
        "id": "pb_medium_alert",
        "name": "Medium Alert Monitoring",
        "priority": 3,
        "severity_action": "ui_only",
        "condition": {"severity": ["medium"]},
        "actions": [
            {"type": "log_alert", "params": {}},
        ],
        "automated": False,
    },
    {
        "id": "pb_low_alert",
        "name": "Low Alert Logging",
        "priority": 4,
        "severity_action": "ui_only",
        "condition": {"severity": ["low"]},
        "actions": [
            {"type": "log_alert", "params": {}},
        ],
        "automated": False,
    },
    {
        "id": "pb_brute_force",
        "name": "Brute Force Mitigation",
        "priority": 1,
        "severity_action": "automated",
        "condition": {"rule_name": ["brute_force_attempt", "BruteForceRule"]},
        "actions": [
            {"type": "block_ip", "params": {"duration": 3600}},
            {"type": "notify_admin", "params": {}},
        ],
        "automated": True,
    },
    {
        "id": "pb_malware",
        "name": "Malware Quarantine",
        "priority": 1,
        "severity_action": "automated",
        "condition": {"rule_name": ["malware_detected", "malicious_process", "malicious_script"]},
        "actions": [
            {"type": "isolate_host", "params": {}},
            {"type": "scan_host", "params": {}},
        ],
        "automated": True,
    },
    {
        "id": "pb_ransomware",
        "name": "Ransomware Response",
        "priority": 1,
        "severity_action": "automated",
        "condition": {"rule_name": ["ransomware_signature", "ransomware_detected"]},
        "actions": [
            {"type": "isolate_host", "params": {}},
            {"type": "block_ip", "params": {}},
            {"type": "notify_soc", "params": {"channel": "emergency"}},
        ],
        "automated": True,
    },
    {
        "id": "pb_c2",
        "name": "C2 Communication Response",
        "priority": 1,
        "severity_action": "automated",
        "condition": {"rule_name": ["c2_communication", "C2Communication"]},
        "actions": [
            {"type": "block_ip", "params": {}},
            {"type": "isolate_host", "params": {}},
            {"type": "notify_soc", "params": {"channel": "pagerduty"}},
        ],
        "automated": True,
    },
]


def match_playbook(alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find matching playbooks for an alert."""
    matched = []
    severity = alert_data.get("severity", "low")
    risk_score = alert_data.get("risk_score", 0)
    rule_name = alert_data.get("rule_name", "")
    
    for pb in PLAYBOOKS:
        cond = pb["condition"]
        
        sev_match = severity in cond.get("severity", [severity])
        risk_match = risk_score >= cond.get("min_risk_score", 0)
        
        rule_match = not cond.get("rule_name") or rule_name in cond.get("rule_name", [rule_name])
        
        if sev_match and risk_match and rule_match:
            matched.append(pb)
    
    return sorted(matched, key=lambda p: p.get("priority", 99))


def get_severity_action(severity: str) -> str:
    """Get the action type for a severity level."""
    action_map = {
        "critical": "automated",
        "high": "notification",
        "medium": "ui_only",
        "low": "ui_only",
    }
    return action_map.get(severity.lower(), "ui_only")
