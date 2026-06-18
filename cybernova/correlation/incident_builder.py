"""
CyberNova — Incident Builder
Builds incidents from correlation results with full attack story and recommendations.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from cybernova.core.utils.helpers import new_id


class IncidentBuilder:
    def build_incident(
        self,
        rule_name: str,
        rule_description: str,
        matched_alerts: List[Dict[str, Any]],
        tenant_id: str,
    ) -> Dict[str, Any]:
        severity = self._calculate_incident_severity(matched_alerts)
        risk_score = self._calculate_risk_score(matched_alerts)
        attack_story = self._build_attack_story(matched_alerts)
        recommendations = self._get_recommendations(rule_name, matched_alerts)
        affected_entities = self._extract_affected_entities(matched_alerts)

        return {
            "id": new_id(),
            "tenant_id": tenant_id,
            "title": f"{rule_name}: {len(matched_alerts)} related alerts",
            "description": rule_description,
            "severity": severity,
            "status": "new",
            "risk_score": risk_score,
            "alert_ids": [a.get("id") for a in matched_alerts if a.get("id")],
            "affected_entities": affected_entities,
            "attack_story": attack_story,
            "recommendations": recommendations,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "escalation_level": 1 if severity == "critical" else 0,
        }

    def _calculate_incident_severity(self, alerts: List[Dict[str, Any]]) -> str:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = "low"
        max_score = 0
        for alert in alerts:
            sev = alert.get("severity", "low").lower()
            score = severity_order.get(sev, 0)
            if score > max_score:
                max_severity = sev
                max_score = score
        return max_severity

    def _calculate_risk_score(self, alerts: List[Dict[str, Any]]) -> float:
        if not alerts:
            return 0.0
        max_risk = max(a.get("risk_score", 0) for a in alerts)
        severity_multiplier = 1.0 + (len(alerts) * 0.05)
        return min(100.0, max_risk * severity_multiplier)

    def _build_attack_story(self, alerts: List[Dict[str, Any]]) -> str:
        if not alerts:
            return "No events available for story reconstruction."

        sorted_alerts = sorted(alerts, key=lambda a: a.get("created_at", ""))
        story_parts = []
        for i, alert in enumerate(sorted_alerts, 1):
            ts = alert.get("created_at", "unknown time")
            rule = alert.get("rule_name", "Unknown event")
            sev = alert.get("severity", "")
            src = alert.get("source_ip", "unknown source")
            story_parts.append(f"{i}. [{ts}] {sev.upper()}: {rule} from {src}")

        return "\n".join(story_parts)

    def _get_recommendations(self, rule_name: str, alerts: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        rule_lower = rule_name.lower()

        if "brute_force" in rule_lower:
            recommendations.extend([
                "Block the source IP immediately via firewall",
                "Force password reset for affected user accounts",
                "Enable account lockout policy (5 failed attempts)",
                "Review recent successful logins for signs of compromise",
                "Enable MFA for all accounts",
            ])
        elif "privilege_escalation" in rule_lower:
            recommendations.extend([
                "Review and revoke unnecessary privilege grants",
                "Audit service accounts with elevated permissions",
                "Enable privileged access management (PAM)",
                "Review admin activity logs for the affected user",
            ])
        elif "port_scan" in rule_lower or "exploit" in rule_lower:
            recommendations.extend([
                "Block source IP at perimeter firewall",
                "Patch vulnerable services identified in scan",
                "Review and restrict exposed services",
                "Enable intrusion detection/prevention system",
            ])
        elif "malware" in rule_lower or "c2" in rule_lower:
            recommendations.extend([
                "Isolate affected host from network immediately",
                "Initiate malware forensics and removal",
                "Review network connections for C2 communication",
                "Check for persistence mechanisms",
                "Notify security operations center",
            ])
        elif "exfiltration" in rule_lower:
            recommendations.extend([
                "Block external destination IP/domain",
                "Review data loss prevention (DLP) logs",
                "Identify and classify exfiltrated data",
                "Notify data owner and compliance team",
            ])
        elif "lateral_movement" in rule_lower:
            recommendations.extend([
                "Segment affected network segments",
                "Reset credentials for compromised accounts",
                "Review jump server and RDP access logs",
                "Enable network detection and response (NDR)",
            ])
        else:
            recommendations.extend([
                "Investigate affected entities for signs of compromise",
                "Collect forensic evidence for analysis",
                "Review access logs and authentication records",
                "Implement additional monitoring on affected systems",
            ])

        return recommendations

    def _extract_affected_entities(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        entities: Dict[str, List[str]] = {
            "source_ips": [],
            "dest_ips": [],
            "users": [],
            "hosts": [],
        }

        for alert in alerts:
            raw = alert.get("raw_event", {})
            src_ip = alert.get("source_ip") or raw.get("source_ip", "")
            dst_ip = alert.get("dest_ip") or raw.get("dest_ip", "")
            user = alert.get("user") or raw.get("user", "")
            host = alert.get("hostname") or raw.get("hostname", "")

            if src_ip and src_ip not in entities["source_ips"]:
                entities["source_ips"].append(src_ip)
            if dst_ip and dst_ip not in entities["dest_ips"]:
                entities["dest_ips"].append(dst_ip)
            if user and user not in entities["users"]:
                entities["users"].append(user)
            if host and host not in entities["hosts"]:
                entities["hosts"].append(host)

        return entities


incident_builder = IncidentBuilder()
