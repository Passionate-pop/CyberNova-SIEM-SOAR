"""
CyberNova — SentinelOne EDR Log Parser
Parses SentinelOne events (threats, alerts, activities).
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.sentinelone")

THREAT_CLASSIFICATIONS = {
    "malware": "malware",
    "ransomware": "ransomware",
    "adware": "adware",
    "spyware": "spyware",
    "trojan": "trojan",
    "worm": "worm",
    "rootkit": "rootkit",
    "keylogger": "keylogger",
    "penetration": "penetration_tool",
    "phishing": "phishing",
    "lateral_movement": "lateral_movement",
    "exploit": "exploit",
    "privilege_escalation": "privilege_escalation",
    "bypass": "bypass",
    "recon": "reconnaissance",
}

MITRE_MAP = {
    "ransomware": {"tactic": "TA0040", "technique": "T1486"},
    "malware": {"tactic": "TA0002", "technique": "T1204"},
    "trojan": {"tactic": "TA0002", "technique": "T1204"},
    "lateral_movement": {"tactic": "TA0008", "technique": "T1021"},
    "privilege_escalation": {"tactic": "TA0004", "technique": "T1068"},
    "exploit": {"tactic": "TA0002", "technique": "T1203"},
    "reconnaissance": {"tactic": "TA0043", "technique": "T1595"},
}


def _parse_threat_details(threat: dict, result: Dict[str, Any]) -> None:
    result["threat_id"] = threat.get("id", threat.get("threat_id", ""))
    result["detection_name"] = threat.get("threat_name", threat.get("name", ""))
    classification = threat.get("classification", threat.get("classification_source", "")).lower()
    result["threat_classification"] = THREAT_CLASSIFICATIONS.get(classification, classification)
    result["severity"] = threat.get("severity", "medium")
    result["confidence"] = threat.get("confidence_level", threat.get("confidence", ""))
    result["analyst_verdict"] = threat.get("analyst_verdict", "")

    mitre = MITRE_MAP.get(result["threat_classification"], {})
    if mitre:
        result["mitre_tactic"] = mitre["tactic"]
        result["mitre_technique"] = mitre["technique"]

    result["metadata"]["malicious_process"] = threat.get("process_name", "")
    result["metadata"]["file_path"] = threat.get("file_path", threat.get("filePath", ""))
    result["metadata"]["file_hash"] = threat.get("file_hash", threat.get("hash", threat.get("sha1", "")))
    result["metadata"]["file_size"] = threat.get("file_size", 0)
    result["metadata"]["process_user"] = threat.get("process_user", threat.get("username", ""))
    result["metadata"]["command_line"] = threat.get("process_cmdline", "")

    result["source_ip"] = threat.get("src_ip", threat.get("source_ip", ""))
    result["dest_ip"] = threat.get("dst_ip", threat.get("dest_ip", ""))
    result["user"] = threat.get("username", threat.get("user", ""))


def _parse_activity(activity: dict, result: Dict[str, Any]) -> None:
    result["activity_id"] = activity.get("id", activity.get("activity_id", ""))
    result["activity_type"] = activity.get("activity_type", activity.get("type", ""))
    result["severity"] = activity.get("severity", "info")
    result["message"] = activity.get("data", activity.get("description", activity.get("message", "")))
    result["user"] = activity.get("user_name", activity.get("user", ""))
    result["metadata"]["primary_description"] = activity.get("primary_description", "")
    result["metadata"]["secondary_description"] = activity.get("secondary_description", "")


def parse_sentinelone_event(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("S1 JSON parse failed: %s", exc)
            return {"event_type": "sentinelone", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "sentinelone", "severity": "info", "message": str(raw)}

    data_type = raw.get("data_type", raw.get("type", raw.get("event_type", "")))

    result: Dict[str, Any] = {
        "event_type": "sentinelone",
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "user": "",
        "hostname": "",
        "timestamp": raw.get("timestamp", raw.get("created_at", raw.get("time", ""))),
        "message": "",
        "metadata": {},
    }

    data = raw.get("data", raw.get("event", raw.get("detail", raw)))

    if not isinstance(data, dict):
        data = raw

    if data_type.lower() in ("threat", "detection"):
        result["event_type"] = "sentinelone_threat"
        _parse_threat_details(data, result)
    elif data_type.lower() in ("activity", "audit"):
        result["event_type"] = "sentinelone_activity"
        _parse_activity(data, result)
    else:
        result["event_type"] = f"sentinelone_{data_type}"
        if isinstance(data, dict):
            result["source_ip"] = data.get("src_ip", data.get("source_ip", ""))
            result["dest_ip"] = data.get("dst_ip", data.get("dest_ip", ""))
            result["user"] = data.get("username", data.get("user", ""))
            result["metadata"] = {k: v for k, v in data.items()
                                  if k not in ("timestamp", "source_ip", "dest_ip")}

    agent = raw.get("agent", raw.get("agent_info", {}))
    if isinstance(agent, dict):
        result["hostname"] = agent.get("computer_name", agent.get("hostname", result.get("hostname", "")))
        result["device_id"] = agent.get("id", agent.get("agent_id", agent.get("uuid", "")))
        result["metadata"]["os"] = agent.get("os_type", agent.get("platform", ""))

    if not result["message"]:
        result["message"] = f"SentinelOne {result['event_type']} on {result.get('hostname', 'unknown')}"

    return result


PARSER_REGISTRY_KEY = "sentinelone"
