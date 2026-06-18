"""
CyberNova — CrowdStrike Falcon EDR Log Parser
Parses CrowdStrike Falcon detection and event streams.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.crowdstrike")

FALCON_EVENT_TYPES = {
    "DetectionSummaryEvent": "cs_detection",
    "ProcessRollup2": "cs_process",
    "DnsRequest": "cs_dns",
    "NetworkConnect": "cs_network",
    "LocalIpAddress": "cs_network",
    "UserAccountCreated": "cs_user_created",
    "UserAccountDeleted": "cs_user_deleted",
    "UserAccountModified": "cs_user_modified",
    "RegistryKeyUpdate": "cs_registry",
    "RegistryValueUpdate": "cs_registry_value",
    "ProcessBlocked": "cs_process_blocked",
    "ExecutableWritten": "cs_file_write",
    "ExecutableDeleted": "cs_file_delete",
    "CriticalEvent": "cs_critical_event",
    "Unknown": "cs_event",
}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def _flatten_detection(detection: dict, result: Dict[str, Any]) -> None:
    severity_name = detection.get("severity_name", detection.get("severity", "low"))
    result["severity"] = SEVERITY_MAP.get(severity_name.lower(), "medium")
    result["detection_id"] = detection.get("detection_id", detection.get("composite_id", ""))
    result["detection_name"] = detection.get("detection_name", detection.get("name", ""))
    result["detection_description"] = detection.get("description", "")
    result["technique"] = detection.get("technique", "")
    result["tactic"] = detection.get("tactic", "")
    scenario = detection.get("scenario", detection.get("pattern", ""))
    if scenario:
        result["metadata"]["scenario"] = scenario
    reports = detection.get("reports", [])
    if isinstance(reports, list) and reports:
        result["metadata"]["reports"] = ", ".join(str(r) for r in reports)


def _parse_device_info(device: dict, result: Dict[str, Any]) -> None:
    if not isinstance(device, dict):
        return
    result["device_id"] = device.get("device_id", device.get("aid", ""))
    result["hostname"] = device.get("hostname", device.get("computer_name", ""))
    result["metadata"]["os"] = device.get("os_version", device.get("platform", ""))
    result["metadata"]["machine_domain"] = device.get("machine_domain", "")
    result["metadata"]["site_name"] = device.get("site_name", "")
    result["metadata"]["local_ip"] = device.get("local_ip", "")
    result["metadata"]["mac_address"] = device.get("mac_address", "")


def parse_crowdstrike_event(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("CrowdStrike JSON parse failed: %s", exc)
            return {"event_type": "crowdstrike", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "crowdstrike", "severity": "info", "message": str(raw)}

    event_type = raw.get("event_type", raw.get("metadata", {}).get("eventType", raw.get("eventType", "Unknown")))
    mapped_type = FALCON_EVENT_TYPES.get(event_type, f"cs_{event_type}")

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "user": "",
        "hostname": "",
        "device_id": "",
        "timestamp": raw.get("timestamp", raw.get("event_creation", raw.get("time", ""))),
        "message": "",
        "metadata": {},
    }

    event_data = raw.get("event", raw.get("detection", raw.get("data", raw)))

    if mapped_type == "cs_detection" and isinstance(event_data, dict):
        _flatten_detection(event_data, result)

    if isinstance(event_data, dict):
        severity_name = event_data.get("severity_name", event_data.get("severity", ""))
        if severity_name:
            result["severity"] = SEVERITY_MAP.get(severity_name.lower(), result["severity"])

        user_name = event_data.get("user_name", event_data.get("user", event_data.get("UserName", "")))
        if user_name:
            result["user"] = user_name

        result["source_ip"] = event_data.get("remote_ip", event_data.get("RemoteIP", event_data.get("source_ip", "")))
        result["dest_ip"] = event_data.get("LocalIP", event_data.get("local_ip", event_data.get("dest_ip", "")))
        result["source_port"] = event_data.get("remote_port", event_data.get("RemotePort", 0))
        result["dest_port"] = event_data.get("LocalPort", event_data.get("local_port", 0))

        dns_request = event_data.get("dns_request", event_data.get("DomainName", ""))
        if dns_request:
            result["metadata"]["dns_request"] = dns_request
        file_path = event_data.get("file_path", event_data.get("FilePath", event_data.get("TargetFilename", "")))
        if file_path:
            result["metadata"]["file_path"] = file_path
        cmdline = event_data.get("command_line", event_data.get("CommandLine", ""))
        if cmdline:
            result["metadata"]["command_line"] = cmdline
        parent_process = event_data.get("parent_process", event_data.get("ParentProcess", ""))
        if parent_process:
            result["metadata"]["parent_process"] = parent_process
        sha256 = event_data.get("sha256", event_data.get("SHA256HashData", ""))
        if sha256:
            result["metadata"]["sha256"] = sha256

    device_section = raw.get("device", raw.get("system", {}))
    if isinstance(device_section, dict):
        _parse_device_info(device_section, result)

    result["message"] = (
        f"CrowdStrike {mapped_type}: {result.get('detection_name', result.get('event_type', 'event'))} "
        f"on {result.get('hostname', 'unknown')}"
    )

    return result


PARSER_REGISTRY_KEY = "crowdstrike"
