"""
CyberNova — Palo Alto Networks Firewall Log Parser
Parses Palo Alto traffic, threat, and system logs.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.palo_alto")

PAN_LOG_TYPES = {
    "TRAFFIC": "pan_traffic",
    "THREAT": "pan_threat",
    "SYSTEM": "pan_system",
    "CONFIG": "pan_config",
    "HIP": "pan_hip",
    "CORRELATION": "pan_correlation",
    "GLOBALPROTECT": "pan_globalprotect",
    "DECRYPTION": "pan_decryption",
    "AUTH": "pan_auth",
    "USERID": "pan_userid",
    "DATA": "pan_data",
}

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "informational": "info",
    "1": "critical", "2": "high", "3": "medium",
    "4": "low", "5": "info",
}

THREAT_SEVERITY_MAP = {
    "1": "critical", "2": "critical", "3": "high",
    "4": "medium", "5": "medium", "6": "low",
}

PAN_FIELD_MAP = {
    "source_ip": ["src", "source_ip", "sourceaddress"],
    "dest_ip": ["dst", "dest_ip", "destinationaddress"],
    "source_port": ["sport", "source_port", "sourceport"],
    "dest_port": ["dport", "dest_port", "destinationport"],
    "protocol": ["proto", "protocol"],
    "user": ["user", "usr", "username"],
    "app": ["app", "application"],
    "rule": ["rule", "rulename"],
    "action": ["action"],
    "category": ["category"],
    "direction": ["direction"],
    "session_id": ["sessionid"],
    "serial": ["serial", "deviceserial"],
    "device_name": ["device_name", "devicename"],
    "nat_source_ip": ["nat_src", "natsourceip"],
    "nat_dest_ip": ["nat_dst", "natdestinationip"],
    "nat_source_port": ["nat_sport", "natsourceport"],
    "nat_dest_port": ["nat_dport", "natdestinationport"],
    "bytes_sent": ["bytes_sent", "bytes Sent"],
    "bytes_received": ["bytes_received", "bytes Received"],
    "packets_sent": ["packets_sent", "packets Sent"],
    "packets_received": ["packets_received", "packets Received"],
    "duration": ["elapsed", "duration", "elapsedtime"],
    "threat_id": ["threatid", "threat_id"],
    "threat_name": ["threat_name", "threatname"],
    "subtype": ["subtype"],
    "url": ["url", "uri"],
    "file_name": ["file_name", "filename"],
    "file_type": ["file_type", "filetype"],
    "content_type": ["contenttype", "content_type"],
    "vendor": ["vendor"],
    "severity_raw": ["severity"],
}


def _extract_field(data: Dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        val = data.get(key)
        if val is not None and val != "":
            return val
    return ""


def parse_palo_alto_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Palo Alto JSON parse failed: %s", exc)
            return {"event_type": "palo_alto", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "palo_alto", "severity": "info", "message": str(raw)}

    log_type = raw.get("type", raw.get("log_type", "")).upper()
    mapped_type = PAN_LOG_TYPES.get(log_type, "palo_alto")

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "",
        "user": "",
        "timestamp": raw.get("time_generated", raw.get("time", raw.get("timestamp", ""))),
        "message": "",
        "metadata": {},
    }

    for field, keys in PAN_FIELD_MAP.items():
        val = _extract_field(raw, keys)
        if val:
            if field in ("source_port", "dest_port", "nat_source_port", "nat_dest_port",
                         "bytes_sent", "bytes_received", "packets_sent", "packets_received",
                         "duration", "session_id"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            result[field] = val

    sev_raw = str(result.pop("severity_raw", ""))
    if log_type == "THREAT":
        result["severity"] = THREAT_SEVERITY_MAP.get(sev_raw, "medium")
    else:
        result["severity"] = SEVERITY_MAP.get(sev_raw.lower(), "info")

    result["metadata"]["pan_type"] = log_type

    action = result.get("action", "")
    if action in ("block", "drop", "deny", "reset-both", "reset-client", "reset-server"):
        result["metadata"]["blocked"] = True
        if result["severity"] in ("info", "low"):
            result["severity"] = "medium"
    else:
        result["metadata"]["blocked"] = False

    threat_name = result.get("threat_name", "")
    if threat_name:
        result["message"] = f"PAN {log_type}: {threat_name}"
    else:
        direction_char = "->" if result.get("direction", "inbound") != "outbound" else "<-"
        result["message"] = (
            f"PAN {log_type}: {result['source_ip']}:{result['source_port']} "
            f"{direction_char} {result['dest_ip']}:{result['dest_port']} "
            f"({result.get('app', 'unknown')}) action={action}"
        )

    return result


PARSER_REGISTRY_KEY = "palo_alto"
