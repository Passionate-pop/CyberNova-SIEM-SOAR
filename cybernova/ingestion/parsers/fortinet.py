"""
CyberNova — Fortinet FortiGate Firewall Log Parser
Parses FortiGate traffic, event, and security logs.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.fortinet")

FORTINET_LOG_TYPES = {
    "traffic": "fortinet_traffic",
    "utm": "fortinet_security",
    "event": "fortinet_event",
    "virus": "fortinet_antivirus",
    "ips": "fortinet_ips",
    "webfilter": "fortinet_webfilter",
    "dnsfilter": "fortinet_dnsfilter",
    "app-ctrl": "fortinet_appcontrol",
    "anomaly": "fortinet_anomaly",
    "dlp": "fortinet_dlp",
    "voip": "fortinet_voip",
    "wifi": "fortinet_wifi",
    "auth": "fortinet_auth",
    "admin": "fortinet_admin",
    "system": "fortinet_system",
    "connector": "fortinet_connector",
}

FORTINET_FIELD_MAP = {
    "srcip": "source_ip",
    "dstip": "dest_ip",
    "srcport": "source_port",
    "dstport": "dest_port",
    "srcintf": "source_interface",
    "dstintf": "dest_interface",
    "action": "action",
    "policyid": "policy_id",
    "poluuid": "policy_uuid",
    "sessionid": "session_id",
    "proto": "protocol",
    "service": "service",
    "app": "application",
    "appcat": "application_category",
    "user": "user",
    "group": "user_group",
    "authserver": "auth_server",
    "status": "status",
    "wanin": "bytes_in",
    "wanout": "bytes_out",
    "waninpkt": "packets_in",
    "wanoutpkt": "packets_out",
    "duration": "duration",
    "sentpkt": "packets_sent",
    "rcvdpkt": "packets_received",
    "sentbyte": "bytes_sent",
    "rcvdbyte": "bytes_received",
    "tz": "timezone",
    "devid": "device_id",
    "devname": "device_name",
    "vd": "vdom",
    "hostname": "hostname",
    "level": "severity_raw",
    "crscore": "credibility",
    "crlevel": "credibility_level",
    "url": "url",
    "cat": "category",
    "catdesc": "category_description",
    "virus": "virus_name",
    "virusid": "virus_id",
    "infection": "infection_name",
    "ref": "reference",
    "msg": "message_text",
    "logid": "log_id",
    "type": "log_type_raw",
    "subtype": "log_subtype",
    "eventtype": "event_type_raw",
}

SEVERITY_VALUE_MAP = {
    "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium",
    "notice": "low", "information": "info", "debug": "debug",
}


def _parse_fortinet_kv(raw: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', raw)
    for key, value in pairs:
        result[key] = value.strip('"')
    return result


def parse_fortinet_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        import json as _json
        try:
            data = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError):
            data = _parse_fortinet_kv(raw)
    else:
        return {"event_type": "fortinet", "severity": "info", "message": str(raw)}

    log_type = data.get("type", "traffic").lower()
    mapped_type = FORTINET_LOG_TYPES.get(log_type, f"fortinet_{log_type}")

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "",
        "user": "",
        "timestamp": data.get("date", data.get("time", data.get("timestamp", ""))),
        "message": "",
        "metadata": {},
    }

    for fk, rk in FORTINET_FIELD_MAP.items():
        val = data.get(fk)
        if val is not None and val != "":
            if rk in ("source_port", "dest_port", "bytes_in", "bytes_out",
                      "packets_in", "packets_out", "duration", "session_id",
                      "policy_id", "bytes_sent", "bytes_received",
                      "packets_sent", "packets_received"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            result[rk] = val

    sev = result.pop("severity_raw", "notice")
    result["severity"] = SEVERITY_VALUE_MAP.get(sev.lower(), "info")

    if log_type == "traffic":
        action = result.get("action", "accept")
        if action in ("deny", "drop", "reject", "reset"):
            result["severity"] = "medium"
        src = result.get("source_ip", "unknown")
        dst = result.get("dest_ip", "unknown")
        sp = result.get("source_port", "")
        dp = result.get("dest_port", "")
        proto = result.get("protocol", "")
        result["message"] = f"FortiGate traffic: {src}:{sp} -> {dst}:{dp} proto={proto} action={action}"

    elif log_type == "utm":
        subtype = result.get("log_subtype", data.get("subtype", ""))
        result["message"] = f"FortiGate UTM: {subtype} detected ({result.get('virus_name', result.get('url', ''))})"

    elif log_type == "event":
        result["message"] = f"FortiGate event: {result.get('log_id', '')} - {result.get('message_text', '')}"

    else:
        result["message"] = f"FortiGate {log_type}: {result.get('message_text', '')}"

    return result


PARSER_REGISTRY_KEY = "fortinet"
