"""
CyberNova — Check Point Firewall Log Parser
Parses Check Point logs (LEA/JSON format).
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.checkpoint")

CP_FIELD_MAP = {
    "src": "source_ip",
    "dst": "dest_ip",
    "s_port": "source_port",
    "x_sport": "source_port",
    "service": "dest_port",
    "service_id": "service",
    "protocol": "protocol",
    "action": "action",
    "rule": "rule_name",
    "rule_uid": "rule_uid",
    "rule_name": "rule_name",
    "user": "user",
    "origin": "origin",
    "originsicname": "origin_sic",
    "product": "product",
    "product_family": "product_family",
    "logid": "log_id",
    "log_deliver_time": "log_deliver_time",
    "first_hit_time": "first_hit",
    "last_hit_time": "last_hit",
    "hit_count": "hit_count",
    "duration": "duration",
    "ifname": "interface",
    "cluster_member": "cluster_member",
    "policy_name": "policy_name",
    "policy_date": "policy_date",
    "layer_name": "layer_name",
    "appi_name": "application",
    "appi_category": "application_category",
    "appi_risk": "application_risk",
    "url": "url",
    "resource": "resource",
    "content_type": "content_type",
    "bytes": "bytes_total",
    "bytes_sent": "bytes_sent",
    "bytes_received": "bytes_received",
    "packets": "packets_total",
    "packets_sent": "packets_sent",
    "packets_received": "packets_received",
    "severity": "severity_raw",
    "icmp_type": "icmp_type",
    "icmp_code": "icmp_code",
    "tcp_flags": "tcp_flags",
    "vpn_feature_name": "vpn_feature",
    "encryption": "encryption",
    "peer_gateway": "peer_gateway",
    "community": "community",
    "src_machine_name": "src_machine",
    "dst_machine_name": "dst_machine",
    "os_name": "os",
    "os_version": "os_version",
}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

ACTION_MAP = {
    "Accept": "accept", "accept": "accept",
    "Drop": "deny", "drop": "deny",
    "Reject": "deny", "reject": "deny",
    "Log": "log", "log": "log",
    "Encrypt": "encrypt", "encrypt": "encrypt",
    "Decrypt": "decrypt", "decrypt": "decrypt",
    "Key Install": "key_install",
    "Alert": "alert",
    "UserAuth": "user_auth",
}


def _parse_cp_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime, timezone
        ts = int(ts_str)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError) as exc:
        log.debug("Invalid Check Point timestamp: %s — %s", ts_str, exc)
        return ts_str


def parse_checkpoint_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        import json as _json
        try:
            data = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Check Point JSON parse failed: %s", exc)
            return {"event_type": "checkpoint", "severity": "info", "message": raw}
    else:
        return {"event_type": "checkpoint", "severity": "info", "message": str(raw)}

    result: Dict[str, Any] = {
        "event_type": "checkpoint",
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "",
        "user": "",
        "timestamp": "",
        "message": "",
        "metadata": {},
    }

    for fk, rk in CP_FIELD_MAP.items():
        val = data.get(fk)
        if val is not None and val != "":
            if rk in ("source_port", "dest_port", "source_port", "bytes_total",
                      "bytes_sent", "bytes_received", "packets_total",
                      "packets_sent", "packets_received", "duration",
                      "hit_count", "application_risk"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            result[rk] = val

    sev = result.pop("severity_raw", "low")
    if isinstance(sev, str):
        result["severity"] = SEVERITY_MAP.get(sev.lower(), "info")
    elif isinstance(sev, int):
        if sev >= 4:
            result["severity"] = "critical"
        elif sev == 3:
            result["severity"] = "high"
        elif sev == 2:
            result["severity"] = "medium"
        else:
            result["severity"] = "low"

    # action classification
    action_raw = result.get("action", data.get("action", ""))
    result["action"] = ACTION_MAP.get(action_raw, action_raw.lower() if isinstance(action_raw, str) else "")

    if result["action"] in ("deny", "drop", "reject"):
        result["severity"] = "medium"

    ts = result.get("log_deliver_time", data.get("time", data.get("timestamp", "")))
    if ts:
        if isinstance(ts, str) and ts.isdigit():
            result["timestamp"] = _parse_cp_timestamp(ts)
        else:
            result["timestamp"] = ts
    else:
        result["timestamp"] = data.get("first_hit_time", "")

    rule = result.get("rule_name", "")
    src = result.get("source_ip", "unknown")
    dst = result.get("dest_ip", "unknown")
    sp = result.get("source_port", "")
    dp = result.get("dest_port", result.get("service", ""))
    act = result.get("action", "unknown")

    result["message"] = f"Check Point: {src}:{sp} -> {dst}:{dp} rule='{rule}' action={act}"

    return result


PARSER_REGISTRY_KEY = "checkpoint"
