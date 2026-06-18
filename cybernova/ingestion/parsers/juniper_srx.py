"""
CyberNova — Juniper SRX Firewall Log Parser
Parses Juniper SRX structured syslog (traffic, IDP, events).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.juniper_srx")

SRX_LOG_TYPES = {
    "RT_FLOW": "srx_traffic",
    "RT_FW": "srx_firewall",
    "RT_IDS": "srx_idp",
    "RT_NAT": "srx_nat",
    "RT_SCREEN": "srx_screen",
    "UI_CFG": "srx_config",
    "UI_COMMIT": "srx_commit",
    "UI_AUTH": "srx_auth",
    "RT_AV": "srx_antivirus",
    "RT_UTM": "srx_utm",
    "RT_DHCP": "srx_dhcp",
    "RT_VPN": "srx_vpn",
    "RT_RPM": "srx_rpm",
    "RT_BGP": "srx_bgp",
    "RT_OSPF": "srx_ospf",
}

SRX_FIELD_MAP = {
    "source-address": "source_ip",
    "destination-address": "dest_ip",
    "source-port": "source_port",
    "destination-port": "dest_port",
    "protocol-id": "protocol",
    "protocol": "protocol",
    "service-name": "service",
    "application-name": "application",
    "nat-source-address": "nat_source_ip",
    "nat-destination-address": "nat_dest_ip",
    "nat-source-port": "nat_source_port",
    "nat-destination-port": "nat_dest_port",
    "username": "user_name",
    "roles": "user_roles",
    "policy-name": "policy_name",
    "policy-id": "policy_id",
    "interface-name": "interface",
    "from-zone": "from_zone",
    "to-zone": "to_zone",
    "incoming-interface": "incoming_interface",
    "outgoing-interface": "outgoing_interface",
    "action": "action",
    "elapsed-time": "duration",
    "bytes-from-client": "bytes_sent",
    "bytes-to-client": "bytes_received",
    "packets-from-client": "packets_sent",
    "packets-to-client": "packets_received",
    "total-packets": "packets_total",
    "total-bytes": "bytes_total",
    "session-id": "session_id",
    "session-id-32": "session_id",
    "src-nat-rule-name": "nat_rule",
    "dst-nat-rule-name": "nat_rule_dst",
    "icmp-type": "icmp_type",
    "icmp-code": "icmp_code",
    "rule-id": "rule_id",
    "attack-name": "attack_name",
    "object-name": "object_name",
    "object-type": "object_type",
}

ACTION_MAP = {
    "permit": "accept", "accept": "accept",
    "deny": "deny", "reject": "deny",
    "drop": "deny",
}

REV_ACTION_MAP = {v: k for k, v in ACTION_MAP.items()}


def _parse_srx_kv(raw: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    pairs = re.findall(r'(\S+?)="([^"]*)"|(\S+?)=(\S+)', raw)
    for full, quoted, unquoted_k, unquoted_v in pairs:
        if quoted:
            key = full
            val = quoted
        else:
            key = unquoted_k
            val = unquoted_v
        result[key] = val
    return result


def _parse_srx_tag(msg: str) -> tuple[str, str]:
    m = re.match(r'^(\w+(?:_\w+)*):\s*(.*)', msg)
    if m:
        return m.group(1), m.group(2)
    return "", msg


def parse_juniper_srx_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        import json as _json
        try:
            data = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError):
            tag, body = _parse_srx_tag(raw)
            data = _parse_srx_kv(f"log_type={tag} {body}")
    else:
        return {"event_type": "juniper_srx", "severity": "info", "message": str(raw)}

    log_type_raw = data.get("log_type", "").upper()
    mapped_type = SRX_LOG_TYPES.get(log_type_raw, f"srx_{log_type_raw.lower()}")

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "",
        "user": "",
        "timestamp": data.get("time", data.get("timestamp", data.get("datetime", ""))),
        "message": "",
        "metadata": {},
    }

    for fk, rk in SRX_FIELD_MAP.items():
        val = data.get(fk)
        if val is None:
            val = data.get(fk.replace("-", "_"))
        if val is not None and val != "":
            if rk in ("source_port", "dest_port", "source_port", "bytes_sent",
                      "bytes_received", "packets_sent", "packets_received",
                      "packets_total", "bytes_total", "session_id",
                      "policy_id", "rule_id", "duration", "icmp_type",
                      "icmp_code"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            result[rk] = val

    action_raw = result.get("action", data.get("action", ""))
    result["action"] = ACTION_MAP.get(action_raw, action_raw.lower() if isinstance(action_raw, str) else "")

    username = result.get("user_name", data.get("user", ""))
    if username:
        result["user"] = username

    if result["action"] in ("deny",):
        result["severity"] = "medium"

    src = result.get("source_ip", "unknown")
    dst = result.get("dest_ip", "unknown")
    sp = result.get("source_port", "")
    dp = result.get("dest_port", "")
    act = result.get("action", "unknown")

    result["message"] = f"SRX {mapped_type}: {src}:{sp} -> {dst}:{dp} action={act}"

    return result


PARSER_REGISTRY_KEY = "juniper_srx"
