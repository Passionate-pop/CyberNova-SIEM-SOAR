"""
CyberNova — Palo Alto PAN-OS Traffic Log Parser
Parses PAN-OS CSV/TSV traffic log exports.
Extracts session info, application, rule, bytes, and action.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.paloalto_traffic")

PAN_TRAFFIC_FIELDS = [
    "receive_time", "serial", "type", "threat_content_type", "config_ver",
    "generate_time", "src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip",
    "rule", "src_user", "dst_user", "app", "vsys", "src_zone",
    "dst_zone", "inbound_iface", "outbound_iface", "log_action",
    "time_logged", "session_id", "repeat_count", "src_port", "dst_port",
    "nat_src_port", "nat_dst_port", "flags", "protocol", "action",
    "bytes", "bytes_sent", "bytes_received", "packets", "start_time",
    "elapsed_time", "category", "padding", "seqno", "action_flags",
    "src_country", "dst_country", "cpadding", "sport", "dport",
    "nat_sport", "nat_dport", "tunnel_id", "monitor_tag",
    "parent_session_id", "parent_start_time", "tunnel", "sctp_assoc_id",
    "sctp_chunks", "sctp_chunks_sent", "sctp_chunks_received", "rule_uuid",
]

ACTION_SEVERITY = {
    "allow": "info",
    "deny": "medium",
    "drop": "medium",
    "reset-both": "medium",
    "reset-client": "medium",
    "reset-server": "medium",
    "block": "medium",
    "block-url": "medium",
    "block-ip": "medium",
}

ACTION_EVENT_TYPE = {
    "allow": "pan_traffic_allowed",
    "deny": "pan_traffic_denied",
    "drop": "pan_traffic_dropped",
    "reset-both": "pan_traffic_reset",
    "reset-client": "pan_traffic_reset",
    "reset-server": "pan_traffic_reset",
    "block": "pan_traffic_blocked",
    "block-url": "pan_traffic_url_blocked",
    "block-ip": "pan_traffic_ip_blocked",
}

APP_CATEGORIES = {
    "web-browsing", "ssl", "dns", "email", "file-sharing",
    "social-networking", "video", "audio", "database", "networking",
    "business-systems", "collaboration", "industrial", "iot",
}

KNOWN_SCANNER_PORTS = {22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017}


def _parse_value(val: str) -> Any:
    if val == "-" or val == "":
        return ""
    if val.isdigit():
        return int(val)
    try:
        return float(val)
    except ValueError:
        pass
    return val


def _parse_csv_line(line: str) -> list[str]:
    result: list[str] = []
    current = ""
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            result.append(current.strip())
            current = ""
        else:
            current += ch
    result.append(current.strip())
    return result


def _parse_tsv_line(line: str) -> list[str]:
    return [v.strip() for v in line.split("\t")]


def _parse_timestamp(ts_str: str) -> str:
    if not ts_str or ts_str == "-":
        return ""
    try:
        from datetime import datetime
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                     "%Y/%m/%d %H:%M", "%m/%d/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
        if "T" in ts_str:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.isoformat()
    except (ValueError, TypeError) as exc:
        log.debug("Invalid PAN timestamp: %s — %s", ts_str, exc)
    return ts_str


def _build_fields_map(raw: str) -> tuple[list[str], list[str]] | None:
    lines = raw.strip().split("\n")
    header_line = ""
    data_lines: list[str] = []
    for line in lines:
        ls = line.strip()
        if not ls:
            continue
        if ls.startswith("Receive Time") or ls.startswith("receive_time") or "Receive Time" in ls or "receive_time" in ls:
            header_line = ls
        elif header_line:
            data_lines.append(ls)
        else:
            if not data_lines:
                data_lines.append(ls)
    if not header_line:
        return None
    if "\t" in header_line:
        field_names = _parse_tsv_line(header_line)
        raw_fields = [_fname_to_key(f) for f in field_names]
    else:
        field_names = _parse_csv_line(header_line)
        raw_fields = [_fname_to_key(f) for f in field_names]
    if not data_lines:
        return None
    return raw_fields, data_lines


def _fname_to_key(fname: str) -> str:
    return fname.strip().lower().replace(" ", "_").replace("-", "_").replace(".", "_")


def parse_paloalto_traffic_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("PAN traffic JSON parse failed: %s", exc)
                return {"event_type": "pan_traffic", "severity": "info", "message": raw}
        else:
            fields_data = _build_fields_map(raw)
            if fields_data:
                field_names, data_lines = fields_data
                vals = _parse_csv_line(data_lines[0]) if "," in data_lines[0] else _parse_tsv_line(data_lines[0])
                data = {}
                for i, name in enumerate(field_names):
                    if i < len(vals):
                        data[name] = vals[i]
            else:
                parts = _parse_csv_line(raw) if "," in raw else _parse_tsv_line(raw)
                data = {}
                for i, name in enumerate(PAN_TRAFFIC_FIELDS):
                    if i < len(parts):
                        data[name] = parts[i]
    else:
        return {"event_type": "pan_traffic", "severity": "info", "message": str(raw)}

    action = data.get("action", data.get("Action", "allow")).lower()
    src_ip = data.get("src_ip", data.get("Source Address", data.get("source_address", data.get("SourceAddress", ""))))
    dst_ip = data.get("dst_ip", data.get("Destination Address", data.get("destination_address", data.get("DestinationAddress", ""))))
    src_port_raw = data.get("src_port", data.get("Source Port", data.get("source_port", data.get("sport", data.get("SPort", 0)))))
    dst_port_raw = data.get("dst_port", data.get("Destination Port", data.get("destination_port", data.get("dport", data.get("DPort", 0)))))
    if isinstance(src_port_raw, str):
        try:
            src_port = int(src_port_raw)
        except ValueError:
            src_port = 0
    else:
        src_port = int(src_port_raw) if src_port_raw else 0
    if isinstance(dst_port_raw, str):
        try:
            dst_port = int(dst_port_raw)
        except ValueError:
            dst_port = 0
    else:
        dst_port = int(dst_port_raw) if dst_port_raw else 0

    protocol = data.get("protocol", data.get("Protocol", "")).lower()
    app = data.get("app", data.get("App", data.get("application", data.get("Application", ""))))
    rule = data.get("rule", data.get("Rule", data.get("rule_name", data.get("Rule Name", ""))))
    src_user = data.get("src_user", data.get("Source User", data.get("source_user", data.get("SourceUser", ""))))
    dst_user = data.get("dst_user", data.get("Destination User", data.get("destination_user", "")))
    src_zone = data.get("src_zone", data.get("Source Zone", data.get("source_zone", "")))
    dst_zone = data.get("dst_zone", data.get("Destination Zone", data.get("destination_zone", "")))
    src_country = data.get("src_country", data.get("Source Country", data.get("source_country", "")))
    dst_country = data.get("dst_country", data.get("Destination Country", data.get("destination_country", "")))

    bytes_sent = data.get("bytes_sent", data.get("Bytes Sent", data.get("bytes_sent", 0)))
    if isinstance(bytes_sent, str):
        try:
            bytes_sent = int(bytes_sent)
        except ValueError:
            bytes_sent = 0
    bytes_received = data.get("bytes_received", data.get("Bytes Received", data.get("bytes_received", 0)))
    if isinstance(bytes_received, str):
        try:
            bytes_received = int(bytes_received)
        except ValueError:
            bytes_received = 0
    total_bytes = bytes_sent + bytes_received

    packets = data.get("packets", data.get("Packets", 0))
    if isinstance(packets, str):
        try:
            packets = int(packets)
        except ValueError:
            packets = 0

    elapsed = data.get("elapsed_time", data.get("Elapsed Time", data.get("elapsed_time_sec", 0)))
    if isinstance(elapsed, str):
        try:
            elapsed = int(elapsed)
        except ValueError:
            elapsed = 0

    session_id = data.get("session_id", data.get("Session ID", data.get("sessionid", "")))
    nat_src_ip = data.get("nat_src_ip", data.get("NAT Source IP", data.get("nat_source_ip", "")))
    nat_dst_ip = data.get("nat_dst_ip", data.get("NAT Destination IP", data.get("nat_destination_ip", "")))
    category = data.get("category", data.get("Category", ""))
    vsys = data.get("vsys", data.get("Virtual System", data.get("virtual_system", "")))

    ts = data.get("generate_time", data.get("Generate Time", data.get("generate_time", data.get("receive_time", data.get("Receive Time", "")))))
    timestamp = _parse_timestamp(ts) if ts else ""

    severity = ACTION_SEVERITY.get(action, "info")
    if action in ("deny", "drop", "block") and dst_port in KNOWN_SCANNER_PORTS:
        severity = "high"
    if total_bytes > 100_000_000:
        severity = "medium"
    if action in ("reset-both", "reset-client", "reset-server"):
        severity = "medium"

    event_type = ACTION_EVENT_TYPE.get(action, "pan_traffic")
    if action == "allow":
        event_type = "pan_traffic_allowed"
    elif action == "deny":
        event_type = "pan_traffic_denied"

    src_internal = src_ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                                      "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                                      "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")) if src_ip else False

    result = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": protocol,
        "app": app,
        "user": src_user or dst_user,
        "timestamp": timestamp,
        "action": action,
        "rule": rule,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "src_country": src_country,
        "dst_country": dst_country,
        "category": category,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "total_bytes": total_bytes,
        "packets": packets,
        "duration_sec": elapsed,
        "session_id": session_id,
        "nat_src_ip": nat_src_ip,
        "nat_dst_ip": nat_dst_ip,
        "source_is_internal": src_internal,
        "message": (
            f"PAN traffic {action}: {src_ip}:{src_port} ({src_zone}) -> "
            f"{dst_ip}:{dst_port} ({dst_zone}) app={app} rule={rule}"
        ),
        "metadata": {
            "vsys": vsys,
            "src_user": src_user,
            "dst_user": dst_user,
            "inbound_iface": data.get("inbound_iface", data.get("Inbound Interface", "")),
            "outbound_iface": data.get("outbound_iface", data.get("Outbound Interface", "")),
            "log_action": data.get("log_action", data.get("Log Action", "")),
            "repeat_count": data.get("repeat_count", data.get("Repeat Count", 0)),
            "serial": data.get("serial", data.get("Serial", "")),
            "flags": data.get("flags", data.get("Flags", "")),
            "rule_uuid": data.get("rule_uuid", data.get("Rule UUID", "")),
            "tunnel_id": data.get("tunnel_id", data.get("Tunnel ID/IMSI", "")),
            "nat_src_port": data.get("nat_src_port", data.get("NAT Source Port", "")),
            "nat_dst_port": data.get("nat_dst_port", data.get("NAT Destination Port", "")),
            "parent_session_id": data.get("parent_session_id", ""),
        },
    }

    return result


PARSER_REGISTRY_KEY = "paloalto_traffic"
