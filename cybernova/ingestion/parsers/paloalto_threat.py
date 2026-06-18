"""
CyberNova — Palo Alto PAN-OS Threat Log Parser
Parses PAN-OS CSV/TSV threat log exports.
Extracts threat ID, category, severity, URL/file, action.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.paloalto_threat")

PAN_THREAT_FIELDS = [
    "receive_time", "serial", "type", "threat_content_type", "config_ver",
    "generate_time", "src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip",
    "rule", "src_user", "dst_user", "app", "vsys", "src_zone",
    "dst_zone", "inbound_iface", "outbound_iface", "log_action",
    "time_logged", "session_id", "repeat_count", "src_port", "dst_port",
    "nat_src_port", "nat_dst_port", "flags", "protocol", "action",
    "url", "threat_id", "category", "severity", "direction", "seqno",
    "action_flags", "src_country", "dst_country", "content_type",
    "pcap_id", "filedigest", "file", "http_method", "user_agent",
    "app_category", "app_subcategory", "app_technology", "app_risk",
    "app_id", "subtype", "cloud", "cloud_app_id", "cloud_app_name",
    "cloud_app_category", "cloud_app_risk", "cloud_certificate",
    "cloud_issuer", "cloud_san", "cloud_serial",
]

SUBTYPE_EVENT_TYPE = {
    "vulnerability": "pan_threat_vulnerability",
    "spyware": "pan_threat_spyware",
    "url": "pan_threat_url_filtering",
    "file": "pan_threat_file_block",
    "data": "pan_threat_data_filtering",
    "wildfire": "pan_threat_wildfire",
    "virus": "pan_threat_virus",
    "botnet": "pan_threat_botnet",
    "dns": "pan_threat_dns_tunnel",
    "phishing": "pan_threat_phishing",
    "ransomware": "pan_threat_ransomware",
    "scan": "pan_threat_recon",
    "info": "pan_threat_info",
}

ACTION_SEVERITY = {
    "alert": "medium",
    "allow": "info",
    "block": "high",
    "drop": "high",
    "reset-both": "high",
    "reset-client": "high",
    "reset-server": "high",
    "block-url": "medium",
    "block-ip": "high",
}

MITRE_MAP = {
    "vulnerability": {"tactic": "initial_access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},
    "spyware": {"tactic": "collection", "technique": "T1056", "technique_name": "Input Capture"},
    "url": {"tactic": "initial_access", "technique": "T1566", "technique_name": "Phishing"},
    "file": {"tactic": "defense_evasion", "technique": "T1202", "technique_name": "Indirect Command Execution"},
    "wildfire": {"tactic": "execution", "technique": "T1204", "technique_name": "User Execution"},
    "virus": {"tactic": "execution", "technique": "T1204", "technique_name": "User Execution"},
    "botnet": {"tactic": "command_and_control", "technique": "T1071", "technique_name": "Application Layer Protocol"},
    "dns": {"tactic": "command_and_control", "technique": "T1572", "technique_name": "Protocol Tunneling"},
    "phishing": {"tactic": "initial_access", "technique": "T1566", "technique_name": "Phishing"},
    "ransomware": {"tactic": "impact", "technique": "T1486", "technique_name": "Data Encrypted for Impact"},
    "scan": {"tactic": "reconnaissance", "technique": "T1595", "technique_name": "Active Scanning"},
}

THREAT_SEVERITY_PAN = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "informational": "info",
}


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


KNOWN_RECON_PORTS = {22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017}
SENSITIVE_DATA_CATEGORIES = {"credit-card", "ssn", "pci", "phi", "pii", "bank-account", "password"}


def parse_paloalto_threat_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("PAN threat JSON parse failed: %s", exc)
                return {"event_type": "pan_threat", "severity": "medium", "message": raw}
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
                for i, name in enumerate(PAN_THREAT_FIELDS):
                    if i < len(parts):
                        data[name] = parts[i]
    else:
        return {"event_type": "pan_threat", "severity": "medium", "message": str(raw)}

    subtype = data.get("subtype", data.get("Subtype", "")).lower()
    threat_id = data.get("threat_id", data.get("Threat ID", data.get("threatid", "")))
    threat_name = data.get("threat_name", data.get("Threat Name", data.get("threatname", data.get("file", ""))))
    action = data.get("action", data.get("Action", "alert")).lower()
    url = data.get("url", data.get("URL", data.get("URI", "")))
    category = data.get("category", data.get("Category", ""))
    direction = data.get("direction", data.get("Direction", "inbound")).lower()
    content_type = data.get("content_type", data.get("Content Type", data.get("contenttype", "")))
    file_name = data.get("file", data.get("File", ""))
    filedigest = data.get("filedigest", data.get("Filedigest", data.get("file_digest", "")))
    http_method = data.get("http_method", data.get("HTTP Method", data.get("httpmethod", "")))
    user_agent = data.get("user_agent", data.get("User Agent", data.get("useragent", "")))

    src_ip = data.get("src_ip", data.get("Source Address", data.get("source_address", data.get("SourceAddress", ""))))
    dst_ip = data.get("dst_ip", data.get("Destination Address", data.get("destination_address", data.get("DestinationAddress", ""))))
    src_port_raw = data.get("src_port", data.get("Source Port", data.get("source_port", data.get("sport", "0"))))
    dst_port_raw = data.get("dst_port", data.get("Destination Port", data.get("destination_port", data.get("dport", "0"))))
    try:
        src_port = int(src_port_raw) if src_port_raw else 0
    except (ValueError, TypeError):
        src_port = 0
    try:
        dst_port = int(dst_port_raw) if dst_port_raw else 0
    except (ValueError, TypeError):
        dst_port = 0

    protocol = data.get("protocol", data.get("Protocol", "")).lower()
    app = data.get("app", data.get("App", data.get("application", data.get("Application", ""))))
    rule = data.get("rule", data.get("Rule", data.get("rule_name", "")))
    src_user = data.get("src_user", data.get("Source User", ""))
    dst_user = data.get("dst_user", data.get("Destination User", ""))
    src_zone = data.get("src_zone", data.get("Source Zone", ""))
    dst_zone = data.get("dst_zone", data.get("Destination Zone", ""))
    src_country = data.get("src_country", data.get("Source Country", ""))
    dst_country = data.get("dst_country", data.get("Destination Country", ""))
    session_id = data.get("session_id", data.get("Session ID", ""))
    vsys = data.get("vsys", data.get("Virtual System", ""))
    nat_src_ip = data.get("nat_src_ip", data.get("NAT Source IP", ""))
    nat_dst_ip = data.get("nat_dst_ip", data.get("NAT Destination IP", ""))

    sev_raw = data.get("severity", data.get("Severity", "medium")).lower()
    severity = THREAT_SEVERITY_PAN.get(sev_raw) or ACTION_SEVERITY.get(action, "medium")

    ts = data.get("generate_time", data.get("Generate Time", data.get("receive_time", data.get("Receive Time", ""))))
    timestamp = _parse_timestamp(ts) if ts else ""

    event_type = SUBTYPE_EVENT_TYPE.get(subtype, "pan_threat")
    if action in ("block", "drop", "reset-both", "block-ip", "block-url") and severity == "medium":
        severity = "high"
    if subtype == "ransomware":
        severity = "critical"

    mitre = MITRE_MAP.get(subtype, {})

    src_internal = bool(src_ip and (src_ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                                       "172.20.", "172.21.", "172.22.", "172.23.",
                                                       "172.24.", "172.25.", "172.26.", "172.27.",
                                                       "172.28.", "172.29.", "172.30.", "172.31.",
                                                       "192.168.")) or src_ip == "127.0.0.1"))

    is_sensitive = category.lower() in SENSITIVE_DATA_CATEGORIES

    message_parts = [f"PAN threat: {subtype or 'unknown'}"]
    if threat_name:
        message_parts.append(threat_name)
    if threat_id:
        message_parts.append(f"[ID:{threat_id}]")
    message_parts.append(f"{action}: {src_ip} -> {dst_ip}")
    if url:
        message_parts.append(f"url={url}")
    if file_name:
        message_parts.append(f"file={file_name}")

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
        "direction": direction,
        "threat_id": threat_id,
        "threat_name": threat_name,
        "subtype": subtype,
        "url": url,
        "file_name": file_name,
        "file_hash": filedigest,
        "http_method": http_method,
        "user_agent": user_agent,
        "content_type": content_type,
        "category": category,
        "src_country": src_country,
        "dst_country": dst_country,
        "session_id": session_id,
        "source_is_internal": src_internal,
        "message": " ".join(message_parts),
        "metadata": {
            "vsys": vsys,
            "nat_src_ip": nat_src_ip,
            "nat_dst_ip": nat_dst_ip,
            "src_user": src_user,
            "dst_user": dst_user,
            "inbound_iface": data.get("inbound_iface", ""),
            "outbound_iface": data.get("outbound_iface", ""),
            "log_action": data.get("log_action", ""),
            "repeat_count": data.get("repeat_count", 0),
            "serial": data.get("serial", ""),
            "flags": data.get("flags", ""),
            "pcap_id": data.get("pcap_id", data.get("PCAP ID", "")),
            "action_flags": data.get("action_flags", ""),
            "cloud_app": data.get("cloud_app_name", ""),
            "is_sensitive_data": is_sensitive,
        },
    }

    if mitre:
        result["metadata"]["mitre_tactic"] = mitre["tactic"]
        result["metadata"]["mitre_technique_id"] = mitre["technique"]
        result["metadata"]["mitre_technique_name"] = mitre["technique_name"]

    return result


PARSER_REGISTRY_KEY = "paloalto_threat"
