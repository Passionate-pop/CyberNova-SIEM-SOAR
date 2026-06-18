"""
CyberNova — Zeek Connection Log Parser
Parses Zeek conn.log TSV format.
Maps conn_state to event_type, extracts network flow metadata.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.zeek_conn_log")

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "conn_state", "local_orig", "local_resp", "missed_bytes",
          "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
          "tunnel_parents"]

TYPES = ["time", "string", "addr", "port", "addr", "port",
         "enum", "string", "interval", "count", "count",
         "string", "bool", "bool", "count",
         "string", "count", "count", "count", "count",
         "set[string]"]

CONN_STATE_MAP = {
    "S0": "connection_attempt",
    "S1": "connection_established",
    "SF": "normal_established",
    "REJ": "connection_rejected",
    "RSTO": "reset_origin",
    "RSTR": "reset_dest",
    "RSTOS0": "reset_both",
    "SH": "half_close_origin",
    "SHR": "half_close_dest",
    "OTH": "one_sided_traffic",
}

HISTORY_ACTION_MAP = {
    "S": "syn_sent", "H": "syn_ack", "A": "ack", "D": "data",
    "F": "fin", "R": "rst", "C": "conn_pending", "I": "incomplete",
    "Q": "reassembly_failed", "T": "tls_handshake",
    "^": "no_conn_syn", "d": "data_drop",
}

SERVICE_PROTO_MAP = {
    "http": "tcp", "dns": "udp", "ssl": "tcp", "smtp": "tcp",
    "ssh": "tcp", "ftp": "tcp", "mysql": "tcp", "rdp": "tcp",
    "dhcp": "udp", "ntp": "udp", "snmp": "udp", "sip": "udp",
}

HIGH_BYTES_THRESHOLD = 10_000_000
LARGE_TRANSFER_THRESHOLD = 100_000_000


def _parse_tsv_line(line: str, fields: list[str]) -> Dict[str, str]:
    vals = line.strip().split("\t")
    result: Dict[str, str] = {}
    for i, name in enumerate(fields):
        if i < len(vals):
            val = vals[i]
            if val != "-":
                result[name] = val
    return result


def _parse_fields_header(line: str) -> list[str]:
    raw = line.strip()
    if raw.startswith("#fields"):
        raw = raw[7:].strip()
    parts = raw.split("\t")
    return [p.strip() for p in parts if p.strip()]


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime, timezone
        ts = float(ts_str)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError) as exc:
        log.debug("Invalid Zeek conn timestamp: %s — %s", ts_str, exc)
        return ts_str


def parse_zeek_conn_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("Zeek conn JSON parse failed: %s", exc)
                return {"event_type": "zeek_conn", "severity": "info", "message": raw}
        else:
            lines = raw.split("\n")
            field_names = FIELDS
            for line in lines:
                if line.startswith("#fields"):
                    field_names = _parse_fields_header(line)
                    break
            data_line = ""
            for line in lines:
                ls = line.strip()
                if ls and not ls.startswith("#"):
                    data_line = ls
                    break
            if not data_line:
                if lines and not lines[0].startswith("#"):
                    data_line = lines[0].strip()
            if data_line:
                data = _parse_tsv_line(data_line, field_names)
            else:
                return {"event_type": "zeek_conn", "severity": "info", "message": raw}
    else:
        return {"event_type": "zeek_conn", "severity": "info", "message": str(raw)}

    ts = data.get("ts", "")
    timestamp = _parse_timestamp(ts) if ts else ""

    src_ip = data.get("id.orig_h", data.get("src_ip", data.get("orig_h", "")))
    src_port = data.get("id.orig_p", data.get("src_port", data.get("orig_p", 0)))
    dst_ip = data.get("id.resp_h", data.get("dest_ip", data.get("dst_ip", data.get("resp_h", ""))))
    dst_port = data.get("id.resp_p", data.get("dest_port", data.get("dst_port", data.get("resp_p", 0))))
    proto = data.get("proto", "").lower()
    service = data.get("service", "")

    if isinstance(src_port, str):
        try:
            src_port = int(src_port)
        except ValueError:
            src_port = 0
    if isinstance(dst_port, str):
        try:
            dst_port = int(dst_port)
        except ValueError:
            dst_port = 0

    conn_state = data.get("conn_state", "")
    state_label = CONN_STATE_MAP.get(conn_state, conn_state)

    orig_bytes = data.get("orig_bytes", 0)
    resp_bytes = data.get("resp_bytes", 0)
    if isinstance(orig_bytes, str):
        try:
            orig_bytes = int(orig_bytes)
        except ValueError:
            orig_bytes = 0
    if isinstance(resp_bytes, str):
        try:
            resp_bytes = int(resp_bytes)
        except ValueError:
            resp_bytes = 0
    total_bytes = orig_bytes + resp_bytes

    orig_pkts = data.get("orig_pkts", 0)
    resp_pkts = data.get("resp_pkts", 0)
    if isinstance(orig_pkts, str):
        try:
            orig_pkts = int(orig_pkts)
        except ValueError:
            orig_pkts = 0
    if isinstance(resp_pkts, str):
        try:
            resp_pkts = int(resp_pkts)
        except ValueError:
            resp_pkts = 0

    duration = data.get("duration", 0)
    if isinstance(duration, str):
        try:
            duration = float(duration)
        except ValueError:
            duration = 0.0

    missed_bytes = data.get("missed_bytes", 0)
    if isinstance(missed_bytes, str):
        try:
            missed_bytes = int(missed_bytes)
        except ValueError:
            missed_bytes = 0

    history = data.get("history", "")
    uid = data.get("uid", "")
    tunnel_parents = data.get("tunnel_parents", "")

    history_actions = []
    if history:
        for ch in history:
            history_actions.append(HISTORY_ACTION_MAP.get(ch, ch))

    severity = "info"
    if conn_state == "REJ":
        severity = "medium"
    if conn_state == "S0" and missed_bytes > 100:
        severity = "medium"
    if total_bytes > LARGE_TRANSFER_THRESHOLD:
        severity = "medium"
    if orig_pkts == 0 and resp_pkts > 1000:
        severity = "medium"

    event_type = "zeek_conn"
    if conn_state == "REJ":
        event_type = "zeek_conn_rejected"
    elif conn_state == "S0":
        event_type = "zeek_conn_attempt"
    elif total_bytes > HIGH_BYTES_THRESHOLD:
        event_type = "zeek_conn_large_transfer"

    if service and not proto:
        proto = SERVICE_PROTO_MAP.get(service, proto)

    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": proto,
        "timestamp": timestamp,
        "uid": uid,
        "service": service,
        "conn_state": conn_state,
        "conn_state_label": state_label,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "total_bytes": total_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "missed_bytes": missed_bytes,
        "history": history,
        "history_actions": history_actions,
        "local_orig": data.get("local_orig", ""),
        "local_resp": data.get("local_resp", ""),
        "tunnel_parents": tunnel_parents,
        "message": (
            f"Zeek conn {conn_state}: {src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port} proto={proto} "
            f"{orig_pkts}pkts/{orig_bytes}bytes -> {resp_pkts}pkts/{resp_bytes}bytes"
        ),
        "metadata": {
            "uid": uid,
            "history": history,
            "tunnel_parents": tunnel_parents,
            "local_orig": data.get("local_orig", ""),
            "local_resp": data.get("local_resp", ""),
        },
    }


PARSER_REGISTRY_KEY = "zeek_conn"
