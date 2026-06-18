"""
CyberNova — Zeek Network Log Parser
Parses Zeek/Bro logs (conn, http, dns, ssl, smtp, dhcp, etc.).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.ingestion.parsers.zeek")

ZEEK_LOG_TYPES = {
    "conn": "zeek_conn",
    "http": "zeek_http",
    "dns": "zeek_dns",
    "ssl": "zeek_ssl",
    "smtp": "zeek_smtp",
    "dhcp": "zeek_dhcp",
    "ftp": "zeek_ftp",
    "ssh": "zeek_ssh",
    "notice": "zeek_notice",
    "weird": "zeek_weird",
    "files": "zeek_files",
    "pe": "zeek_pe",
    "x509": "zeek_x509",
    "ntp": "zeek_ntp",
    "kerberos": "zeek_kerberos",
    "rdp": "zeek_rdp",
    "smb": "zeek_smb",
    "dce_rpc": "zeek_dce_rpc",
    "mysql": "zeek_mysql",
    "modbus": "zeek_modbus",
}

CONN_STATE_MAP = {
    "S0": "connection_attempt",
    "S1": "established",
    "SF": "normal",
    "REJ": "rejected",
    "RSTO": "reset_origin",
    "RSTR": "reset_dest",
    "RSTOS0": "reset_both",
    "SH": "half_close",
    "OTH": "other",
}

SERVICE_PROTO_MAP = {
    "http": 6, "dns": 17, "ssl": 6, "smtp": 6, "ssh": 6,
    "dhcp": 17, "ftp": 6, "mysql": 6,
}


def _parse_tsv_line(line: str, columns: list[str]) -> Optional[Dict[str, str]]:
    vals = line.strip().split("\t")
    if len(vals) != len(columns):
        return None
    return dict(zip(columns, vals))


def _parse_json_zeek(data: Dict[str, Any]) -> Dict[str, Any]:
    log_type = data.get("_log_type", data.get("log_type", data.get("event_type", "zeek")))
    mapped_type = ZEEK_LOG_TYPES.get(log_type, f"zeek_{log_type}")

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "source_ip": data.get("id.orig_h", data.get("src_ip", data.get("source_ip", ""))),
        "source_port": data.get("id.orig_p", data.get("src_port", data.get("source_port", 0))),
        "dest_ip": data.get("id.resp_h", data.get("dest_ip", data.get("dst_ip", ""))),
        "dest_port": data.get("id.resp_p", data.get("dest_port", data.get("dst_port", 0))),
        "protocol": data.get("proto", ""),
        "timestamp": data.get("ts", data.get("timestamp", "")),
        "message": "",
        "metadata": {},
    }

    if log_type == "conn":
        state = data.get("conn_state", "")
        result["metadata"]["conn_state"] = state
        result["metadata"]["conn_state_label"] = CONN_STATE_MAP.get(state, state)
        result["metadata"]["duration"] = data.get("duration", 0.0)
        result["metadata"]["orig_bytes"] = data.get("orig_bytes", 0)
        result["metadata"]["resp_bytes"] = data.get("resp_bytes", 0)
        result["metadata"]["orig_pkts"] = data.get("orig_pkts", 0)
        result["metadata"]["resp_pkts"] = data.get("resp_pkts", 0)
        service = data.get("service", "")
        result["metadata"]["service"] = service
        if service:
            result["protocol"] = SERVICE_PROTO_MAP.get(service, result["protocol"])
        result["message"] = f"Zeek conn: {result['source_ip']}:{result['source_port']} -> {result['dest_ip']}:{result['dest_port']} [{state}]"
        if state == "REJ":
            result["severity"] = "medium"

    elif log_type == "http":
        result["metadata"]["method"] = data.get("method", "")
        result["metadata"]["host"] = data.get("host", "")
        result["metadata"]["uri"] = data.get("uri", "")
        result["metadata"]["referrer"] = data.get("referrer", "")
        result["metadata"]["user_agent"] = data.get("user_agent", "")
        result["metadata"]["status_code"] = data.get("status_code", 0)
        result["metadata"]["request_body_len"] = data.get("request_body_len", 0)
        result["metadata"]["response_body_len"] = data.get("response_body_len", 0)
        result["metadata"]["mime_type"] = data.get("resp_mime_types", data.get("mime_type", ""))
        result["message"] = f"Zeek HTTP: {data.get('method', '')} http://{data.get('host', '')}{data.get('uri', '')}"
        sc = data.get("status_code", 0)
        if isinstance(sc, int) and sc >= 500:
            result["severity"] = "medium"

    elif log_type == "dns":
        result["metadata"]["query"] = data.get("query", "")
        result["metadata"]["qtype"] = data.get("qtype_name", data.get("qtype", ""))
        result["metadata"]["rcode"] = data.get("rcode_name", data.get("rcode", ""))
        answers = data.get("answers", [])
        if isinstance(answers, list):
            result["metadata"]["answers"] = ",".join(str(a) for a in answers)
        else:
            result["metadata"]["answers"] = str(answers)
        result["metadata"]["rejected"] = data.get("rejected", False)
        result["message"] = f"Zeek DNS: {data.get('query', '')} -> {result['metadata']['answers']}"
        if data.get("rejected"):
            result["severity"] = "medium"

    elif log_type == "ssl":
        result["metadata"]["server_name"] = data.get("server_name", "")
        result["metadata"]["issuer"] = data.get("issuer", "")
        result["metadata"]["subject"] = data.get("subject", "")
        result["metadata"]["version"] = data.get("version", "")
        result["metadata"]["cipher"] = data.get("cipher", "")
        result["metadata"]["curve"] = data.get("curve", "")
        result["metadata"]["validation_status"] = data.get("validation_status", "")
        result["message"] = f"Zeek SSL: {result['metadata']['server_name'] or result['metadata']['subject']}"
        if data.get("validation_status") not in ("ok", "", None):
            result["severity"] = "medium"

    elif log_type == "notice":
        note = data.get("note", "")
        msg = data.get("msg", "")
        sub = data.get("sub", "")
        result["severity"] = "medium"
        result["metadata"]["note"] = note
        result["metadata"]["msg"] = msg
        result["metadata"]["sub"] = sub
        result["metadata"]["notice_type"] = data.get("notice_type", "")
        result["message"] = f"Zeek notice: {msg or note}"

    else:
        result["message"] = f"Zeek {log_type} event"
        result["metadata"] = {k: v for k, v in data.items()
                              if k not in ("ts", "uid", "source_ip", "dest_ip")}

    return result


def _parse_tsv(raw: str) -> Dict[str, Any]:
    lines = raw.strip().split("\n")
    header_idx = -1
    for i, line in enumerate(lines):
        if line.startswith("#fields"):
            header_idx = i
            break

    if header_idx == -1:
        return {"event_type": "zeek", "severity": "info", "message": raw}

    sep_line = lines[header_idx]
    columns = sep_line.split("\t")[1:]  # remove #fields prefix

    data_lines = []
    for line in lines[header_idx + 1:]:
        if line.startswith("#"):
            continue
        if line.strip():
            data_lines.append(line)

    if not data_lines:
        return {"event_type": "zeek", "severity": "info", "message": raw}

    parsed = _parse_tsv_line(data_lines[0], columns)
    if not parsed:
        return {"event_type": "zeek", "severity": "info", "message": raw}

    return _parse_json_zeek(parsed)


def parse_zeek_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return _parse_json_zeek(raw)

    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                return _parse_json_zeek(_json.loads(raw))
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("Zeek JSON parse failed: %s", exc)
        if raw.startswith("#separator") or raw.startswith("#fields"):
            return _parse_tsv(raw)

    return {"event_type": "zeek", "severity": "info", "message": str(raw)}


PARSER_REGISTRY_KEY = "zeek"
