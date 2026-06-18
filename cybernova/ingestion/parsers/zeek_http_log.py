"""
CyberNova — Zeek HTTP Log Parser
Parses Zeek http.log TSV format.
Extracts method, host, uri, status, user-agent, referrer.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.zeek_http_log")

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "trans_depth", "method", "host", "uri", "referrer", "version",
          "user_agent", "request_body_len", "response_body_len", "status_code",
          "status_msg", "info_code", "info_msg", "tags", "username",
          "password", "proxied", "orig_fuids", "orig_mime_types",
          "resp_fuids", "resp_mime_types"]

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

STATUS_CLASS = {2: "success", 3: "redirect", 4: "client_error", 5: "server_error"}
ALERT_STATUSES = {401, 403, 404, 405, 500, 502, 503, 504}

SENSITIVE_PATHS = re.compile(
    r'(/\.\.|/\.env|/wp-admin|/admin|/config|/backup|/\.git|'
    r'/sql|/phpmyadmin|/mysql|/setup|/install|/shell|/cmd|'
    r'/webshell|/actuator|/swagger|/api-docs|/.aws|/.azure)',
    re.IGNORECASE,
)

SQL_INJECTION = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|"
    r"\bDROP\b.*\bTABLE\b|\bOR\b\s+\d+\s*=\s*\d+|"
    r"'\s*OR\s*'1'\s*=\s*'1|--\s|%27|%22)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(<script|onerror=|onload=|onfocus=|onclick=|javascript:|alert\(|prompt\(|confirm\()",
    re.IGNORECASE,
)


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
    return [p.strip() for p in raw.split("\t") if p.strip()]


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime, timezone
        ts = float(ts_str)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError) as exc:
        log.debug("Invalid Zeek HTTP timestamp: %s — %s", ts_str, exc)
        return ts_str


def _detect_attack(path: str, query: str, ua: str) -> str:
    combined = f"{path} {query}"
    if SQL_INJECTION.search(combined):
        return "sql_injection"
    if XSS_PATTERN.search(combined):
        return "xss"
    if SENSITIVE_PATHS.search(path):
        return "sensitive_path_access"
    return ""


def parse_zeek_http_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("Zeek HTTP JSON parse failed: %s", exc)
                return {"event_type": "zeek_http", "severity": "info", "message": raw}
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
            if not data_line and lines and not lines[0].startswith("#"):
                data_line = lines[0].strip()
            if data_line:
                data = _parse_tsv_line(data_line, field_names)
            else:
                return {"event_type": "zeek_http", "severity": "info", "message": raw}
    else:
        return {"event_type": "zeek_http", "severity": "info", "message": str(raw)}

    ts = data.get("ts", "")
    timestamp = _parse_timestamp(ts) if ts else ""

    src_ip = data.get("id.orig_h", data.get("orig_h", data.get("src_ip", "")))
    src_port = data.get("id.orig_p", data.get("orig_p", data.get("src_port", 0)))
    dst_ip = data.get("id.resp_h", data.get("resp_h", data.get("dest_ip", "")))
    dst_port = data.get("id.resp_p", data.get("resp_p", data.get("dest_port", 0)))

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

    method = data.get("method", "").upper()
    host = data.get("host", "")
    uri = data.get("uri", "")
    referrer = data.get("referrer", data.get("referer", ""))
    version = data.get("version", "")
    user_agent = data.get("user_agent", data.get("user-agent", ""))
    raw_status = data.get("status_code", 0)
    status_msg = data.get("status_msg", "")
    request_body = data.get("request_body_len", 0)
    response_body = data.get("response_body_len", 0)
    username = data.get("username", "")
    data.get("password", "")
    tags = data.get("tags", "")
    proxied = data.get("proxied", "")
    resp_mime = data.get("resp_mime_types", data.get("mime_types", ""))

    if isinstance(raw_status, str):
        try:
            status_code = int(raw_status)
        except ValueError:
            status_code = 0
    else:
        status_code = raw_status

    if isinstance(request_body, str):
        try:
            request_body = int(request_body)
        except ValueError:
            request_body = 0
    if isinstance(response_body, str):
        try:
            response_body = int(response_body)
        except ValueError:
            response_body = 0

    path = uri
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)

    attack_type = _detect_attack(path, query, user_agent)
    status_class = STATUS_CLASS.get(status_code // 100, "unknown")

    severity = "info"
    if status_code >= 500:
        severity = "medium"
    if status_code in (401, 403):
        severity = "medium"
    if attack_type:
        severity = "high"

    event_type = "zeek_http"
    if status_code in ALERT_STATUSES:
        event_type = "zeek_http_error"

    uid = data.get("uid", "")
    trans_depth = data.get("trans_depth", "")
    info_code = data.get("info_code", "")
    info_msg = data.get("info_msg", "")
    orig_mime = data.get("orig_mime_types", "")
    resp_mime = data.get("resp_mime_types", "")

    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": "tcp",
        "timestamp": timestamp,
        "uid": uid,
        "method": method,
        "host": host,
        "uri": uri,
        "path": path,
        "query": query,
        "referrer": referrer,
        "version": version,
        "user_agent": user_agent,
        "status_code": status_code,
        "status_msg": status_msg,
        "status_class": status_class,
        "request_body_len": request_body,
        "response_body_len": response_body,
        "attack_type": attack_type,
        "username": username,
        "tags": tags,
        "proxied": proxied,
        "message": f"Zeek HTTP: {method} http://{host}{uri} -> {status_code} from {src_ip}",
        "metadata": {
            "uid": uid,
            "trans_depth": trans_depth,
            "info_code": info_code,
            "info_msg": info_msg,
            "orig_mime_types": orig_mime,
            "resp_mime_types": resp_mime,
            "has_auth": bool(username),
            "proxied": proxied,
            "tags": tags,
        },
    }


PARSER_REGISTRY_KEY = "zeek_http"
