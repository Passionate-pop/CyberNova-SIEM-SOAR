"""
CyberNova — Apache / Nginx Web Server Log Parser
Parses combined/common log format and JSON access logs.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.ingestion.parsers.web_server")

COMBINED_LOG_RE = re.compile(
    r'(\S+)\s+'                    # IP
    r'(\S+)\s+'                    # ident
    r'(\S+)\s+'                    # user
    r'\[([^\]]+)\]\s+'             # datetime
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+' # method, path, protocol
    r'(\d+)\s+'                    # status
    r'(\d+|-)\s*'                  # bytes
    r'(?:"([^"]*)"\s+)?'          # referer (optional)
    r'(?:"([^"]*)")?',             # user-agent
)

STATUS_CLASS = {
    2: "success", 3: "redirect", 4: "client_error", 5: "server_error",
}

SUSPICIOUS_PATHS = re.compile(
    r'(/\.\.|/\.env|/wp-admin|/admin|/config|/backup|/\.git|'
    r'/sql|/phpmyadmin|/mysql|/setup|/install|/shell|/cmd|'
    r'/(webshell|shell|cmd|exec|eval|assert))',
    re.IGNORECASE,
)

SUSPICIOUS_EXTENSIONS = re.compile(
    r'\.(php\d*|asp|aspx|jsp|pl|cgi|exe|sh|py|eval|cmd)$', re.IGNORECASE,
)

SQL_INJECTION = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|"
    r"\bDROP\b.*\bTABLE\b|\bOR\b\s+\d+\s*=\s*\d+|"
    r"'\s*OR\s*'1'\s*=\s*'1|--\s|%27|%22)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(<script|onerror=|onload=|javascript:|alert\(|%3Cscript|%3Csvg)",
    re.IGNORECASE,
)


def _classify_status( status_code: int) -> str:
    return STATUS_CLASS.get(status_code // 100, "unknown")


def _detect_attack( path: str, query: str, ua: str) -> Optional[str]:
    combined = f"{path} {query}"
    if SUSPICIOUS_PATHS.search(path):
        return "path_traversal"
    if SQL_INJECTION.search(combined):
        return "sql_injection"
    if XSS_PATTERN.search(combined):
        return "xss"
    if SUSPICIOUS_EXTENSIONS.search(path):
        return "suspicious_file"
    known_bad_agents = {"nikto", "sqlmap", "nmap", "acunetix", "nessus", "openvas", "burp", "zap", "dirb", "gobuster", "wfuzz"}
    if ua and any(bad in ua.lower() for bad in known_bad_agents):
        return "scanner"
    return None


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except (ValueError, TypeError) as exc:
        log.debug("Failed to parse web log timestamp: %s — %s", ts_str, exc)
        return ts_str


def parse_web_server_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return _parse_json_format(raw)
    if not isinstance(raw, str):
        return {"event_type": "web_server", "severity": "info", "message": str(raw)}

    raw = raw.strip()
    if raw.startswith("{"):
        import json as _json
        try:
            return _parse_json_format(_json.loads(raw))
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Web log JSON parse failed: %s", exc)

    m = COMBINED_LOG_RE.match(raw)
    if not m:
        return {"event_type": "web_server", "severity": "info", "message": raw}

    ip = m.group(1)
    user = m.group(3) if m.group(3) != "-" else ""
    timestamp = _parse_timestamp(m.group(4))
    method = m.group(5)
    path = m.group(6)
    protocol = m.group(7)
    status_str = m.group(8)
    bytes_str = m.group(9)
    referer = m.group(10) or ""
    user_agent = m.group(11) or ""

    try:
        status_code = int(status_str)
    except ValueError:
        status_code = 0
    try:
        bytes_sent = int(bytes_str) if bytes_str != "-" else 0
    except ValueError:
        bytes_sent = 0

    query = ""
    if "?" in path:
        path, query = path.split("?", 1)

    attack_type = _detect_attack(path, query, user_agent)
    status_class = _classify_status(status_code)

    severity = "info"
    if status_code >= 500:
        severity = "medium"
    if status_code == 403:
        severity = "medium"
    if attack_type:
        severity = "high"

    return {
        "event_type": "web_server",
        "severity": severity,
        "source_ip": ip,
        "user": user,
        "timestamp": timestamp,
        "method": method,
        "path": path,
        "query": query,
        "protocol": protocol,
        "status_code": status_code,
        "status_class": status_class,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "user_agent": user_agent,
        "attack_type": attack_type or "",
        "message": f"{method} {path} -> {status_code} from {ip}",
        "metadata": {
            "server_type": "unknown",
        },
    }


def _parse_json_format(data: Dict[str, Any]) -> Dict[str, Any]:
    ip = data.get("remote_ip", data.get("ip", data.get("client_ip", "")))
    method = data.get("method", data.get("request_method", ""))
    path = data.get("path", data.get("uri", data.get("request", "")))
    status = data.get("status", data.get("status_code", 0))
    ua = data.get("user_agent", data.get("agent", ""))
    ts = data.get("timestamp", data.get("time", ""))
    referer = data.get("referer", data.get("referrer", ""))
    body_bytes = data.get("body_bytes", data.get("bytes", data.get("size", 0)))
    user = data.get("user", data.get("remote_user", ""))
    protocol = data.get("protocol", data.get("http_version", ""))

    query = ""
    if "?" in path:
        path, query = path.split("?", 1)

    try:
        status_code = int(status)
    except (ValueError, TypeError):
        status_code = 0
    try:
        bytes_sent = int(body_bytes)
    except (ValueError, TypeError):
        bytes_sent = 0

    attack_type = _detect_attack(path, query, ua)
    status_class = _classify_status(status_code)

    severity = "info"
    if status_code >= 500:
        severity = "medium"
    if status_code == 403:
        severity = "medium"
    if attack_type:
        severity = "high"

    return {
        "event_type": "web_server",
        "severity": severity,
        "source_ip": ip,
        "user": user,
        "timestamp": ts,
        "method": method,
        "path": path,
        "query": query,
        "protocol": protocol,
        "status_code": status_code,
        "status_class": status_class,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "user_agent": ua,
        "attack_type": attack_type or "",
        "message": f"{method} {path} -> {status_code} from {ip}",
        "metadata": {"server_type": "json"},
    }


PARSER_REGISTRY_KEY = "web_server"
