"""
CyberNova — Apache HTTP Access Log Parser
Parses Apache combined/common log format.
Extracts method, path, status, user-agent, referer.
Generates HTTP-scoped event types for detection.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.apache_access")

COMBINED_LOG_RE = re.compile(
    r'(?P<remote_addr>\S+)\s+'          # IP
    r'(?P<ident>\S+)\s+'                # identd
    r'(?P<remote_user>\S+)\s+'          # auth user
    r'\[(?P<time_local>[^\]]+)\]\s+'    # datetime
    r'"(?P<method>\S+)\s+'              # HTTP method
    r'(?P<path>\S+)\s+'                 # URI path
    r'(?P<protocol>\S+)"\s+'            # HTTP version
    r'(?P<status>\d+)\s+'              # status code
    r'(?P<body_bytes>\d+|-)\s*'         # bytes sent
    r'(?:"(?P<referer>[^"]*)"\s+)?'     # referer
    r'(?:"(?P<user_agent>[^"]*)")?'     # user-agent
)

COMMON_LOG_RE = re.compile(
    r'(?P<remote_addr>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>\S+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<body_bytes>\d+|-)'
)

HTTP_EVENT_TYPES = {
    "GET": "http_get_request",
    "POST": "http_post_request",
    "PUT": "http_put_request",
    "PATCH": "http_patch_request",
    "DELETE": "http_delete_request",
    "HEAD": "http_head_request",
    "OPTIONS": "http_options_request",
    "CONNECT": "http_connect_request",
    "TRACE": "http_trace_request",
}

STATUS_CLASS = {
    2: "success", 3: "redirect", 4: "client_error", 5: "server_error",
}

ALERT_STATUSES = {401, 403, 404, 405, 500, 502, 503, 504}

SENSITIVE_PATHS = re.compile(
    r'(/\.\.|/\.env|/wp-admin|/admin|/config|/backup|/\.git|'
    r'/sql|/phpmyadmin|/mysql|/setup|/install|/shell|/cmd|'
    r'/webshell|/actuator|/swagger|/api-docs|/.aws|/.azure)',
    re.IGNORECASE,
)

SUSPICIOUS_EXT = re.compile(
    r'\.(php\d*|asp|aspx|jsp|pl|cgi|exe|sh|py|jar|war|eval|cmd)$',
    re.IGNORECASE,
)

SQL_INJECTION = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|"
    r"\bDROP\b.*\bTABLE\b|\bOR\b\s+\d+\s*=\s*\d+|"
    r"'\s*OR\s*'1'\s*=\s*'1|--\s|%27|%22|\bWAITFOR\b.*\bDELAY\b)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(<script|onerror=|onload=|onfocus=|onclick=|"
    r"javascript:|alert\(|%3Cscript|%3Csvg|%3Cimg|"
    r"<img.*\bonerror|<svg.*\bonload)",
    re.IGNORECASE,
)

PATH_TRAVERSAL = re.compile(
    r'(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%00|\.\.%5c)',
    re.IGNORECASE,
)

SCANNER_AGENTS = {
    "nikto", "sqlmap", "nmap", "nessus", "openvas", "acunetix",
    "burp", "burpsuite", "zap", "owasp", "dirb", "gobuster",
    "wfuzz", "ffuf", "hydra", "medusa", "ncrack", "masscan",
    "whatweb", "wpscan", "joomscan", "droopescan",
}


def _classify_status(status_code: int) -> str:
    return STATUS_CLASS.get(status_code // 100, "unknown")


def _detect_attack(method: str, path: str, query: str, ua: str) -> str:
    combined = f"{path} {query}"
    if PATH_TRAVERSAL.search(combined):
        return "path_traversal"
    if SQL_INJECTION.search(combined):
        return "sql_injection"
    if XSS_PATTERN.search(combined):
        return "xss"
    if SENSITIVE_PATHS.search(path):
        return "sensitive_path_access"
    if SUSPICIOUS_EXT.search(path):
        return "suspicious_file_access"
    if ua and any(bot in ua.lower() for bot in SCANNER_AGENTS):
        return "scanner"
    return ""


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except (ValueError, TypeError) as exc:
        log.debug("Failed to parse Apache timestamp: %s — %s", ts_str, exc)
        return ts_str


def _classify_apache_severity(status_code: int, attack_type: str, method: str) -> str:
    if attack_type:
        return "high"
    if status_code >= 500:
        return "medium"
    if status_code == 403 or status_code == 401:
        return "medium"
    if status_code == 404 and method == "POST":
        return "medium"
    return "info"


def _json_fallback(raw: str) -> Dict[str, Any] | None:
    import json as _json
    try:
        data = _json.loads(raw)
        if isinstance(data, dict) and any(k in data for k in ("remote_ip", "method", "request", "status")):
            return data
    except (ValueError, _json.JSONDecodeError):
        pass
    return None


def parse_apache_access_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        data = _json_fallback(raw)
        if data is None:
            m = COMBINED_LOG_RE.match(raw)
            if not m:
                m = COMMON_LOG_RE.match(raw)
            if not m:
                return {"event_type": "apache_access", "severity": "info", "message": raw}
            data = m.groupdict()
    else:
        return {"event_type": "apache_access", "severity": "info", "message": str(raw)}

    ip = data.get("remote_addr", data.get("remote_ip", data.get("source_ip", "")))
    method = data.get("method", data.get("request_method", "")).upper()
    path = data.get("path", data.get("uri", data.get("request", "")))
    protocol = data.get("protocol", data.get("http_version", ""))
    raw_status = data.get("status", data.get("status_code", 0))
    raw_bytes = data.get("body_bytes", data.get("bytes", data.get("size", data.get("body_bytes_sent", 0))))
    referer = data.get("referer", data.get("http_referer", ""))
    user_agent = data.get("user_agent", data.get("http_user_agent", data.get("agent", "")))
    user = data.get("remote_user", data.get("user", ""))
    ts_str = data.get("time_local", data.get("time", data.get("timestamp", "")))

    try:
        status_code = int(raw_status)
    except (ValueError, TypeError):
        status_code = 0
    try:
        body_bytes = int(raw_bytes) if raw_bytes not in (None, "", "-") else 0
    except (ValueError, TypeError):
        body_bytes = 0

    query = ""
    if "?" in path:
        path, query = path.split("?", 1)

    timestamp = _parse_timestamp(ts_str) if ts_str else ts_str

    attack_type = _detect_attack(method, path, query, user_agent)
    status_class = _classify_status(status_code)
    severity = _classify_apache_severity(status_code, attack_type, method)
    event_type = HTTP_EVENT_TYPES.get(method, "http_request")

    if status_code in ALERT_STATUSES:
        event_type = f"{event_type}_error"

    return {
        "event_type": event_type,
        "source_ip": ip,
        "user": user,
        "method": method,
        "path": path,
        "query": query,
        "protocol": protocol,
        "status_code": status_code,
        "status_class": status_class,
        "body_bytes": body_bytes,
        "referer": referer,
        "user_agent": user_agent,
        "attack_type": attack_type,
        "severity": severity,
        "timestamp": timestamp,
        "message": f"{method} {path} -> {status_code} from {ip}",
        "metadata": {
            "ident": data.get("ident", ""),
            "request_uri": data.get("request", ""),
            "response_time_ms": data.get("response_time", data.get("duration_ms", 0)),
        },
    }


PARSER_REGISTRY_KEY = "apache_access"
