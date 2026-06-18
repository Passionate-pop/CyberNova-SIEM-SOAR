"""
CyberNova — Nginx HTTP Access Log Parser
Parses Nginx combined/log_format access logs.
Same as Apache, with Nginx-specific field handling.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.nginx_access")

NGINX_COMBINED_RE = re.compile(
    r'(?P<remote_addr>\S+)\s+'          # IP
    r'(?P<ident>\S+)\s+'                # identd
    r'(?P<remote_user>\S+)\s+'          # auth user
    r'\[(?P<time_local>[^\]]+)\]\s+'    # datetime
    r'"(?P<method>\S+)\s+'              # HTTP method
    r'(?P<path>\S+)\s+'                 # URI path
    r'(?P<protocol>\S+)"\s+'            # HTTP version
    r'(?P<status>\d+)\s+'              # status
    r'(?P<body_bytes>\d+|-)\s*'         # bytes sent
    r'"(?:"[^"]*"|[^"]*)"\s+'          # referer
    r'"(?:"[^"]*"|[^"]*)"\s*'          # user-agent
    r'(?P<gzip_ratio>\S+)?'             # optional gzip ratio
)

NGINX_JSON_RE = re.compile(
    r'\{(?:"[^"]*"\s*:\s*"[^"]*"\s*,?\s*)*\}',
)

EVENT_TYPES = {
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

STATUS_CLASS = {2: "success", 3: "redirect", 4: "client_error", 5: "server_error"}
ALERT_STATUSES = {401, 403, 404, 405, 429, 500, 502, 503, 504}

SENSITIVE_PATHS = re.compile(
    r'(/\.\.|/\.env|/wp-admin|/admin|/config|/backup|/\.git|'
    r'/sql|/phpmyadmin|/mysql|/setup|/install|/shell|/cmd|'
    r'/webshell|/actuator|/swagger|/api-docs|/.aws|/.azure|'
    r'/vendor|/composer|/package\.json|/console|/proxy|'
    r'/server-status|/server-info|/metrics)',
    re.IGNORECASE,
)

SUSPICIOUS_EXT = re.compile(
    r'\.(php\d*|asp|aspx|jsp|pl|cgi|exe|sh|py|jar|war|eval|cmd)$',
    re.IGNORECASE,
)

SQL_INJECTION = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|"
    r"\bDROP\b.*\bTABLE\b|\bOR\b\s+\d+\s*=\s*\d+|"
    r"'\s*OR\s*'1'\s*=\s*'1|--\s|%27|%22|"
    r"\bWAITFOR\b.*\bDELAY\b|pg_sleep|dbms_lock)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(<script|onerror=|onload=|onfocus=|onclick=|"
    r"javascript:|alert\(|%3Cscript|%3Csvg|%3Cimg|"
    r"<img.*\bonerror|<svg.*\bonload|prompt\(|confirm\()",
    re.IGNORECASE,
)

PATH_TRAVERSAL = re.compile(
    r'(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%00|\.\.%5c|\.\.%252f)',
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
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except (ValueError, TypeError):
            log.debug("Failed to parse Nginx timestamp: %s — %s", ts_str, exc)
            return ts_str


def _classify_nginx_severity(status_code: int, attack_type: str, method: str) -> str:
    if attack_type:
        return "high"
    if status_code >= 500:
        return "medium"
    if status_code in (401, 403, 429):
        return "medium"
    if status_code == 404 and method in ("POST", "PUT", "DELETE", "PATCH"):
        return "medium"
    return "info"


def _is_nginx_json(raw: str) -> Dict[str, Any] | None:
    import json as _json
    try:
        data = _json.loads(raw)
        if isinstance(data, dict):
            for key in ("request", "method", "uri", "status", "remote_addr", "connection"):
                if key in data:
                    return data
    except (ValueError, _json.JSONDecodeError):
        pass
    return None


def _split_request(request: str, result: Dict[str, Any]) -> None:
    parts = request.split()
    if len(parts) >= 1:
        result["method"] = parts[0].upper()
    if len(parts) >= 2:
        result["path"] = parts[1]
    if len(parts) >= 3:
        result["protocol"] = parts[2]


def _parse_upstream(upstream: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if not upstream or upstream == "-":
        return info
    parts = upstream.split(":")
    if len(parts) >= 1:
        info["upstream_addr"] = parts[0]
    if len(parts) >= 2:
        try:
            info["upstream_port"] = int(parts[1])
        except ValueError:
            info["upstream_port"] = parts[1]
    if " " in upstream:
        segs = upstream.split()
        if len(segs) >= 2:
            dur = segs[-1].rstrip("ms")
            try:
                info["upstream_response_time"] = float(dur)
            except ValueError:
                pass
    return info


def parse_nginx_access_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        data = _is_nginx_json(raw)
        if data is None:
            m = NGINX_COMBINED_RE.match(raw)
            if not m:
                return {"event_type": "nginx_access", "severity": "info", "message": raw}
            data = m.groupdict()
    else:
        return {"event_type": "nginx_access", "severity": "info", "message": str(raw)}

    remote_addr = data.get("remote_addr", data.get("remote_ip", data.get("source_ip", "")))
    x_forwarded_for = data.get("http_x_forwarded_for", data.get("x_forwarded_for", "")).strip()
    real_ip = data.get("http_real_ip", data.get("real_ip", "")).strip()
    source_ip = real_ip or x_forwarded_for.split(",")[0].strip() or remote_addr

    request = data.get("request", data.get("request_line", ""))
    method = data.get("method", "").upper()
    path = data.get("path", data.get("uri", data.get("request_uri", "")))
    protocol = data.get("protocol", data.get("server_protocol", ""))

    if not method and request:
        _split_request(request, data)
        method = data.get("method", "").upper()
        path = data.get("path", path)
        protocol = data.get("protocol", protocol)

    raw_status = data.get("status", data.get("status_code", 0))
    raw_bytes = data.get("body_bytes", data.get("body_bytes_sent", data.get("bytes_sent", 0)))
    referer = data.get("http_referer", data.get("referer", ""))
    user_agent = data.get("http_user_agent", data.get("user_agent", data.get("agent", "")))
    user = data.get("remote_user", data.get("user", ""))
    ts_str = data.get("time_local", data.get("time", data.get("timestamp", data.get("@timestamp", ""))))

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
    severity = _classify_nginx_severity(status_code, attack_type, method)
    event_type = EVENT_TYPES.get(method, "http_request")

    if status_code in ALERT_STATUSES:
        event_type = f"{event_type}_error"

    request_time = data.get("request_time", data.get("request_time_ms", 0))
    if isinstance(request_time, str):
        try:
            request_time = float(request_time)
        except ValueError:
            request_time = 0

    upstream = data.get("upstream_addr", data.get("upstream", ""))
    upstream_info = _parse_upstream(upstream)

    connection = data.get("connection", data.get("connection_serial", ""))
    connection_requests = data.get("connection_requests", "")

    ssl_cipher = data.get("ssl_cipher", data.get("ssl_protocol", ""))
    server_name = data.get("server_name", data.get("host", data.get("http_host", "")))

    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "original_ip": remote_addr,
        "x_forwarded_for": x_forwarded_for,
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
        "server_name": server_name,
        "message": f"{method} {path} -> {status_code} from {source_ip}",
        "metadata": {
            "request_time_sec": request_time,
            "upstream_addr": upstream_info.get("upstream_addr", ""),
            "upstream_port": upstream_info.get("upstream_port", ""),
            "upstream_response_time_ms": upstream_info.get("upstream_response_time", 0),
            "connection": connection,
            "connection_requests": connection_requests,
            "ssl_cipher": ssl_cipher,
            "gzip_ratio": data.get("gzip_ratio", ""),
            "ident": data.get("ident", ""),
            "request_length": data.get("request_length", 0),
            "bytes_sent": data.get("bytes_sent", body_bytes),
        },
    }


PARSER_REGISTRY_KEY = "nginx_access"
