"""
CyberNova — Nginx Error Log Parser
Parses Nginx error log entries into structured events.
Maps error levels to severity and extracts client/server context.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.nginx_error")

NGINX_ERROR_RE = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s*'
    r'\*(?P<conn_id>\d+)?\s*'
    r'(?P<message>.+)',
    re.DOTALL,
)

CLIENT_RE = re.compile(r'client:\s+(\S+)')
SERVER_RE = re.compile(r'server:\s+(\S+)')
REQUEST_RE = re.compile(r'request:\s+"([^"]*)"')
UPSTREAM_RE = re.compile(r'upstream:\s+"([^"]*)"')
HOST_RE = re.compile(r'host:\s+"([^"]*)"')
REFERER_RE = re.compile(r'referer:\s+"([^"]*)"')

LEVEL_MAP = {
    "debug": "debug",
    "info": "info",
    "notice": "low",
    "warn": "medium",
    "error": "high",
    "crit": "critical",
    "alert": "critical",
    "emerg": "critical",
}

ERROR_EVENT_MAP: dict[str, str] = {}

ERROR_CATEGORIES = {
    "connect() failed": "nginx_upstream_connect_failed",
    "connection refused": "nginx_upstream_connection_refused",
    "connection reset": "nginx_upstream_connection_reset",
    " connection timed out": "nginx_upstream_timeout",
    " timed out": "nginx_upstream_timeout",
    "no live upstreams": "nginx_no_live_upstreams",
    "upstream prematurely closed": "nginx_upstream_closed",
    "upstream sent too big header": "nginx_upstream_header_too_big",
    "upstream sent invalid header": "nginx_upstream_invalid_header",
    "upstream sent no valid servers": "nginx_upstream_no_servers",
    "upstream sent no HTTP/1.0": "nginx_upstream_bad_protocol",
    "SSL handshake failed": "nginx_ssl_handshake_failed",
    "SSL certificate error": "nginx_ssl_cert_error",
    "SSL_do_handshake() failed": "nginx_ssl_handshake_failed",
    "peer closed connection in SSL handshake": "nginx_ssl_handshake_closed",
    "peer rejected certificate": "nginx_ssl_cert_rejected",
    "certificate expired": "nginx_ssl_cert_expired",
    "open() \"": "nginx_file_open_failed",
    "mkdir() \"": "nginx_mkdir_failed",
    "rename() \"": "nginx_rename_failed",
    "readv() failed": "nginx_read_failed",
    "writev() failed": "nginx_write_failed",
    "sendfile() failed": "nginx_sendfile_failed",
    "recv() failed": "nginx_recv_failed",
    "send() failed": "nginx_send_failed",
    "shutdown() failed": "nginx_shutdown_failed",
    "accept() failed": "nginx_accept_failed",
    "socket() failed": "nginx_socket_failed",
    "bind() to ": "nginx_bind_failed",
    "listen() to ": "nginx_listen_failed",
    "kevent() failed": "nginx_kevent_failed",
    "epoll() failed": "nginx_epoll_failed",
    "getaddrinfo() failed": "nginx_dns_resolve_failed",
    " name not found": "nginx_dns_not_found",
    "host not found": "nginx_dns_not_found",
    "invalid URL prefix": "nginx_invalid_url",
    "invalid port in upstream": "nginx_invalid_upstream_port",
    "invalid host in upstream": "nginx_invalid_upstream_host",
    "no protocol specified": "nginx_no_protocol",
    "protocol not supported": "nginx_unsupported_protocol",
    "method not allowed": "nginx_method_not_allowed",
    "request entity too large": "nginx_request_entity_too_large",
    "client sent too long URI": "nginx_uri_too_long",
    "client sent too long header line": "nginx_header_too_long",
    "client sent invalid request": "nginx_invalid_request",
    "client sent invalid method": "nginx_invalid_method",
    "client sent invalid header": "nginx_invalid_header",
    "client intended to send too large body": "nginx_body_too_large",
    "client closed connection": "nginx_client_closed",
    "client aborted connection": "nginx_client_aborted",
    "connection was refused": "nginx_connection_refused",
    "connection was reset": "nginx_connection_reset",
    "connection timed out": "nginx_connection_timeout",
    "no buffer space available": "nginx_no_buffer_space",
    "file not found": "nginx_file_not_found",
    "access forbidden by rule": "nginx_access_forbidden",
    "access forbidden": "nginx_access_forbidden",
    "rewrite or internal redirection cycle": "nginx_rewrite_cycle",
    "the rewritten URI has a zero length": "nginx_rewrite_zero_uri",
    "subrequest cycle": "nginx_subrequest_cycle",
    "memory allocation failed": "nginx_oom",
    "malloc() failed": "nginx_oom",
    "alloc() failed": "nginx_oom",
    "failed to initialize": "nginx_init_failed",
    "failed to load": "nginx_load_failed",
    "configuration failed": "nginx_config_failed",
    "invalid value in configuration": "nginx_config_invalid",
    "invalid directive": "nginx_config_invalid_directive",
    "directive is not allowed": "nginx_config_directive_not_allowed",
    "worker process is shutting down": "nginx_worker_shutdown",
    "worker process exited": "nginx_worker_exited",
    "signal process started": "nginx_signal_started",
    "graceful shutdown": "nginx_graceful_shutdown",
    "reopening logs": "nginx_log_reopen",
    "reconfiguring": "nginx_reconfiguring",
    "limiting connections by zone": "nginx_limit_conn",
    "limiting requests by zone": "nginx_limit_req",
    "delaying request": "nginx_delaying_request",
    "no socket": "nginx_no_socket",
    "cannot allocate memory": "nginx_oom",
    "fork() failed": "nginx_fork_failed",
    "pipe() failed": "nginx_pipe_failed",
    "dup() failed": "nginx_dup_failed",
    "fcntl() failed": "nginx_fcntl_failed",
    "setuid() failed": "nginx_setuid_failed",
    "setgid() failed": "nginx_setgid_failed",
    "chdir() failed": "nginx_chdir_failed",
    "unlink() failed": "nginx_unlink_failed",
    "symlink() failed": "nginx_symlink_failed",
}


def _map_error_event(message: str) -> str:
    msg_lower = message.lower()
    for pattern, event_type in ERROR_CATEGORIES.items():
        if pattern in msg_lower:
            return event_type
    return "nginx_error"


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime
        dt = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
        return dt.isoformat()
    except (ValueError, TypeError) as exc:
        log.debug("Failed to parse Nginx error timestamp: %s — %s", ts_str, exc)
        return ts_str


def parse_nginx_error_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        raw = raw.strip()
        m = NGINX_ERROR_RE.match(raw)
        if not m:
            return {"event_type": "nginx_error", "severity": "info", "message": raw}
        data = m.groupdict()
    elif isinstance(raw, dict):
        data = raw
    else:
        return {"event_type": "nginx_error", "severity": "info", "message": str(raw)}

    level = data.get("level", data.get("severity", "error")).lower()
    severity = LEVEL_MAP.get(level, "info")
    ts_str = data.get("timestamp", data.get("time", data.get("@timestamp", "")))
    timestamp = _parse_timestamp(ts_str) if ts_str else ts_str
    message = data.get("message", data.get("msg", "")).strip()
    pid = data.get("pid", data.get("process_id", ""))
    tid = data.get("tid", data.get("thread_id", ""))
    conn_id = data.get("conn_id", data.get("connection_id", ""))

    client = data.get("client", data.get("client_ip", ""))
    server = data.get("server", data.get("server_name", ""))
    request = data.get("request", data.get("request_line", ""))
    upstream = data.get("upstream", data.get("upstream_url", ""))
    host = data.get("host", data.get("http_host", ""))

    if not client:
        cm = CLIENT_RE.search(message)
        if cm:
            client = cm.group(1)
    if not server:
        sm = SERVER_RE.search(message)
        if sm:
            server = sm.group(1)
    if not request:
        rm = REQUEST_RE.search(message)
        if rm:
            request = rm.group(1)
    if not upstream:
        um = UPSTREAM_RE.search(message)
        if um:
            upstream = um.group(1)
    if not host:
        hm = HOST_RE.search(message)
        if hm:
            host = hm.group(1)

    event_type = _map_error_event(message)

    return {
        "event_type": event_type,
        "severity": severity,
        "log_level": level,
        "message": message,
        "source_ip": client,
        "server_name": server,
        "host": host,
        "request": request,
        "upstream": upstream,
        "pid": str(pid),
        "thread_id": str(tid),
        "connection_id": str(conn_id),
        "timestamp": timestamp,
        "metadata": {
            "process_id": pid,
            "thread_id": tid,
            "connection_id": conn_id,
            "upstream": upstream,
            "server": server,
            "host": host,
        },
    }


PARSER_REGISTRY_KEY = "nginx_error"
