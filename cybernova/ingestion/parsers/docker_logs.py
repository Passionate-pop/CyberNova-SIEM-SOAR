"""
CyberNova — Docker Container Log Parser
Parses Docker JSON log driver output (json-file/Journald).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.docker_logs")

STREAM_SEVERITY = {
    "stdout": "info",
    "stderr": "warning",
}

ERROR_PATTERNS = re.compile(
    r"(error|exception|traceback|failed|failure|crash|panic|fatal|"
    r"segfault|oom.kill|out.of.memory|killed|timeout|refused|"
    r"cannot.connect|connection.reset|permission.denied|"
    r"unhealthy|health.check.failed|exit.code)",
    re.IGNORECASE,
)

WARN_PATTERNS = re.compile(
    r"(warn|deprecated|unable|cannot|unreachable|retry|"
    r"rate.limit|throttl|backoff|timeout|slow)",
    re.IGNORECASE,
)

COMMON_LOG_FORMATS = re.compile(
    r"^(?P<container>[a-zA-Z0-9_.-]+)\s*\|\s*(?P<rest>.*)",
)

CONTAINERD_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\s(stdout|stderr)\s",
    re.IGNORECASE,
)


def _parse_docker_json_line(line: str) -> Dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if "log" not in obj and "message" not in obj:
        return None
    return obj


def _detect_stream(stream: str) -> str:
    return stream.strip().lower() if stream else ""


def _extract_container_info(raw: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    m = COMMON_LOG_FORMATS.match(raw)
    if m:
        info["container"] = m.group("container")
        info["rest"] = m.group("rest")
    return info


def parse_docker_logs(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        m = CONTAINERD_PREFIX.match(raw)
        if m:
            return _parse_containerd_line(raw)
        parsed = _parse_docker_json_line(raw)
        if parsed:
            data = parsed
        else:
            return {
                "event_type": "docker_log",
                "severity": "info",
                "message": raw,
                "timestamp": "",
            }
    else:
        return {"event_type": "docker_log", "severity": "info", "message": str(raw)}

    log_msg = data.get("log", data.get("message", data.get("Message", "")))
    if isinstance(log_msg, str):
        log_msg = log_msg.rstrip("\n\r")
    elif isinstance(log_msg, list):
        log_msg = " ".join(str(m) for m in log_msg)
    else:
        log_msg = str(log_msg) if log_msg else ""

    stream = _detect_stream(data.get("stream", data.get("Stream", data.get("source", data.get("Source", "")))))
    if not stream:
        if isinstance(data.get("stdout"), str):
            stream = "stdout"
            log_msg = data["stdout"]
        elif isinstance(data.get("stderr"), str):
            stream = "stderr"
            log_msg = data["stderr"]

    timestamp = data.get("time", data.get("Time", data.get("timestamp", data.get("Timestamp", data.get("@timestamp", "")))))
    if isinstance(timestamp, (int, float)):
        from datetime import datetime, timezone
        timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
    elif timestamp:
        timestamp = str(timestamp).replace("T", "T").replace("Z", "+00:00") if "T" in str(timestamp) else str(timestamp)

    severity = STREAM_SEVERITY.get(stream, "info")

    if stream == "stderr":
        severity = "warning"
        if ERROR_PATTERNS.search(log_msg):
            severity = "high"
    elif ERROR_PATTERNS.search(log_msg):
        severity = "medium"
        for pattern in ("oom", "segfault", "panic", "fatal", "crash"):
            if pattern in log_msg.lower():
                severity = "high"
                break
    elif WARN_PATTERNS.search(log_msg):
        severity = "warning"

    container_id = data.get("container_id", data.get("ContainerID", data.get("containerId", data.get("id", ""))))
    container_name = data.get("container_name", data.get("ContainerName", data.get("containerName", data.get("name", ""))))
    container_image = data.get("image", data.get("Image", data.get("container_image", "")))
    compose_service = data.get("compose_service", data.get("service", data.get("ComposeService", "")))
    container_host = data.get("host", data.get("Host", data.get("hostname", data.get("Hostname", ""))))

    result = {
        "event_type": "docker_log",
        "severity": severity,
        "source_ip": container_host if container_host else "",
        "timestamp": timestamp if timestamp else "",
        "message": log_msg,
        "metadata": {
            "stream": stream,
            "container_id": container_id,
            "container_name": container_name,
            "container_image": container_image,
            "compose_service": compose_service,
            "container_host": container_host,
        },
    }

    result["metadata"] = {k: v for k, v in result["metadata"].items() if v}

    if tail := data.get("tail", data.get("Tail", "")):
        result["metadata"]["tail"] = tail
    if attrs := data.get("attrs", data.get("Attrs", {})):
        result["metadata"]["attrs"] = attrs

    return result


def _parse_containerd_line(raw: str) -> Dict[str, Any]:
    ts_end = raw.find(" ")
    if ts_end == -1:
        return {"event_type": "docker_log", "severity": "info", "message": raw}
    timestamp = raw[:ts_end]
    rest = raw[ts_end + 1:].strip()

    stream_match = re.match(r"^(stdout|stderr)\s+(.*)", rest, re.IGNORECASE)
    if stream_match:
        stream = stream_match.group(1).lower()
        log_msg = stream_match.group(2)
    else:
        stream = ""
        log_msg = rest

    severity = STREAM_SEVERITY.get(stream, "info")
    if stream == "stderr" and ERROR_PATTERNS.search(log_msg):
        severity = "high"
    elif ERROR_PATTERNS.search(log_msg):
        severity = "medium"

    return {
        "event_type": "docker_log",
        "severity": severity,
        "source_ip": "",
        "timestamp": timestamp.replace("T", "T").replace("Z", "+00:00") if "T" in timestamp else timestamp,
        "message": log_msg,
        "metadata": {"stream": stream, "log_source": "containerd"},
    }


PARSER_REGISTRY_KEY = "docker_logs"
