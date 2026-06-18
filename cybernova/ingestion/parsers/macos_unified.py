"""
CyberNova — macOS Unified Log Parser
Parses JSON output from `log show --style json`.
Maps process, subsystem, category, message type.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.macos_unified")

APPLE_EVENT_TYPES = {
    "logEvent": "macos_unified_log",
    "activityEvent": "macos_unified_activity",
    "signpostEvent": "macos_unified_signpost",
    "signpostIntervalEvent": "macos_unified_signpost_interval",
    "stateEvent": "macos_unified_state",
    "lossEvent": "macos_unified_loss",
    "timesyncEvent": "macos_unified_timesync",
    "traceEvent": "macos_unified_trace",
}

MESSAGE_TYPE_SEVERITY = {
    "Fault": "critical",
    "Error": "high",
    "Critical": "critical",
    "Alert": "critical",
    "Emergency": "critical",
    "Notice": "medium",
    "Warning": "medium",
    "Default": "info",
    "Debug": "low",
    "Info": "info",
    "Activity": "info",
    "Signpost": "info",
    "Trace": "debug",
    "Loss": "medium",
    "Timesync": "info",
}

SENSITIVE_SUBSYSTEMS = {
    "com.apple.security", "com.apple.sandbox", "com.apple.loginwindow",
    "com.apple.opendirectoryd", "com.apple.audit", "com.apple.SecurityServer",
    "com.apple.authd", "com.apple.arc", "com.apple.biometrickit",
    "com.apple.crypto", "com.apple.keychain",
    "com.apple.AccountPolicy", "com.apple.AccountAuthentication",
}

SENSITIVE_KEYWORDS = re.compile(
    r"(password|ssh_key|private.?key|token|secret|credential|"
    r"sudo|su\b|admin|root|kext|kernel|exploit|cve-|backdoor|"
    r"malware|suspicious|unauthorized|blocked|denied|rejected)",
    re.IGNORECASE,
)

PRIVILEGED_PROCESSES = {
    "sudo", "security", "dscl", "csrutil", "kextutil", "kextload",
    "syspolicyd", "sandboxd", "amfid", "kernelmanagerd",
}

SUBSYSTEM_EVENT_TYPES = {
    "com.apple.security": "macos_security_event",
    "com.apple.sandbox": "macos_sandbox_event",
    "com.apple.loginwindow": "macos_login_event",
    "com.apple.authd": "macos_auth_event",
    "com.apple.opendirectoryd": "macos_directory_event",
    "com.apple.audit": "macos_audit_event",
    "com.apple.kernel": "macos_kernel_event",
    "com.apple.networking": "macos_network_event",
    "com.apple.wifi": "macos_wifi_event",
}

ACTIVITY_EVENT_NAMES = {
    "ActivityCreate": "activity_created",
    "ActivityStart": "activity_started",
    "ActivityStop": "activity_stopped",
}


def _parse_apple_timestamp(ts_str: str) -> str:
    if not ts_str:
        return ""
    try:
        from datetime import datetime
        ts_str = ts_str.replace(" +0000", "+00:00").replace(" ", "T", 1)
        dt = datetime.fromisoformat(ts_str)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass
    try:
        from datetime import datetime, timezone
        secs = float(ts_str)
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return ts_str


def _extract_backtrace_info(backtrace: Any) -> Dict[str, Any]:
    if not backtrace:
        return {}
    if isinstance(backtrace, dict):
        return {
            "backtrace_uuid": backtrace.get("uuid", ""),
            "backtrace_frames": backtrace.get("frames", []),
            "backtrace_module": backtrace.get("moduleName", ""),
        }
    if isinstance(backtrace, str):
        return {"backtrace_raw": backtrace}
    return {}


def _extract_thread_info(thread_data: Any) -> Dict[str, Any]:
    if not thread_data:
        return {}
    if isinstance(thread_data, dict):
        return {
            "thread_id": thread_data.get("threadID", thread_data.get("id", "")),
            "thread_name": thread_data.get("threadName", thread_data.get("name", "")),
        }
    return {}


def parse_macos_unified_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            try:
                raw = json.loads(raw)
            except (ValueError, json.JSONDecodeError) as exc:
                log.debug("macOS Unified JSON decode failed: %s", exc)
                timestamp = ""
                ts_m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", raw)
                if ts_m:
                    timestamp = ts_m.group(1).replace(" ", "T")
                return {
                    "event_type": "macos_unified_log",
                    "severity": "info",
                    "message": raw,
                    "timestamp": timestamp,
                }
        else:
            return {
                "event_type": "macos_unified_log",
                "severity": "info",
                "message": raw,
            }
    if not isinstance(raw, dict):
        return {"event_type": "macos_unified_log", "severity": "info", "message": str(raw)}

    event_type_raw = raw.get("eventType", raw.get("event_type", "logEvent"))
    app_event_type = APPLE_EVENT_TYPES.get(event_type_raw, "macos_unified_log")

    timestamp = raw.get("timestamp", raw.get("time", raw.get("date", "")))
    if isinstance(timestamp, (int, float)):
        from datetime import datetime, timezone
        timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
    elif timestamp:
        timestamp = _parse_apple_timestamp(str(timestamp))
    else:
        timestamp = ""

    format_str = raw.get("formatString", raw.get("message", raw.get("eventMessage", "")))
    if isinstance(format_str, list):
        format_str = " ".join(str(m) for m in format_str)

    subsystem = raw.get("subsystem", raw.get("Subsystem", raw.get("subSystem", "")))
    category = raw.get("category", raw.get("Category", ""))
    message_type = raw.get("messageType", raw.get("message_type", raw.get("MessageType", "Default")))
    process_name = raw.get("process", raw.get("Process", raw.get("processName", raw.get("sender", ""))))
    process_id = raw.get("processID", raw.get("pid", raw.get("process_id", raw.get("PID", 0))))
    thread_id = raw.get("threadID", raw.get("thread_id", raw.get("thread", 0)))
    library = raw.get("library", raw.get("Library", raw.get("senderImagePath", "")))
    sender = raw.get("senderImagePath", raw.get("sender", raw.get("Sender", "")))
    activity_id = raw.get("activityIdentifier", raw.get("activity_id", ""))
    parent_activity_id = raw.get("parentActivityIdentifier", raw.get("parent_activity_id", ""))
    trace_id = raw.get("traceID", raw.get("trace_id", ""))
    event_message = raw.get("eventMessage", raw.get("event_message", ""))

    backtrace = raw.get("backtrace", raw.get("Backtrace", raw.get("stackTrace", None)))
    thread_info_raw = raw.get("thread", raw.get("Thread", None))

    severity = MESSAGE_TYPE_SEVERITY.get(message_type, "info")

    if message_type in ("Fault", "Critical", "Alert", "Emergency"):
        severity = "critical"
    elif message_type == "Error":
        severity = "high"

    if subsystem in SENSITIVE_SUBSYSTEMS:
        if severity in ("info", "low"):
            severity = "medium"

    if SENSITIVE_KEYWORDS.search(str(format_str) + " " + str(event_message)):
        if severity in ("info", "low"):
            severity = "medium"
        if any(kw in str(format_str).lower() for kw in ("cve-", "exploit", "backdoor", "malware")):
            severity = "high"

    if process_name in PRIVILEGED_PROCESSES:
        severity = "medium"

    if process_id:
        try:
            process_id = int(process_id)
        except (ValueError, TypeError):
            process_id = 0

    subsystem_event_type = SUBSYSTEM_EVENT_TYPES.get(subsystem, "")
    effective_event_type = subsystem_event_type or app_event_type

    activity_type = raw.get("activityType", "")
    activity_name = ACTIVITY_EVENT_NAMES.get(activity_type, activity_type)

    backtrace_info = _extract_backtrace_info(backtrace)
    thread_info = _extract_thread_info(thread_info_raw)

    message_text = event_message or format_str or ""
    if not message_text:
        msg_parts = []
        if activity_name:
            msg_parts.append(f"[{activity_name}]")
        if process_name:
            msg_parts.append(f"{process_name}[{process_id}]")
        if subsystem:
            msg_parts.append(f"{subsystem}({category})")
        if format_str:
            msg_parts.append(str(format_str))
        message_text = " ".join(msg_parts)

    result = {
        "event_type": effective_event_type,
        "severity": severity,
        "source_ip": "",
        "timestamp": timestamp,
        "message": message_text,
        "metadata": {
            "subsystem": subsystem,
            "category": category,
            "message_type": message_type,
            "process_name": process_name,
            "process_id": process_id,
            "thread_id": thread_id,
            "library": library or sender,
            "activity_id": str(activity_id),
            "parent_activity_id": str(parent_activity_id),
            "trace_id": str(trace_id),
            "event_type_raw": event_type_raw,
            "activity_type": activity_type,
            "activity_name": activity_name,
            "activity_id_map": {
                "activity_identifier": str(activity_id),
                "parent_activity_identifier": str(parent_activity_id),
            },
            "format_string": str(format_str) if format_str else "",
            **backtrace_info,
            **thread_info,
        },
    }

    return result


PARSER_REGISTRY_KEY = "macos_unified"
