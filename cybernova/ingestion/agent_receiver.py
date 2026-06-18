from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from cybernova.api.routes.agent_auth import get_current_agent, CurrentAgent

log = logging.getLogger("cybernova.agent_receiver")
router = APIRouter(prefix="/api/v1/agent/receiver", tags=["Agent Receiver"])


# ── Schemas ──


class AgentEvent(BaseModel):
    id: str
    timestamp_ns: int
    event_type: str
    payload: Dict[str, Any]


class EventBatch(BaseModel):
    agent_id: str
    batch_seq: int
    events: List[AgentEvent]


class BatchAck(BaseModel):
    ok: bool
    ingested: int
    errors: int


# ── Event type mappings ──

EVENT_TYPE_MAP = {
    "process:new": "process_create",
    "process:exit": "process_terminate",
    "file:change": "file_change",
    "net:new": "network_connection",
    "net:closed": "network_disconnect",
    "registry:change": "registry_change",
    "heartbeat": "heartbeat",
}

REGISTRY_KEYS = {
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services",
}


def _normalize_event(
    event: AgentEvent,
    agent: CurrentAgent,
) -> Optional[Dict[str, Any]]:
    event_type = EVENT_TYPE_MAP.get(event.event_type, event.event_type)
    ts = datetime.fromtimestamp(event.timestamp_ns / 1_000_000_000, tz=timezone.utc).isoformat()
    payload = event.payload
    severity = "info"
    message = ""
    extra: Dict[str, Any] = {}

    if event.event_type == "process:new":
        message = f"Process started: {payload.get('name', '')} (PID {payload.get('pid', '')})"
        severity = "low"
        extra = {
            "process_pid": payload.get("pid"),
            "process_name": payload.get("name"),
            "process_path": payload.get("exe"),
            "command_line": payload.get("cmdline"),
            "user": payload.get("user"),
            "parent_pid": payload.get("ppid"),
        }

    elif event.event_type == "process:exit":
        message = f"Process exited: PID {payload.get('pid', '')}"
        severity = "low"
        extra = {"process_pid": payload.get("pid")}

    elif event.event_type == "file:change":
        action = payload.get("kind", "modified")
        message = f"File {action}: {payload.get('path', '')}"
        severity = "medium"
        extra = {
            "file_path": payload.get("path"),
            "file_action": action,
            "file_size": payload.get("file_size"),
            "is_directory": payload.get("is_dir"),
        }

    elif event.event_type == "net:new":
        message = f"New connection: {payload.get('local_addr', '')} -> {payload.get('remote_addr', '')}"
        severity = "medium"
        extra = {
            "source_ip": _extract_ip(payload.get("local_addr", "")),
            "dest_ip": _extract_ip(payload.get("remote_addr", "")),
            "protocol": "tcp",
            "connection_state": payload.get("state"),
        }

    elif event.event_type == "net:closed":
        message = f"Connection closed: {payload.get('local_addr', '')}"
        severity = "low"
        extra = {
            "source_ip": _extract_ip(payload.get("local_addr", "")),
            "dest_ip": _extract_ip(payload.get("remote_addr", "")),
        }

    elif event.event_type == "registry:change":
        key = payload.get("registry_key", "")
        message = f"Registry modified: {key}"
        severity = "high" if _is_sensitive_registry_key(key) else "medium"
        extra = {
            "registry_key": key,
            "registry_value": payload.get("registry_value"),
        }

    else:
        message = payload.get("message", f"Event: {event.event_type}")
        extra = payload

    return {
        "source": "agent",
        "hostname": agent.hostname,
        "log_type": event_type,
        "message": message,
        "timestamp": ts,
        "device_id": agent.device_id,
        "ip_address": agent.ip_address,
        "severity": severity,
        "event_type": event_type,
        "extra_data": extra,
    }


def _extract_ip(addr: str) -> str:
    return addr.split(":")[0] if ":" in addr else addr


def _is_sensitive_registry_key(key: str) -> bool:
    for sk in REGISTRY_KEYS:
        if sk.lower() in key.lower():
            return True
    return False


# ── Routes ──


@router.post("/batch", summary="Ingest batch of EDR telemetry events")
async def ingest_telemetry_batch(
    batch: EventBatch,
    agent: CurrentAgent = Depends(get_current_agent),
):
    if agent.device_id != batch.agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    normalized: List[Dict[str, Any]] = []
    errors = 0

    for event in batch.events:
        try:
            ev = _normalize_event(event, agent)
            if ev:
                normalized.append(ev)
        except Exception as e:
            errors += 1
            log.warning("event normalization failed: event=%s error=%s", event.event_type, e)

    if normalized:
        try:
            from cybernova.pipeline.unified_pipeline import unified_pipeline

            await unified_pipeline.ingest_batch(
                events=normalized,
                tenant_id=agent.tenant_id,
                source="agent",
                source_type="edr_batch",
            )
        except Exception as e:
            log.error("pipeline ingest failed: %s", e)
            raise HTTPException(status_code=502, detail=f"Ingestion pipeline error: {e}")

    log.info(
        "telemetry ingested: agent=%s batch_seq=%d events=%d errors=%d",
        agent.device_id, batch.batch_seq, len(normalized), errors,
    )

    return BatchAck(ok=errors == 0, ingested=len(normalized), errors=errors)
