"""
CyberNova — Response Action Transformer
Converts internal ResponseAction ORM model → frontend-compatible dict.

Frontend expects:
    id, action_type, target, status, initiated_by, timestamp, result
"""
from __future__ import annotations

from typing import Any, Dict, List


def transform_action(action: Any, initiated_by: str = "system") -> Dict[str, Any]:
    """Transform a single ResponseAction DB model to frontend shape."""
    created_at = getattr(action, "created_at", None)

    # Extract target from parameters dict
    params = getattr(action, "parameters", {}) or {}
    target = params.get("target", "") or params.get("ip", "") or params.get("hostname", "")
    if not target:
        target = getattr(action, "device_id", None) or getattr(action, "alert_id", "") or "N/A"

    # Build result string from the result JSON or error_message
    result_data = getattr(action, "result", None)
    error_msg = getattr(action, "error_message", None)
    if result_data and isinstance(result_data, dict):
        result_str = result_data.get("details", "") or result_data.get("status", "")
    elif error_msg:
        result_str = error_msg
    elif getattr(action, "status", "") == "completed":
        result_str = f"{getattr(action, 'action_type', 'action')} completed successfully"
    else:
        result_str = None

    return {
        "id": getattr(action, "id", ""),
        "action_type": getattr(action, "action_type", "unknown"),
        "target": target,
        "status": _map_action_status(getattr(action, "status", "pending")),
        "initiated_by": initiated_by,
        "timestamp": created_at.isoformat() if created_at else "",
        "result": result_str,
    }


def transform_actions(
    actions: List[Any],
    initiated_by: str = "system",
) -> List[Dict[str, Any]]:
    """Transform a list of ResponseAction models to frontend shape."""
    return [transform_action(a, initiated_by) for a in actions]


def _map_action_status(status: str) -> str:
    """Map backend action statuses to frontend-expected statuses."""
    mapping = {
        "pending": "pending",
        "completed": "completed",
        "failed": "failed",
    }
    return mapping.get(status, "executing")
