"""
CyberNova — Incident Transformer
Converts internal Incident ORM model → frontend-compatible dict.

Frontend expects:
    incident_id, title, severity, status, created_at, updated_at,
    related_alerts, affected_systems, attack_chain, timeline,
    assigned_to, description
"""
from __future__ import annotations

from typing import Any, Dict, List

from cybernova.schemas.transformers.severity import map_severity


def transform_incident(incident: Any, related_alerts: List[str] = None) -> Dict[str, Any]:
    """Transform a single Incident DB model to frontend shape.

    Maps:
        id              → incident_id
        risk_score      → severity (via map_severity)
        escalation_level → used to enrich status
        assigned_to     → assigned_to (user ID or fallback)
    """
    severity_str = getattr(incident, "severity", None)
    if not severity_str or severity_str not in ("low", "medium", "high", "critical"):
        severity_str = map_severity(getattr(incident, "risk_score", 0) or 0)

    created_at = getattr(incident, "created_at", None)
    updated_at = getattr(incident, "updated_at", None)

    return {
        "incident_id": getattr(incident, "id", ""),
        "title": getattr(incident, "title", "Untitled Incident") or "Untitled Incident",
        "severity": severity_str,
        "status": _map_incident_status(getattr(incident, "status", "new")),
        "created_at": created_at.isoformat() if created_at else "",
        "updated_at": updated_at.isoformat() if updated_at else "",
        "related_alerts": related_alerts or [],
        "affected_systems": _build_affected_systems(incident),
        "attack_chain": _build_attack_chain(incident),
        "timeline": _build_timeline(incident),
        "assigned_to": getattr(incident, "assigned_to", None) or "unassigned",
        "description": getattr(incident, "description", None) or "No description provided.",
    }


def transform_incidents(
    incidents: List[Any],
    alerts_by_incident: Dict[str, List[str]] = None,
) -> List[Dict[str, Any]]:
    """Transform a list of Incident models to frontend shape."""
    alerts_map = alerts_by_incident or {}
    return [
        transform_incident(inc, alerts_map.get(inc.id, []))
        for inc in incidents
    ]


def _map_incident_status(status: str) -> str:
    """Map backend incident statuses to frontend-expected statuses."""
    mapping = {
        "new": "open",
        "in_progress": "investigating",
        "escalated": "investigating",
        "resolved": "resolved",
        "closed": "resolved",
    }
    return mapping.get(status, "open")


def _build_affected_systems(incident: Any) -> List[str]:
    """Build list of affected systems from incident data."""
    # The incident model does not have a direct 'affected_systems' column.
    # We derive from description or return a placeholder from device_id context.
    description = getattr(incident, "description", "") or ""
    # Simple heuristic: extract hostnames that look like system identifiers
    systems = []
    for word in description.split():
        # Match patterns like SRV-xxx, WKS-xxx, FW-xxx
        if any(word.upper().startswith(prefix) for prefix in ("SRV-", "WKS-", "FW-", "DC-", "DB-")):
            systems.append(word.strip(".,;:!"))
    return systems if systems else ["Unknown"]


def _build_attack_chain(incident: Any) -> List[Dict[str, Any]]:
    """Build MITRE ATT&CK chain from incident metadata.

    The Incident model doesn't store attack_chain natively.
    We construct a basic chain from the title/description keywords.
    """
    title = (getattr(incident, "title", "") or "").lower()
    status = getattr(incident, "status", "new")

    chain = []
    phase_map = [
        ("reconnaissance", "T1595 — Active Scanning"),
        ("initial access", "T1190 — Exploit Public App"),
        ("execution", "T1059 — Command Line Interface"),
        ("persistence", "T1547 — Boot/Logon Autostart"),
        ("lateral movement", "T1021 — Remote Services"),
        ("exfiltration", "T1048 — Exfiltration Over Alt Protocol"),
    ]

    # If we can detect phases from title, add them
    for phase_keyword, technique in phase_map:
        if phase_keyword in title:
            chain.append({
                "phase": phase_keyword.title(),
                "technique": technique,
                "status": "completed" if status in ("resolved", "closed") else "in_progress",
                "timestamp": (getattr(incident, "created_at", None) or "").isoformat()
                    if hasattr(getattr(incident, "created_at", None), "isoformat") else "",
            })

    # Always provide at least one entry
    if not chain:
        chain.append({
            "phase": "Detection",
            "technique": "CyberNova Rule Engine",
            "status": "completed",
            "timestamp": (getattr(incident, "created_at", None) or "").isoformat()
                if hasattr(getattr(incident, "created_at", None), "isoformat") else "",
        })

    return chain


def _build_timeline(incident: Any) -> List[Dict[str, Any]]:
    """Build a basic timeline for the incident."""
    created_at = getattr(incident, "created_at", None)
    updated_at = getattr(incident, "updated_at", None)

    timeline = []

    if created_at:
        timeline.append({
            "id": "t1",
            "timestamp": created_at.isoformat(),
            "type": "detection",
            "title": "Incident Created",
            "description": getattr(incident, "title", "Incident detected by correlation engine"),
            "severity": getattr(incident, "severity", "medium"),
        })

    if updated_at and updated_at != created_at:
        timeline.append({
            "id": "t2",
            "timestamp": updated_at.isoformat(),
            "type": "action",
            "title": "Incident Updated",
            "description": f"Status changed to {getattr(incident, 'status', 'unknown')}",
            "severity": "low",
        })

    resolved_at = getattr(incident, "resolved_at", None)
    if resolved_at:
        timeline.append({
            "id": "t3",
            "timestamp": resolved_at.isoformat(),
            "type": "response",
            "title": "Incident Resolved",
            "description": "Incident marked as resolved",
            "severity": "low",
        })

    return timeline
