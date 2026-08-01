"""
CyberNova — Alert Transformer
Converts internal Alert ORM model → frontend-compatible dict.

Frontend expects:
    alert_id, type, severity, timestamp, status,
    source_ip, destination_ip, description, rule_id, affected_system
    
Also includes investigation details:
    - threat_intel: VirusTotal, AbuseIPDB, OTX verdicts
    - geo: Geographic location of IPs
    - enrichment_sources: List of threat intel sources consulted
    - raw_event: Original event data for deep investigation
    - alert_reason: Why this alert was created
"""
from __future__ import annotations

from typing import Any, Dict, List

from cybernova.schemas.transformers.severity import map_severity


def transform_alert(alert: Any) -> Dict[str, Any]:
    """Transform a single Alert DB model to frontend shape with investigation details.

    Maps:
        id           → alert_id
        rule_name    → type
        risk_score   → severity (via map_severity)
        created_at   → timestamp
        description  → description (with fallback)
        device_id    → affected_system (with fallback)
        
    Adds investigation details:
        - threat_intel: VirusTotal, AbuseIPDB, OTX verdicts
        - geo: Geographic location
        - enrichment_sources: Threat intel sources consulted
        - raw_event: Original event data
        - alert_reason: Why alert was created
    """
    severity_str = getattr(alert, "severity", None)
    if not severity_str or severity_str not in ("low", "medium", "high", "critical"):
        severity_str = map_severity(getattr(alert, "risk_score", 0) or 0)

    created_at = getattr(alert, "created_at", None)
    timestamp = created_at.isoformat() if created_at else ""

    description = getattr(alert, "description", None) or ""
    
    extra_data = getattr(alert, "extra_data", None) or {}
    threat_intel = extra_data.get("threat_intel", {}) if isinstance(extra_data, dict) else {}
    geo = extra_data.get("geo", {}) if isinstance(extra_data, dict) else {}
    enrichment_sources = extra_data.get("enrichment_sources", []) if isinstance(extra_data, dict) else []
    raw_event = extra_data.get("raw_event", {}) if isinstance(extra_data, dict) else {}
    alert_reason = extra_data.get("alert_reason", "") if isinstance(extra_data, dict) else ""

    # Pipeline worker stores source_ip/dest_ip only in extra_data, not as ORM columns
    source_ip = _extract_field(alert, "source_ip", "") or (extra_data.get("source_ip", "") if isinstance(extra_data, dict) else "")
    dest_ip = _extract_field(alert, "dest_ip", "") or (extra_data.get("dest_ip", "") if isinstance(extra_data, dict) else "")

    rule_name = getattr(alert, "rule_name", None) or ""

    result = {
        "alert_id": getattr(alert, "id", ""),
        "type": rule_name if rule_name else "Unknown",
        "severity": severity_str,
        "risk_score": getattr(alert, "risk_score", 0) or 0,
        "timestamp": timestamp,
        "status": _map_alert_status(getattr(alert, "status", "new")),
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "description": description if description else f"Alert triggered by rule: {rule_name or 'unknown'}",
        "rule_id": rule_name if rule_name else "",
        "rule_name": rule_name if rule_name else "",
        "affected_system": getattr(alert, "device_id", None) or "Unknown",
        "investigation": {
            "threat_intel": _build_threat_intel_details(threat_intel),
            "geo_location": _build_geo_details(geo),
            "enrichment_sources": enrichment_sources,
            "raw_event": _sanitize_raw_event(raw_event),
            "alert_reason": alert_reason,
        }
    }
    
    return result


def _build_threat_intel_details(threat_intel: Dict[str, Any]) -> Dict[str, Any]:
    """Build threat intelligence details for frontend."""
    if not threat_intel:
        return {
            "verified": False,
            "verdict": "Unknown",
            "sources": [],
            "virustotal": None,
            "abuseipdb": None,
            "otx": None,
            "risk_level": "unverified"
        }
    
    is_safe = threat_intel.get("is_safe", False)
    is_malicious = threat_intel.get("is_malicious", False)
    sources = threat_intel.get("sources", [])
    
    vt_data = threat_intel.get("virustotal", {})
    abuse_data = threat_intel.get("abuseipdb", {})
    otx_data = threat_intel.get("otx", {})
    
    if is_safe:
        verdict = "Safe"
        risk_level = "low"
        verified = True
    elif is_malicious:
        verdict = "Malicious"
        risk_level = "critical"
        verified = True
    else:
        verdict = "Unverified"
        risk_level = "medium"
        verified = False
    
    return {
        "verified": verified,
        "verdict": verdict,
        "sources": sources,
        "virustotal": {
            "malicious": vt_data.get("malicious", False) if isinstance(vt_data, dict) else False,
            "detections": vt_data.get("detections", 0) if isinstance(vt_data, dict) else 0,
        } if vt_data else None,
        "abuseipdb": {
            "confidence_score": abuse_data.get("abuse_confidence_score", 0),
            "country_code": abuse_data.get("country_code", ""),
            "usage_type": abuse_data.get("usage_type", ""),
        } if abuse_data else None,
        "otx": {
            "pulses": otx_data.get("pulses", 0),
            "is_malicious": otx_data.get("is_malicious", False),
        } if otx_data else None,
        "risk_level": risk_level,
        "risk_modifier": threat_intel.get("risk_modifier", 0),
    }


def _build_geo_details(geo: Dict[str, Any]) -> Dict[str, Any]:
    """Build geographic location details for frontend."""
    if not geo:
        return {
            "source_location": None,
            "dest_location": None,
        }
    
    if isinstance(geo, dict):
        return {
            "source_location": {
                "country": geo.get("country", ""),
                "country_code": geo.get("country_code", ""),
                "city": geo.get("city", ""),
                "region": geo.get("region", ""),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
            } if geo.get("country") else None,
            "dest_location": None,
        }
    return {"source_location": None, "dest_location": None}


def _sanitize_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize raw event data for frontend display."""
    if not raw_event:
        return {}
    
    important_fields = [
        "event_type", "severity", "message", "user", "timestamp",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol",
        "device_id", "hostname", "process_name", "file_path", "hash",
        "parent_process", "command_line", "action", "result",
    ]
    
    sanitized = {}
    for field in important_fields:
        if field in raw_event:
            sanitized[field] = raw_event[field]
    
    return sanitized


def transform_alerts(alerts: List[Any]) -> List[Dict[str, Any]]:
    """Transform a list of Alert models to frontend shape."""
    return [transform_alert(a) for a in alerts]


def _map_alert_status(status: str) -> str:
    """Map backend alert statuses to frontend-expected statuses."""
    mapping = {
        "new": "open",
        "correlated": "investigating",
        "in_progress": "investigating",
        "resolved": "closed",
        "closed": "closed",
    }
    return mapping.get(status, "open")


def _extract_field(obj: Any, field: str, default: str = "") -> str:
    """Safely extract a field from an ORM model, falling back to default."""
    val = getattr(obj, field, None)
    return val if val else default
