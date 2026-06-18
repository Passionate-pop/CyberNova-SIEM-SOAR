from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.ueba.models import BehavioralBaseline


def extract_login_features(login_events: List[Dict[str, Any]]) -> Dict[str, float]:
    failed = sum(1 for e in login_events if e.get("status") == "failed")
    success = sum(1 for e in login_events if e.get("status") == "success")
    unique_ips = set(e.get("source_ip", "") for e in login_events if e.get("source_ip"))
    unique_hours = set(e.get("hour", -1) for e in login_events)
    outside_hours = sum(1 for e in login_events if e.get("hour", -1) not in range(7, 19))

    return {
        "login_attempts": float(len(login_events)),
        "failed_logins": float(failed),
        "successful_logins": float(success),
        "failure_rate": float(failed) / max(len(login_events), 1),
        "unique_source_ips": float(len(unique_ips)),
        "unique_login_hours": float(len(unique_hours)),
        "outside_business_hours": float(outside_hours),
    }


def extract_network_features(network_events: List[Dict[str, Any]]) -> Dict[str, float]:
    unique_dest_ips = set(e.get("dest_ip", "") for e in network_events if e.get("dest_ip"))
    unique_ports = set(e.get("dest_port", 0) for e in network_events)
    high_risk_ports = sum(1 for e in network_events if e.get("dest_port", 0) in {22, 3389, 445, 135, 1433, 3306, 27017, 6379})
    external = sum(1 for e in network_events if not _is_private_ip(e.get("dest_ip", "")))

    return {
        "network_connections": float(len(network_events)),
        "unique_dest_ips": float(len(unique_dest_ips)),
        "unique_ports": float(len(unique_ports)),
        "high_risk_port_hits": float(high_risk_ports),
        "external_connections": float(external),
        "external_ratio": float(external) / max(len(network_events), 1),
    }


def extract_resource_features(resource_events: List[Dict[str, Any]]) -> Dict[str, float]:
    unique_resources = set(e.get("resource", "") for e in resource_events if e.get("resource"))
    sensitive_access = sum(1 for e in resource_events if e.get("sensitive", False))
    denied = sum(1 for e in resource_events if e.get("status") == "denied")

    return {
        "resource_accesses": float(len(resource_events)),
        "unique_resources": float(len(unique_resources)),
        "sensitive_resource_access": float(sensitive_access),
        "denied_access": float(denied),
        "denied_rate": float(denied) / max(len(resource_events), 1),
    }


def extract_authentication_features(auth_events: List[Dict[str, Any]]) -> Dict[str, float]:
    mfa_failures = sum(1 for e in auth_events if e.get("mfa_status") == "failed")
    token_refreshes = sum(1 for e in auth_events if e.get("event_type") == "token_refresh")
    privileged_usage = sum(1 for e in auth_events if e.get("privileged", False))

    return {
        "auth_attempts": float(len(auth_events)),
        "mfa_failures": float(mfa_failures),
        "token_refreshes": float(token_refreshes),
        "privileged_usage": float(privileged_usage),
    }


def update_baseline(baseline: Optional[BehavioralBaseline], value: float) -> BehavioralBaseline:
    if baseline is None or baseline.sample_count == 0:
        return BehavioralBaseline(
            mean=value, min_val=value, max_val=value,
            sample_count=1, last_updated=datetime.now(timezone.utc).isoformat(),
        )

    n = baseline.sample_count
    new_mean = (baseline.mean * n + value) / (n + 1)
    if n > 0 and baseline.std > 0:
        new_std = math.sqrt(
            (n * (baseline.std ** 2) + (value - baseline.mean) * (value - new_mean)) / (n + 1)
        )
    else:
        new_std = abs(value - baseline.mean) / 2

    return BehavioralBaseline(
        mean=new_mean,
        std=new_std,
        min_val=min(baseline.min_val, value),
        max_val=max(baseline.max_val, value),
        sample_count=n + 1,
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


def compute_anomaly_score(value: float, baseline: BehavioralBaseline) -> Dict[str, Any]:
    if baseline.sample_count < 5 or baseline.std == 0:
        return {"z_score": 0.0, "is_anomaly": False, "severity": "low"}

    z_score = abs(value - baseline.mean) / baseline.std if baseline.std > 0 else 0

    if z_score >= 4:
        severity = "critical"
        is_anomaly = True
    elif z_score >= 3:
        severity = "high"
        is_anomaly = True
    elif z_score >= 2:
        severity = "medium"
        is_anomaly = True
    else:
        severity = "low"
        is_anomaly = False

    return {"z_score": round(z_score, 2), "is_anomaly": is_anomaly, "severity": severity}


def _is_private_ip(ip: str) -> bool:
    if not ip or ip == "127.0.0.1" or ip == "::1":
        return True
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return True
        return (parts[0] == 10 or
                parts[0] == 172 and 16 <= parts[1] <= 31 or
                parts[0] == 192 and parts[1] == 168 or
                parts[0] == 169 and parts[1] == 254)
    except (ValueError, IndexError):
        return True
