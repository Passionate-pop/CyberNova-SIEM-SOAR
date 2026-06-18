from __future__ import annotations

from typing import Any, Dict, List


SYSTEM_FEATURES = [
    "cpu_usage", "memory_usage", "disk_usage", "process_count",
    "thread_count", "network_connections", "listening_ports",
]

PROCESS_FEATURES = [
    "suspicious_process_count", "unknown_process_count",
    "process_spawn_rate", "total_processes",
]

NETWORK_FEATURES = [
    "unique_dest_ips", "unique_dest_ports", "external_connections",
    "dns_queries", "bytes_sent_mb", "bytes_received_mb",
]

FILE_FEATURES = [
    "file_create_rate", "file_modify_rate", "file_delete_rate",
    "ransomware_ext_count", "sensitive_file_access",
]

SECURITY_FEATURES = [
    "failed_logins", "privilege_escalations", "registry_changes",
    "service_installs", "scheduled_task_changes",
]


def extract_system_features(system_info: Dict[str, Any]) -> Dict[str, float]:
    return {
        "cpu_usage": float(system_info.get("cpu_usage", 0)),
        "memory_usage": float(system_info.get("memory_usage", 0)),
        "disk_usage": float(system_info.get("disk_usage", 0)),
        "process_count": float(system_info.get("process_count", 0)),
        "network_connections": float(system_info.get("network_connections", 0)),
    }


def extract_process_features(processes: List[Dict[str, Any]]) -> Dict[str, float]:
    suspicious_keywords = ["powershell", "cmd", "wscript", "cscript", "mshta",
                           "rundll32", "regsvr32", "certutil", "bitsadmin"]
    suspicious_count = sum(
        1 for p in processes
        if any(kw in p.get("name", "").lower() for kw in suspicious_keywords)
    )
    return {
        "suspicious_process_count": float(suspicious_count),
        "total_processes": float(len(processes)),
    }


def extract_network_features(connections: List[Dict[str, Any]]) -> Dict[str, float]:
    unique_ips = set(c.get("remote_ip", "") for c in connections if c.get("remote_ip"))
    return {
        "unique_dest_ips": float(len(unique_ips)),
        "external_connections": float(len(connections)),
    }


def extract_file_features(file_events: List[Dict[str, Any]]) -> Dict[str, float]:
    ransomware_exts = {".crypted", ".locked", ".encrypted", ".enc", ".locky", ".cerber"}
    create_count = sum(1 for e in file_events if e.get("action") == "create")
    modify_count = sum(1 for e in file_events if e.get("action") in ("modify", "write"))
    delete_count = sum(1 for e in file_events if e.get("action") == "delete")
    rw_count = sum(
        1 for e in file_events
        if any(e.get("path", "").lower().endswith(ext) for ext in ransomware_exts)
    )
    return {
        "file_create_rate": float(create_count),
        "file_modify_rate": float(modify_count),
        "file_delete_rate": float(delete_count),
        "ransomware_ext_count": float(rw_count),
    }


def combine_features(
    system: Dict[str, float],
    process: Dict[str, float],
    network: Dict[str, float],
    file_feat: Dict[str, float],
) -> Dict[str, float]:
    combined = {}
    combined.update(system)
    combined.update(process)
    combined.update(network)
    combined.update(file_feat)
    return combined
