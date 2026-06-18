"""
Tamper Guard — monitors CyberNova agent and driver processes, files, and
registry keys for tampering attempts. Detects when security tools
are being stopped, unloaded, or modified.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("cybernova.protection.tamper_guard")

# Critical CyberNova files to monitor for integrity
CRITICAL_FILES = [
    "/opt/cybernova/agent.py",
    "/opt/cybernova/scanner.py",
    "/usr/lib/cybernova/cybernova_lsm.ko",
    "/etc/suricata/suricata.yaml",
    "/etc/suricata/rules/",
]

# Processes that must never be killed
PROTECTED_PROCESSES = [
    "agent.py", "scanner.py", "cybernova_lsm",
    "suricata", "event_bridge.py",
]

# Security-related syscalls that should never be disabled
PROTECTED_SYSCTLS = {
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.kexec_disabled": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
}

# Windows-specific (checked when os.name == 'nt')
WINDOWS_PROTECTED_PATHS = [
    "C:\\Windows\\System32\\drivers\\cybernova.sys",
]

WINDOWS_PROTECTED_SERVICES = [
    "CybernovaAV", "CybernovaAgent",
]

WINDOWS_PROTECTED_REGISTRY = [
    r"HKLM\SYSTEM\CurrentControlSet\Services\CybernovaAV",
]


def check_process_integrity() -> List[Dict[str, Any]]:
    findings = []
    try:
        proc = Path("/proc")
        if not proc.exists():
            return findings

        running_processes: Set[str] = set()
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
                running_processes.add(comm)
            except (OSError, PermissionError) as e:
                log.warning("TamperGuard process check: could not read comm for PID %s: %s", entry.name, e)
                continue

        for protected in PROTECTED_PROCESSES:
            if protected not in running_processes:
                findings.append({
                    "type": "protected_process_not_running",
                    "severity": "critical",
                    "risk_score": 95.0,
                    "message": f"Protected process '{protected}' is not running",
                    "process": protected,
                    "recommendation": f"Restart {protected} immediately",
                })
    except Exception as e:
        log.warning("Process integrity check error: %s", e)

    return findings


def check_file_integrity(baseline: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    findings = []

    for path in CRITICAL_FILES:
        p = Path(path)
        if not p.exists():
            findings.append({
                "type": "critical_file_missing",
                "severity": "critical",
                "risk_score": 98.0,
                "message": f"Critical CyberNova file missing: {path}",
                "file": path,
            })
            continue

        if p.is_file():
            try:
                current_hash = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                if baseline and path in baseline and baseline[path] != current_hash:
                    findings.append({
                        "type": "critical_file_modified",
                        "severity": "critical",
                        "risk_score": 99.0,
                        "message": f"Critical file hash changed: {path}",
                        "file": path,
                        "previous_hash": baseline[path],
                        "current_hash": current_hash,
                    })
            except Exception as e:
                findings.append({
                    "type": "file_integrity_check_failed",
                    "severity": "high",
                    "risk_score": 70.0,
                    "message": f"Cannot verify integrity of {path}: {e}",
                    "file": path,
                })

    return findings


def check_kernel_module_loaded() -> List[Dict[str, Any]]:
    findings = []
    try:
        modules = Path("/proc/modules")
        if modules.exists():
            text = modules.read_text()
            if "cybernova_lsm" not in text:
                findings.append({
                    "type": "security_module_not_loaded",
                    "severity": "critical",
                    "risk_score": 96.0,
                    "message": "CyberNova LSM kernel module is not loaded",
                    "recommendation": "Run: insmod cybernova_lsm.ko",
                })
    except OSError as e:
        log.warning("TamperGuard kernel module check: could not read /proc/modules: %s", e)
    return findings


def check_sysctl_protections() -> List[Dict[str, Any]]:
    findings = []
    for key, expected in PROTECTED_SYSCTLS.items():
        try:
            proc_key = key.replace(".", "/")
            path = Path(f"/proc/sys/{proc_key}")
            if path.exists():
                val = path.read_text().strip()
                if val != expected:
                    findings.append({
                        "type": "sysctl_tampered",
                        "severity": "high",
                        "risk_score": 85.0,
                        "message": f"Protected sysctl '{key}' changed: {val} (expected {expected})",
                        "key": key,
                        "current": val,
                        "expected": expected,
                    })
        except OSError as e:
            log.warning("TamperGuard sysctl check: could not read %s: %s", path, e)
    return findings


def check_cgroup_memory() -> List[Dict[str, Any]]:
    findings = []
    try:
        path = Path("/proc/self/cgroup")
        if path.exists():
            cgroups = path.read_text()
            if "docker" in cgroups:
                # Running in container — check if memory limits removed
                mem_limit = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
                if mem_limit.exists():
                    val = mem_limit.read_text().strip()
                    if val == "9223372036854771712":
                        pass  # No limit — container could host cryptominer
        # Simulated: just return empty for now
    except OSError as e:
        log.warning("TamperGuard cgroup check: could not read /proc/self/cgroup: %s", e)
    return findings


def run_checks(baseline: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    all_findings = []
    all_findings.extend(check_process_integrity())
    all_findings.extend(check_file_integrity(baseline))
    all_findings.extend(check_kernel_module_loaded())
    all_findings.extend(check_sysctl_protections())

    tamper_detected = any(f.get("severity") in ("critical", "high") for f in all_findings)
    max_risk = max((f.get("risk_score", 0) for f in all_findings), default=0.0)

    return {
        "tamper_detected": tamper_detected,
        "max_risk_score": round(max_risk, 1),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


tamper_guard = run_checks
