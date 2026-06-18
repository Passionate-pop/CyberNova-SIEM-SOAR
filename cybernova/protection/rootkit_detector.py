"""
Rootkit Detector — kernel integrity validation, hidden process detection,
syscall table hook detection, loaded kernel module auditing.
Runs agent-side with results sent as events for pipeline enrichment.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List

log = logging.getLogger("cybernova.protection.rootkit_detector")

SUSPICIOUS_KMOD_KEYWORDS = [
    "hide", "stealth", "rootkit", "hook", "kbeast", "adore",
    "suterusu", "override", "diamorphine", "tunnel", "nethook",
]

KNOWN_GOOD_SYSCALL_HASHES: Dict[str, str] = {}  # Populated per kernel version

CRITICAL_PROCESSES = [
    "init", "systemd", "sshd", "cron", "rsyslogd", "syslogd",
    "auditd", "bash", "sh", "python3", "python",
]

HIDDEN_PROC_INDICATORS = [
    r"/proc/\d+/status",  # Hidden from /proc but fd still open
    r"unlinked\s+from\s+/proc",  # Process unlinked from /proc
]


def detect_hidden_processes() -> List[Dict[str, Any]]:
    findings = []
    try:
        proc = Path("/proc")
        if not proc.exists():
            return findings

        all_pids = set()
        for entry in proc.iterdir():
            if entry.name.isdigit():
                all_pids.add(int(entry.name))

        # Check for processes with fd but no /proc entry (hidden)
        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            pid = int(pid_dir.name)
            try:
                fd_dir = pid_dir / "fd"
                if fd_dir.exists():
                    for fd_entry in fd_dir.iterdir():
                        try:
                            link = os.readlink(str(fd_entry))
                            m = re.search(r"/proc/(\d+)/", link)
                            if m and int(m.group(1)) not in all_pids and int(m.group(1)) != pid:
                                findings.append({
                                    "type": "hidden_process",
                                    "pid": int(m.group(1)),
                                    "detected_via": f"fd_link_in_pid_{pid}",
                                    "severity": "critical",
                                    "risk_score": 98.0,
                                    "message": f"Hidden process detected: PID {m.group(1)} not in /proc",
                                })
                        except (OSError, ValueError):
                            continue
            except PermissionError:
                continue
    except Exception as e:
        log.warning("Hidden process detection error: %s", e)

    return findings


def detect_syscall_hooks() -> List[Dict[str, Any]]:
    findings = []
    try:
        kallsyms = Path("/proc/kallsyms")
        if not kallsyms.exists():
            return findings

        text = kallsyms.read_text()
        syscall_table_entries = []
        for line in text.split("\n"):
            if "sys_call_table" in line or "ia32_sys_call_table" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    syscall_table_entries.append({
                        "address": parts[0],
                        "type": parts[1],
                        "name": parts[2],
                    })

        if syscall_table_entries:
            findings.append({
                "type": "syscall_table_location",
                "severity": "info",
                "risk_score": 0.0,
                "message": f"sys_call_table found in kallsyms ({len(syscall_table_entries)} entries)",
                "entries": syscall_table_entries[:5],
            })

        # Check for hooked syscalls by looking for non-standard addresses
        # Standard syscalls are in .text section; hooked ones point to modules
        for line in text.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 3:
                name = parts[2]
                if name.startswith("sys_") and not name.startswith("sys_call_table"):
                    section = parts[1] if len(parts) > 1 else ""
                    if section not in ("T", "t"):  # Not in .text section
                        findings.append({
                            "type": "syscall_hook_detected",
                            "severity": "critical",
                            "risk_score": 95.0,
                            "message": f"Syscall {name} at non-standard address ({section})",
                            "syscall": name,
                            "section": section,
                        })
    except Exception as e:
        log.warning("Syscall hook detection error: %s", e)

    return findings


def detect_suspicious_kernel_modules() -> List[Dict[str, Any]]:
    findings = []
    try:
        modules_path = Path("/proc/modules")
        if not modules_path.exists():
            return findings

        for line in modules_path.read_text().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 1:
                modname = parts[0].lower()
                for kw in SUSPICIOUS_KMOD_KEYWORDS:
                    if kw in modname:
                        findings.append({
                            "type": "suspicious_kernel_module",
                            "severity": "critical",
                            "risk_score": 94.0,
                            "message": f"Suspicious kernel module loaded: {modname}",
                            "module": modname,
                            "matched_keyword": kw,
                        })
                        break
    except Exception as e:
        log.warning("Kernel module detection error: %s", e)

    return findings


def check_kernel_integrity() -> List[Dict[str, Any]]:
    findings = []

    try:
        kptr_restrict = Path("/proc/sys/kernel/kptr_restrict")
        if kptr_restrict.exists():
            val = kptr_restrict.read_text().strip()
            if val == "0":
                findings.append({
                    "type": "kernel_protection_disabled",
                    "severity": "high",
                    "risk_score": 75.0,
                    "message": "kptr_restrict is 0 — kernel pointers visible to userspace",
                    "recommendation": "Set sysctl kernel.kptr_restrict=2",
                })
    except OSError as e:
        log.warning("RootkitDetector: could not read kptr_restrict: %s", e)

    try:
        dmesg_restrict = Path("/proc/sys/kernel/dmesg_restrict")
        if dmesg_restrict.exists():
            val = dmesg_restrict.read_text().strip()
            if val == "0":
                findings.append({
                    "type": "kernel_protection_disabled",
                    "severity": "medium",
                    "risk_score": 55.0,
                    "message": "dmesg_restrict is 0 — kernel log visible to all users",
                    "recommendation": "Set sysctl kernel.dmesg_restrict=1",
                })
    except OSError as e:
        log.warning("RootkitDetector: could not read dmesg_restrict: %s", e)

    try:
        kexec_disabled = Path("/proc/sys/kernel/kexec_disabled")
        if kexec_disabled.exists():
            val = kexec_disabled.read_text().strip()
            if val == "0":
                findings.append({
                    "type": "kernel_protection_disabled",
                    "severity": "high",
                    "risk_score": 80.0,
                    "message": "kexec is enabled — kernel replacement possible",
                    "recommendation": "Set sysctl kernel.kexec_disabled=1",
                })
    except OSError as e:
        log.warning("RootkitDetector: could not read kexec_disabled: %s", e)

    # Check SELinux / AppArmor status
    try:
        selinux = Path("/sys/fs/selinux/enforce")
        if selinux.exists():
            val = selinux.read_text().strip()
            if val != "1":
                findings.append({
                    "type": "mandatory_access_control_disabled",
                    "severity": "critical",
                    "risk_score": 90.0,
                    "message": "SELinux is not enforcing",
                    "recommendation": "Set SELinux to enforcing mode",
                })
    except OSError as e:
        log.warning("RootkitDetector: could not read SELinux enforce: %s", e)

    try:
        apparmor = Path("/sys/module/apparmor/parameters/enabled")
        if apparmor.exists():
            val = apparmor.read_text().strip()
            if val != "Y":
                findings.append({
                    "type": "mandatory_access_control_disabled",
                    "severity": "high",
                    "risk_score": 75.0,
                    "message": "AppArmor is not enabled",
                    "recommendation": "Enable AppArmor via kernel boot parameters",
                })
    except OSError as e:
        log.warning("RootkitDetector: could not read AppArmor status: %s", e)

    return findings


def run_scan() -> Dict[str, Any]:
    all_findings = []
    all_findings.extend(detect_hidden_processes())
    all_findings.extend(detect_syscall_hooks())
    all_findings.extend(detect_suspicious_kernel_modules())
    all_findings.extend(check_kernel_integrity())

    risk_score = max((f.get("risk_score", 0) for f in all_findings), default=0.0)
    rootkit_detected = any(f.get("type") in ("hidden_process", "syscall_hook_detected", "suspicious_kernel_module")
                           for f in all_findings)

    return {
        "scan_complete": True,
        "rootkit_detected": rootkit_detected,
        "max_risk_score": round(risk_score, 1),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


rootkit_detector = run_scan
