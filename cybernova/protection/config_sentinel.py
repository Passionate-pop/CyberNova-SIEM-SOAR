"""
Config Sentinel — CIS benchmark auditing for Linux/Windows servers.
Identifies security misconfigurations that attackers exploit.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger("cybernova.protection.config_sentinel")

HARDENING_CHECKS = []


def _check(name: str, severity: str, risk: float, desc: str, check_fn):
    HARDENING_CHECKS.append((name, severity, risk, desc, check_fn))


def _register_default_checks():
    if HARDENING_CHECKS:
        return

    # ── SSH Hardening ────────────────────────────────────────────────────────

    def _ssh_permit_root():
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            return "PermitRootLogin yes" not in p.read_text() or "PermitRootLogin prohibit-password" in p.read_text()
        return None

    _check("ssh_root_login_disabled", "high", 85.0, "SSH root login should be disabled", _ssh_permit_root)

    def _ssh_password_auth():
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            return "PasswordAuthentication no" in p.read_text()
        return None

    _check("ssh_password_auth_disabled", "medium", 65.0, "SSH password auth should be disabled (use keys)", _ssh_password_auth)

    def _ssh_protocol():
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            return "Protocol 2" in p.read_text()
        return None

    _check("ssh_protocol_2", "medium", 55.0, "SSH protocol should be version 2 only", _ssh_protocol)

    # ── File Permissions ─────────────────────────────────────────────────────

    def _passwd_perms():
        p = Path("/etc/passwd")
        return p.exists() and oct(p.stat().st_mode)[-3:] == "644"

    _check("passwd_permissions", "medium", 60.0, "/etc/passwd should be 644", _passwd_perms)

    def _shadow_perms():
        p = Path("/etc/shadow")
        return p.exists() and oct(p.stat().st_mode)[-3:] == "640" or oct(p.stat().st_mode)[-3:] == "600"

    _check("shadow_permissions", "high", 85.0, "/etc/shadow should be 600 or 640", _shadow_perms)

    def _sudoers_perms():
        p = Path("/etc/sudoers")
        return p.exists() and oct(p.stat().st_mode)[-3:] == "440"

    _check("sudoers_permissions", "critical", 95.0, "/etc/sudoers should be 440", _sudoers_perms)

    def _ssh_dir_perms():
        p = Path("/root/.ssh")
        if p.exists():
            return oct(p.stat().st_mode)[-3:] == "700"
        return None

    _check("ssh_dir_permissions", "high", 80.0, "/root/.ssh should be 700", _ssh_dir_perms)

    # ── File Integrity ───────────────────────────────────────────────────────

    def _no_world_writable_etc():
        for f in Path("/etc").iterdir():
            if f.is_file() and oct(f.stat().st_mode)[-1] in ("2", "3", "6", "7"):
                return False
        return True

    _check("no_world_writable_etc", "high", 82.0, "No world-writable files in /etc", _no_world_writable_etc)

    # ── Network Hardening ────────────────────────────────────────────────────

    def _ip_forward():
        p = Path("/proc/sys/net/ipv4/ip_forward")
        if p.exists():
            return p.read_text().strip() == "0"
        return None

    _check("ip_forwarding_disabled", "medium", 65.0, "IP forwarding should be disabled unless router", _ip_forward)

    def _tcp_syncookies():
        p = Path("/proc/sys/net/ipv4/tcp_syncookies")
        if p.exists():
            return p.read_text().strip() == "1"
        return None

    _check("tcp_syncookies_enabled", "medium", 55.0, "TCP SYN cookies should be enabled", _tcp_syncookies)

    def _rp_filter():
        p = Path("/proc/sys/net/ipv4/conf/all/rp_filter")
        if p.exists():
            return p.read_text().strip() == "1"
        return None

    _check("rp_filter_enabled", "medium", 55.0, "Reverse path filtering should be enabled", _rp_filter)

    # ── Kernel Hardening ─────────────────────────────────────────────────────

    def _kptr_restrict():
        p = Path("/proc/sys/kernel/kptr_restrict")
        if p.exists():
            return p.read_text().strip() == "2"
        return None

    _check("kptr_restrict_enabled", "high", 75.0, "kernel.kptr_restrict should be 2", _kptr_restrict)

    def _dmesg_restrict():
        p = Path("/proc/sys/kernel/dmesg_restrict")
        if p.exists():
            return p.read_text().strip() == "1"
        return None

    _check("dmesg_restrict_enabled", "medium", 55.0, "kernel.dmesg_restrict should be 1", _dmesg_restrict)

    def _kexec_disabled():
        p = Path("/proc/sys/kernel/kexec_disabled")
        if p.exists():
            return p.read_text().strip() == "1"
        return None

    _check("kexec_disabled", "high", 80.0, "kernel.kexec_disabled should be 1", _kexec_disabled)

    def _modules_disabled():
        p = Path("/proc/sys/kernel/modules_disabled")
        if p.exists():
            return p.read_text().strip() == "1"
        return None

    _check("modules_disabled", "high", 78.0, "kernel.modules_disabled should be 1", _modules_disabled)

    # ── Password Policy ──────────────────────────────────────────────────────

    def _pam_passwdqc():
        p = Path("/etc/pam.d/common-password")
        if p.exists():
            return "pam_passwdqc" in p.read_text() or "pam_pwquality" in p.read_text()
        return None

    _check("password_quality_module", "medium", 60.0, "Password quality module should be enabled", _pam_passwdqc)

    def _min_password_len():
        p = Path("/etc/login.defs")
        if p.exists():
            for line in p.read_text().split("\n"):
                if "PASS_MIN_LEN" in line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) >= 12
            return None
        return None

    _check("min_password_length", "medium", 55.0, "Minimum password length should be >= 12", _min_password_len)

    # ── Audit / Logging ──────────────────────────────────────────────────────

    def _auditd_running():
        p = Path("/var/log/audit")
        return p.exists() and any(p.iterdir())

    _check("audit_logging_enabled", "high", 75.0, "Audit logging should be enabled", _auditd_running)


_register_default_checks()


def run_audit() -> Dict[str, Any]:
    findings = []
    passed = 0
    failed = 0
    skipped = 0
    total_risk = 0.0

    for name, severity, risk, description, check_fn in HARDENING_CHECKS:
        try:
            result = check_fn()
            if result is True:
                passed += 1
            elif result is False:
                failed += 1
                total_risk = max(total_risk, risk)
                findings.append({
                    "check": name,
                    "severity": severity,
                    "risk_score": risk,
                    "message": description,
                    "status": "failed",
                })
            else:
                skipped += 1
        except Exception as e:
            log.warning("ConfigSentinel audit: check %s failed: %s", name, e)
            skipped += 1

    return {
        "audit_complete": True,
        "total_checks": len(HARDENING_CHECKS),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "compliance_score": round((passed / max(len(HARDENING_CHECKS) - skipped, 1)) * 100, 1),
        "max_risk_score": round(total_risk, 1),
        "findings": findings,
    }


config_sentinel = run_audit
