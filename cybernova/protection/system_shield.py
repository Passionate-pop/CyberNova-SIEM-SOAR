from __future__ import annotations

import logging
import re
import stat as stat_module
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

log = logging.getLogger("cybernova.protection.system_shield")

CRITICAL_SYSCTL_SETTINGS: Dict[str, Tuple[str, str, float]] = {
    "kernel.kptr_restrict": ("2", "kernel pointers hidden", 75),
    "kernel.dmesg_restrict": ("1", "dmesg restricted", 55),
    "kernel.kexec_disabled": ("1", "kexec disabled", 80),
    "kernel.modules_disabled": ("0", "modules enabled (recommend 1 for production)", 78),
    "net.ipv4.ip_forward": ("0", "IP forwarding disabled", 65),
    "net.ipv4.conf.all.rp_filter": ("1", "reverse path filtering", 55),
    "net.ipv4.conf.default.rp_filter": ("1", "default rp_filter", 55),
    "net.ipv4.tcp_syncookies": ("1", "SYN cookies enabled", 55),
    "net.ipv4.conf.all.accept_redirects": ("0", "ICMP redirects rejected", 65),
    "net.ipv4.conf.all.secure_redirects": ("0", "secure redirects disabled", 65),
    "net.ipv4.conf.all.log_martians": ("1", "martian packets logged", 50),
    "net.ipv4.icmp_echo_ignore_broadcasts": ("1", "broadcast pings ignored", 50),
    "net.ipv4.icmp_ignore_bogus_error_responses": ("1", "bogus ICMP ignored", 45),
    "net.ipv4.conf.all.send_redirects": ("0", "send_redirects disabled", 65),
    "net.ipv6.conf.all.accept_redirects": ("0", "IPv6 redirects rejected", 60),
}

EXPECTED_FILE_PERMS: Dict[str, str] = {
    "/etc/passwd": "644", "/etc/shadow": "600",
    "/etc/gshadow": "600", "/etc/group": "644",
    "/etc/sudoers": "440", "/etc/ssh/sshd_config": "600",
    "/root/.ssh": "700", "/boot/grub/grub.cfg": "600",
    "/boot/grub2/grub.cfg": "600",
}

SSH_HARDENING_CHECKS: List[Tuple[str, str, str, float]] = [
    ("PermitRootLogin", "PermitRootLogin (yes|prohibit-password)", "prohibit-password", 85),
    ("PasswordAuthentication", "PasswordAuthentication (yes|no)", "no", 65),
    ("PubkeyAuthentication", "PubkeyAuthentication (yes|no)", "yes", 45),
    ("Protocol", "Protocol [0-9]", "2", 55),
    ("X11Forwarding", "X11Forwarding (yes|no)", "no", 55),
    ("MaxAuthTries", "MaxAuthTries [0-9]+", "3", 65),
    ("ClientAliveInterval", "ClientAliveInterval [0-9]+", "300", 50),
    ("ClientAliveCountMax", "ClientAliveCountMax [0-9]+", "0", 55),
    ("AllowTcpForwarding", "AllowTcpForwarding (yes|no)", "no", 55),
]

DESTRUCTIVE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(dd|mkfs|format|fdisk|parted|mkswap)\s+.*(/dev/|of=)", re.I),
    re.compile(r"rm\s+(-rf|--recursive|/)\s+/", re.I),
    re.compile(r">\s*/dev/(sda|sdb|sdc|nvme|mmc)", re.I),
    re.compile(r"chmod\s+000\s+/", re.I),
    re.compile(r"mv\s+/.*?\s+/dev/null", re.I),
    re.compile(r"shutdown\s+-[rnh]?\s+0", re.I),
    re.compile(r"halt|poweroff|reboot\s+-f", re.I),
    re.compile(r"iptables\s+-[FP]\s+", re.I),
    re.compile(r"ufw\s+disable", re.I),
    re.compile(r"systemctl\s+stop\s+(firewalld|ufw|iptables)", re.I),
    re.compile(r"mount\s+-o\s+remount,ro\s+/", re.I),
    re.compile(r"umount\s+/", re.I),
]

SENSITIVE_SERVICES: List[str] = [
    "telnet", "rsh", "rlogin", "rexec", "ftp",
    "tftp", "snmp", "chargen", "echo", "daytime",
]


class SystemShield:
    def __init__(self):
        self._audit_interval: float = 0
        self._last_perms_check: float = 0
        self._last_ssh_check: float = 0
        self._last_sysctl_check: float = 0
        self._last_services_check: float = 0
        self._destructive_cmds: Dict[str, List[float]] = defaultdict(list)

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze event for system misconfigurations and destructive commands."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        event.get("message", "")

        if etype in ("system_check", "agent_heartbeat", "config_audit_request"):
            self._check_sysctl(results)
            self._check_file_permissions(results)
            self._check_ssh_hardening(results)

        if etype == "new_process":
            cmdline = (extra.get("command_line", extra.get("cmdline", "")) + " " + extra.get("process", "")).lower()
            self._detect_destructive(cmdline, results)

        if etype == "selinux_event":
            self._check_selinux(results)

        self._detect_weak_services(results)
        return results

    def _check_sysctl(self, res: dict):
        now = time.time()
        if now - self._last_sysctl_check < 120:
            return
        self._last_sysctl_check = now
        for key, (expected, desc, risk) in CRITICAL_SYSCTL_SETTINGS.items():
            try:
                proc_key = key.replace(".", "/")
                path = Path(f"/proc/sys/{proc_key}")
                if path.exists():
                    val = path.read_text().strip()
                    if val != expected:
                        self._add_finding(res, f"sysctl_{key.replace('.', '_')}", f"Misconfigured: {key}={val} (expected {expected}) — {desc}", risk, {"key": key, "current": val, "expected": expected})
            except Exception as e:
                log.warning("Sysctl check failed for %s: %s", key, e)

    def _check_file_permissions(self, res: dict):
        now = time.time()
        if now - self._last_perms_check < 300:
            return
        self._last_perms_check = now
        for path_str, expected_perm in EXPECTED_FILE_PERMS.items():
            try:
                p = Path(path_str)
                if p.exists():
                    actual = oct(p.stat().st_mode)[-3:]
                    if actual != expected_perm:
                        self._add_finding(res, f"file_perm_{path_str.replace('/', '_')}", f"Wrong permissions on {path_str}: {actual} (expected {expected_perm})", 80, {"path": path_str, "current": actual, "expected": expected_perm})
            except Exception as e:
                log.warning("File perm check failed for %s: %s", path_str, e)
        try:
            for entry in Path("/etc").iterdir():
                if entry.is_file():
                    mode = entry.stat().st_mode
                    if mode & stat_module.S_IWOTH:
                        self._add_finding(res, "world_writable_file", f"World-writable file: {entry}", 82, {"path": str(entry)})
        except Exception as e:
            log.warning("World-writable check error: %s", e)

    def _check_ssh_hardening(self, res: dict):
        now = time.time()
        if now - self._last_ssh_check < 600:
            return
        self._last_ssh_check = now
        sshd_path = Path("/etc/ssh/sshd_config")
        if not sshd_path.exists():
            return
        try:
            config = sshd_path.read_text()
            for setting_name, pattern, expected_val, risk in SSH_HARDENING_CHECKS:
                m = re.search(pattern, config, re.I)
                actual = m.group(1) if m else "not set"
                is_secure = False
                if expected_val == "prohibit-password":
                    is_secure = actual.lower() in ("prohibit-password", "without-password", "no")
                elif expected_val == "yes":
                    is_secure = actual.lower() == "yes"
                elif expected_val == "no":
                    is_secure = actual.lower() in ("no", "0")
                else:
                    is_secure = actual == expected_val
                if not is_secure:
                    self._add_finding(res, f"ssh_{setting_name}", f"SSH {setting_name}={actual} (expected {expected_val})", risk, {"setting": setting_name, "current": actual, "expected": expected_val})
        except Exception as e:
            log.warning("SSH hardening check error: %s", e)

    def _detect_destructive(self, cmdline: str, res: dict):
        if not cmdline:
            return
        for pat in DESTRUCTIVE_PATTERNS:
            if pat.search(cmdline):
                self._add_finding(res, "destructive_command", f"Destructive command: {cmdline[:120]}", 95, {"pattern": pat.pattern[:50]})
                break

    def _check_selinux(self, res: dict):
        try:
            selinux_path = Path("/sys/fs/selinux/enforce")
            if selinux_path.exists():
                if selinux_path.read_text().strip() != "1":
                    self._add_finding(res, "selinux_disabled", "SELinux not enforcing — MAC protection disabled", 90, {})
        except Exception as e:
            log.warning("SELinux check error: %s", e)
        try:
            apparmor = Path("/sys/module/apparmor/parameters/enabled")
            if apparmor.exists() and apparmor.read_text().strip() != "Y":
                self._add_finding(res, "apparmor_disabled", "AppArmor not enabled", 75, {})
        except Exception as e:
            log.warning("AppArmor check error: %s", e)

    def _detect_weak_services(self, res: dict):
        now = time.time()
        if now - self._last_services_check < 600:
            return
        self._last_services_check = now
        try:
            services_path = Path("/etc/services")
            if services_path.exists():
                text = services_path.read_text().lower()
                for svc in SENSITIVE_SERVICES:
                    if svc in text:
                        self._add_finding(res, f"weak_service_{svc}", f"Weak/insecure service configured: {svc}", 70, {"service": svc})
        except Exception as e:
            log.warning("Weak services check error: %s", e)

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True


system_shield = SystemShield()
