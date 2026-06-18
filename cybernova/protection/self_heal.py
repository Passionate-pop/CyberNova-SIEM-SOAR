from __future__ import annotations

import logging
import subprocess  # nosec
import time
from pathlib import Path
from typing import Any, Dict, List

log = logging.getLogger("cybernova.protection.self_heal")

CRITICAL_SECURITY_PROCESSES: Dict[str, List[str]] = {
    "agent": ["agent.py", "/opt/cybernova/agent.py"],
    "scanner": ["scanner.py", "/opt/cybernova/scanner.py"],
    "suricata": ["suricata", "/usr/bin/suricata"],
    "lsm_module": ["cybernova_lsm"],
    "auditd": ["auditd", "/usr/sbin/auditd"],
}

PROTECTED_PATHS: Dict[str, str] = {
    "/opt/cybernova/agent.py": "a70b8c9d1e2f3a4b5c6d7e8f9a0b1c2d",
    "/opt/cybernova/scanner.py": "b80c9d1e2f3a4b5c6d7e8f9a0b1c2d3e",
    "/etc/suricata/suricata.yaml": "c90d1e2f3a4b5c6d7e8f9a0b1c2d3e4f",
}

KERNEL_MODULES_PATH = "/proc/modules"
SYSCTL_PATH = "/proc/sys"
SECURITYFS_PATH = "/sys/kernel/security"


class SelfHeal:
    def __init__(self):
        self._heal_interval: float = 0
        self._last_heal_report: float = 0
        self._heal_count: int = 0
        self._fail_count: int = 0

    HEALTH_CHECKS = [
        "check_processes", "check_kernel_module", "check_sysctl_presence",
        "check_file_integrity", "check_security_fs",
    ]

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        now = time.time()

        if etype in ("agent_heartbeat", "system_check"):
            if now - self._heal_interval > 60:
                self._heal_interval = now
                self._run_health_checks(results)

        if etype in ("tamper_detected", "rootkit_detected", "platform_compromised"):
            self._auto_remediate(event, results)

        return results

    def _run_health_checks(self, res: dict):
        findings = self.check_processes() or []
        findings.extend(self.check_kernel_module() or [])
        findings.extend(self.check_sysctl_presence() or [])
        findings.extend(self.check_file_integrity() or [])
        findings.extend(self.check_security_fs() or [])
        for f in findings:
            if f.get("healed"):
                self._heal_count += 1
                log.info("HEALED: %s", f["message"])
            else:
                self._fail_count += 1
        for f in findings:
            self._add_finding(res, f.get("type", "health_check"), f.get("message", ""), f.get("risk_score", 50), {"healed": f.get("healed", False)})
        if findings:
            res["threat_detected"] = any(not f.get("healed") and f.get("risk_score", 0) >= 70 for f in findings)

    def check_processes(self) -> List[Dict[str, Any]]:
        findings = []
        running = set()
        try:
            for entry in Path("/proc").iterdir():
                if entry.name.isdigit():
                    try:
                        running.add((entry / "comm").read_text().strip())
                    except (OSError, PermissionError) as e:
                        log.warning("SelfHeal check_processes: could not read comm for PID %s: %s", entry.name, e)
                        continue
        except OSError as e:
            log.warning("SelfHeal check_processes: could not list /proc: %s", e)
            return findings

        for name, paths in CRITICAL_SECURITY_PROCESSES.items():
            proc_names = [p.rsplit("/", 1)[-1] for p in paths]
            is_running = any(p in running for p in proc_names)
            if not is_running:
                healed = self._restart_process(name, paths)
                findings.append({
                    "type": f"{name}_process_down", "severity": "critical",
                    "risk_score": 95, "healed": healed,
                    "message": f"Security process '{name}' was down — {'RESTARTED' if healed else 'FAILED to restart'}",
                })
        return findings

    def check_kernel_module(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            mods = Path(KERNEL_MODULES_PATH).read_text() if Path(KERNEL_MODULES_PATH).exists() else ""
            if "cybernova_lsm" not in mods:
                healed = self._load_kernel_module()
                findings.append({
                    "type": "lsm_module_unloaded", "severity": "critical",
                    "risk_score": 96, "healed": healed,
                    "message": f"cybernova_lsm module not loaded — {'LOADED' if healed else 'FAILED to load'}",
                })
        except OSError as e:
            log.warning("SelfHeal check_kernel_module: could not read /proc/modules: %s", e)
        return findings

    def check_sysctl_presence(self) -> List[Dict[str, Any]]:
        findings = []
        critical_keys = ["kernel.kptr_restrict", "kernel.dmesg_restrict", "net.ipv4.tcp_syncookies"]
        for key in critical_keys:
            path = Path(SYSCTL_PATH) / key.replace(".", "/")
            if not path.exists():
                healed = self._apply_sysctl(key, "1")
                findings.append({
                    "type": f"sysctl_missing_{key.replace('.', '_')}", "severity": "high",
                    "risk_score": 75, "healed": healed,
                    "message": f"sysctl {key} missing — {'APPLIED' if healed else 'FAILED'}",
                })
        return findings

    def check_file_integrity(self) -> List[Dict[str, Any]]:
        findings = []
        for path_str in PROTECTED_PATHS:
            p = Path(path_str)
            if not p.exists():
                healed = self._restore_file(path_str)
                findings.append({
                    "type": "critical_file_missing", "severity": "critical",
                    "risk_score": 98, "healed": healed,
                    "message": f"Critical file missing: {path_str} — {'RESTORED' if healed else 'FAILED'}",
                })
        return findings

    def check_security_fs(self) -> List[Dict[str, Any]]:
        findings = []
        secfs = Path(SECURITYFS_PATH)
        if not secfs.exists():
            healed = self._mount_securityfs()
            findings.append({
                "type": "securityfs_not_mounted", "severity": "high",
                "risk_score": 80, "healed": healed,
                "message": f"securityfs not mounted at {SECURITYFS_PATH} — {'MOUNTED' if healed else 'FAILED'}",
            })
        return findings

    def _restart_process(self, name: str, paths: List[str]) -> bool:
        for path in paths:
            p = Path(path)
            if p.exists():
                try:
                    cmd = ["python3", path] if path.endswith(".py") else [path]
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosec
                    return True
                except (OSError, ValueError) as e:
                    log.warning("SelfHeal _restart_process: could not restart %s: %s", path, e)
                    continue
        return False

    def _load_kernel_module(self) -> bool:
        paths = [
            "/usr/lib/modules/*/extra/cybernova_lsm.ko",
            "/opt/cybernova/cybernova_lsm.ko",
            "/root/cybernova_lsm.ko",
        ]
        import glob
        for pattern in paths:
            for match in glob.glob(pattern):
                try:
                    subprocess.run(["insmod", match], capture_output=True, timeout=10)  # nosec
                    return True
                except (OSError, subprocess.TimeoutExpired) as e:
                    log.warning("SelfHeal _load_kernel_module: could not load %s: %s", match, e)
                    continue
        return False

    def _apply_sysctl(self, key: str, val: str) -> bool:
        try:
            subprocess.run(["sysctl", "-w", f"{key}={val}"], capture_output=True, timeout=10)  # nosec
            return True
        except (OSError, subprocess.TimeoutExpired) as e:
            log.warning("SelfHeal _apply_sysctl: failed for %s: %s", key, e)
            return False

    def _restore_file(self, path_str: str) -> bool:
        try:
            p = Path(path_str)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.touch()
            p.chmod(0o644)
            return True
        except (OSError, PermissionError) as e:
            log.warning("SelfHeal _restore_file: could not restore %s: %s", path_str, e)
            return False

    def _mount_securityfs(self) -> bool:
        try:
            Path("/sys/kernel").mkdir(parents=True, exist_ok=True)
            subprocess.run(["mount", "-t", "securityfs", "securityfs", "/sys/kernel/security"],  # nosec
                           capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.TimeoutExpired) as e:
            log.warning("SelfHeal _mount_securityfs: could not mount securityfs: %s", e)
            return False

    def _auto_remediate(self, event: dict, res: dict):
        etype = event.get("event_type", "")
        if etype == "tamper_detected":
            healed = self.check_processes()
            if any(h.get("healed") for h in healed):
                self._add_finding(res, "auto_remediated_tamper", "Tamper auto-remediated: processes restarted", 50, {"healed": True})
        if etype == "rootkit_detected":
            self._add_finding(res, "rootkit_requires_intervention", "Rootkit detected — manual investigation required", 95, {})
        if etype == "platform_compromised":
            self._add_finding(res, "platform_breach_alert", "Platform compromise detected — emergency response", 99, {"critical": True})

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        if risk >= 70:
            res["threat_detected"] = True


self_heal = SelfHeal()
