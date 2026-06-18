from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

log = logging.getLogger("cybernova.protection.process_shield")

MIMIKATZ_SIGNATURES: List[re.Pattern] = [
    re.compile(r"mimikatz", re.I),
    re.compile(r"sekurlsa", re.I),
    re.compile(r"kerberos::", re.I),
    re.compile(r"privilege::debug", re.I),
    re.compile(r"lsadump::", re.I),
    re.compile(r"crypto::", re.I),
    re.compile(r"token::", re.I),
    re.compile(r"vault::", re.I),
    re.compile(r"dpapi::", re.I),
]
PROCESS_HOLLOWING_TARGETS: Set[str] = {"svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "services.exe", "csrss.exe", "smss.exe", "wininit.exe"}
SUSPICIOUS_DLLS: Set[str] = {"wininet.dll", "ws2_32.dll", "ntdll.dll", "kernel32.dll", "kernelbase.dll"}
KNOWN_LSASS_PROTECTORS: Set[str] = {"lsass.exe", "lsaiso.exe"}
PASS_THE_HASH_TOOLS: List[str] = ["wmiexec", "psexec", "smbexec", "atexec", "dcomexec", "secdump", "crackmapexec", "responder", "impacket", "ntlmrelayx"]

PROTECTED_PROCESSES: List[str] = [
    "lsass", "lsaiso", "winlogon", "services", "svchost",
    "audiodg", "csrss", "smss", "wininit", "system",
]

SENSITIVE_PROC_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:^|[/\\])(?:wget|curl|nc|ncat|netcat|powershell|cmd|python|perl|ruby|php|bash)\s+(?:-e|-c|-i|\/c|\/e)", re.I),
    re.compile(r"(?:downloadstring|invoke-webrequest|wget|curl).*?(?:-outfile|-o|>)\s+", re.I),
    re.compile(r"(?:bypass|unrestricted|hidden|-w\s+hidden|-ep\s+bypass)", re.I),
    re.compile(r"(?:schtasks|at\s+|sc\s+create|wmic\s+process)", re.I),
    re.compile(r"(?:invoke-mimikatz|invoke-thehash|invoke-tokenmanipulation)", re.I),
]


class ProcessShield:
    def __init__(self):
        self._proc_ancestry: Dict[int, int] = {}
        self._proc_cmdline: Dict[int, str] = {}
        self._proc_start: Dict[int, float] = {}
        self._suspicious_procs: Dict[int, float] = defaultdict(float)
        self._known_pids_last: Set[int] = set()
        self._scan_count: int = 0

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze event for process-based threats (mimikatz, hollowing, injections)."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        pid = extra.get("pid") or event.get("pid")
        parent_pid = extra.get("ppid") or extra.get("parent_pid")

        if etype == "new_process":
            proc_name = extra.get("process", extra.get("name", "")).lower()
            cmdline = extra.get("command_line", extra.get("cmdline", "")).lower()
            self._track_process(int(pid) if pid else 0, int(parent_pid) if parent_pid else 0, proc_name, cmdline, results)
        if etype in ("agent_telemetry", "system_check", "process_telemetry"):
            self._scan_processes(results)
        if etype == "memory_alert":
            self._analyze_memory_event(extra, results)

        return results

    def _track_process(self, pid: int, ppid: int, name: str, cmdline: str, res: dict):
        if pid <= 0:
            return
        self._proc_ancestry[pid] = ppid
        self._proc_cmdline[pid] = cmdline
        self._proc_start[pid] = time.time()
        if len(self._proc_ancestry) > 10000:
            self._proc_ancestry.clear()
        if not name and not cmdline:
            return

        for sig in MIMIKATZ_SIGNATURES:
            if sig.search(name) or sig.search(cmdline):
                self._add_finding(res, "mimikatz_detected", f"Mimikatz detected: {name} (PID {pid})", 98, {"pid": pid, "process": name})
                break

        for tool in PASS_THE_HASH_TOOLS:
            if tool in name or tool in cmdline:
                self._add_finding(res, "pass_the_hash_detected", f"Pass-the-hash tool: {name} (PID {pid})", 95, {"pid": pid, "tool": tool})
                break

        for pat in SENSITIVE_PROC_PATTERNS:
            if pat.search(cmdline) or pat.search(name):
                self._add_finding(res, "suspicious_command", f"Suspicious command: {name} (PID {pid})", 85, {"pid": pid, "matched": pat.pattern[:60]})
                break

        if ppid > 0 and ppid in self._proc_ancestry:
            grandparent = self._proc_ancestry.get(ppid, 0)
            if name in ("cmd.exe", "powershell.exe", "powershell", "sh", "bash") and grandparent == 4:
                self._add_finding(res, "winlogon_child_process", f"Shell spawned from winlogon via PID {ppid}: {name}", 90, {"pid": pid, "ppid": ppid, "grandparent": grandparent})

    def _scan_processes(self, res: dict):
        self._scan_count += 1
        if self._scan_count % 3 != 0:
            return
        proc = Path("/proc")
        if not proc.exists():
            return
        current_pids: Set[int] = set()
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            current_pids.add(pid)
        new_pids = current_pids - self._known_pids_last
        for pid in new_pids:
            try:
                comm = (proc / str(pid) / "comm").read_text().strip().lower()
                cmdline_raw = (proc / str(pid) / "cmdline").read_text(errors="replace").lower().replace("\0", " ")
                self._track_process(pid, 0, comm, cmdline_raw, res)
            except Exception as e:
                log.warning("Cannot read /proc/%s: %s", pid, e)
        self._known_pids_last = current_pids
        if len(self._known_pids_last) > 5000:
            self._known_pids_last = set(list(self._known_pids_last)[-3000:])

        for pid in list(self._suspicious_procs.keys()):
            if pid not in current_pids:
                self._add_finding(res, "process_tampered", f"Suspicious process PID {pid} disappeared", 88, {"pid": pid})
                del self._suspicious_procs[pid]

    def _analyze_memory_event(self, extra: dict, res: dict):
        mem_type = extra.get("memory_type", "")
        region = extra.get("region", "")
        if mem_type == "writable_executable":
            self._add_finding(res, "w_x_memory", f"W+X memory region: {region}", 92, {"region": region})
        if mem_type == "process_hollowing":
            self._add_finding(res, "process_hollowing", f"Process hollowing detected: {extra.get('process', '')}", 96, extra)
        if mem_type == "dll_injection":
            self._add_finding(res, "dll_injection", f"DLL injection detected: {extra.get('dll', '')} into {extra.get('target', '')}", 94, extra)
        if mem_type == "hook_detected":
            self._add_finding(res, "api_hooking", f"API hook detected: {extra.get('api', '')}", 88, extra)
        if mem_type == "stack_pivot":
            self._add_finding(res, "stack_pivot", f"Stack pivot detected in PID {extra.get('pid', '')}", 95, extra)

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True
        pid = details.get("pid", 0)
        if pid:
            self._suspicious_procs[pid] = max(self._suspicious_procs.get(pid, 0), risk)


process_shield = ProcessShield()
