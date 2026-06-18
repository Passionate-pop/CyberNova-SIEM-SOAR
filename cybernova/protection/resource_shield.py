from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

log = logging.getLogger("cybernova.protection.resource_shield")

MINING_PROCESS_NAMES: Set[str] = {
    "xmrig", "xmrig-nvidia", "xmrig-amd", "xmrig-cpu",
    "cpuminer", "minerd", "ccminer", "sgminer", "bfgminer",
    "cgminer", "ethminer", "claymore", "phoenixminer", "teamredminer",
    "lolminer", "trex", "nbminer", "gminer", "bminer",
    "ewbf", "dstm", "zm", "ethdcrminer64", "ethdcrminer",
    "srbminer", "wildrig", "beamcuda", "beamopencl",
    "lolminer", "tt-miner", "tonpoolminer",
}
MINING_POOL_PATTERNS: List[re.Pattern] = [
    re.compile(r"stratum\+?(tcp|ssl)?://", re.I),
    re.compile(r"pool\.(minexmr|xmrpool|supportxmr|ethermine|f2pool|nanopool|poolin|sparkpool|miningpoolhub|zpool)\.", re.I),
    re.compile(r"(nicehash|daggerhashimoto|cryptonight|ethash|equihash)", re.I),
    re.compile(r"monero|ethereum|zcash|bytecoin|electroneum", re.I),
]
BROWSER_MINER_DOMAINS: Set[str] = {
    "coinhive.com", "coin-hive.com", "cryptoloot.pro", "jsecoin.com",
    "miner.pr0gramm.com", "webmine.cz", "miner.eu", "coinimp.com",
    "monerominer.rocks", "deepminer.xyz", "minr.pw",
}
BROWSER_MINER_PATTERNS: List[re.Pattern] = [
    re.compile(r"coin[-_]?hive|miner|webmine|cryptoloot|jsecoin", re.I),
    re.compile(r"miner\.(js|wasm)"),
    re.compile(r"new\s+Cryptonight|new\s+CoinHive|new\s+Miner", re.I),
]
SESSION_HIJACK_PATTERNS: List[re.Pattern] = [
    re.compile(r"session|token|cookie|jwt", re.I),
    re.compile(r"document\.cookie|localStorage|sessionStorage", re.I),
    re.compile(r"x-requested-with|x-csrf-token|x-xsrf-token", re.I),
]
SUSPICIOUS_USER_AGENTS: List[re.Pattern] = [
    re.compile(r"curl|wget|python-requests|go-http-client|java/|ruby|perl|libwww", re.I),
    re.compile(r"masscan|nmap|zmap|zgrab|http-scanner", re.I),
    re.compile(r"sqlmap|havij|sqlninja", re.I),
]

GPU_MONITOR_PATHS: List[str] = [
    "/sys/class/drm/card0/device/gpu_busy_percent",
    "/sys/class/drm/card1/device/gpu_busy_percent",
    "/proc/driver/nvidia/gpus/0/usage",
    "/proc/driver/nvidia/gpus/1/usage",
]


class ResourceShield:
    def __init__(self):
        self._cpu_samples: Dict[int, List[float]] = defaultdict(list)
        self._process_cpu: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
        self._gpu_check_time: float = 0
        self._session_tokens: Dict[str, float] = {}
        self._request_rate: Dict[str, List[float]] = defaultdict(list)

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze event for resource abuse (cryptominers, scanning, session hijack)."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        message = event.get("message", "")

        if etype in ("system_check", "process_event", "process_telemetry"):
            self._detect_cryptominers(results, extra)
            self._check_gpu_usage(results)
            self._detect_resource_abuse(results)

        if etype == "http_request":
            ua = extra.get("user_agent", extra.get("user-agent", ""))
            path = extra.get("url", extra.get("path", ""))
            session = extra.get("session_id", extra.get("cookie", ""))
            self._detect_scanning(ua, path, results)
            self._detect_session_hijack(session, path, results)
            self._detect_browser_miner(path, message, results)

        return results

    def _detect_cryptominers(self, res: dict, extra: dict):
        proc = Path("/proc")
        if not proc.exists():
            return
        time.time()
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmdline = (entry / "cmdline").read_text(errors="replace").lower().replace("\0", " ")
                comm = (entry / "comm").read_text(errors="replace").strip().lower()
            except (OSError, PermissionError) as e:
                log.warning("ResourceShield cryptominer detection: could not read process %s: %s", entry.name, e)
                continue
            combined = f"{cmdline} {comm}"

            for name in MINING_PROCESS_NAMES:
                if name in combined:
                    cpu_usage = self._estimate_cpu(pid)
                    self._add_finding(res, "cryptominer_process", f"Cryptominer: {comm} (PID {pid}) [{cpu_usage:.0f}% CPU]", 95, {"pid": pid, "process": comm, "matched": name, "cpu": cpu_usage})
                    break

            for pat in MINING_POOL_PATTERNS:
                if pat.search(cmdline):
                    self._add_finding(res, "mining_pool_connection", f"Mining pool in PID {pid} ({comm}): {pat.pattern[:40]}", 88, {"pid": pid, "pattern": pat.pattern[:60]})
                    break

            if "stratum" in cmdline:
                self._add_finding(res, "stratum_protocol", f"Stratum mining protocol: PID {pid} ({comm})", 92, {"pid": pid})

    def _check_gpu_usage(self, res: dict):
        now = time.time()
        if now - self._gpu_check_time < 30:
            return
        self._gpu_check_time = now
        for gpu_path in GPU_MONITOR_PATHS:
            try:
                p = Path(gpu_path)
                if p.exists():
                    usage = int(p.read_text().strip())
                    if usage > 90:
                        self._add_finding(res, "gpu_high_usage", f"GPU usage {usage}% — possible cryptomining", 80, {"gpu_path": gpu_path, "usage": usage})
            except (OSError, PermissionError, ValueError) as e:
                log.warning("ResourceShield GPU usage check failed for %s: %s", gpu_path, e)

    def _detect_resource_abuse(self, res: dict):
        proc = Path("/proc")
        if not proc.exists():
            return
        total_mem = 0
        proc_count = 0
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text()
                for line in status.split("\n"):
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        total_mem += kb
                        break
                proc_count += 1
            except (OSError, ValueError) as e:
                log.warning("ResourceShield resource abuse: could not read process %s: %s", entry.name, e)
                continue
        if proc_count > 500:
            self._add_finding(res, "excessive_process_count", f"Excessive processes: {proc_count} running", 65, {"count": proc_count})
        if total_mem > 16 * 1024 * 1024:
            self._add_finding(res, "excessive_memory_usage", f"Total RSS {total_mem // 1024 // 1024}GB — possible abuse", 70, {"memory_mb": total_mem // 1024})

    def _detect_scanning(self, ua: str, path: str, res: dict):
        for pat in SUSPICIOUS_USER_AGENTS:
            if ua and pat.search(ua):
                self._add_finding(res, "scanning_tool", f"Scanning tool detected in UA: {ua[:60]}", 75, {"user_agent": ua[:120], "matched": pat.pattern[:40]})
                break

    def _detect_session_hijack(self, session: str, path: str, res: dict):
        if not session:
            return
        if re.search(r"document\.cookie|steal|hijack|session.*fix", path, re.I):
            self._add_finding(res, "session_hijacking", f"Session hijacking attempt: {path[:80]}", 92, {"path": path[:120]})

    def _detect_browser_miner(self, path: str, message: str, res: dict):
        combined = f"{path} {message}"
        for domain in BROWSER_MINER_DOMAINS:
            if domain in combined.lower():
                self._add_finding(res, "browser_cryptominer", f"Browser miner domain: {domain}", 88, {"domain": domain})
                break
        for pat in BROWSER_MINER_PATTERNS:
            if pat.search(combined):
                self._add_finding(res, "browser_miner_script", "Browser miner script detected", 88, {"pattern": pat.pattern[:40]})
                break

    def _estimate_cpu(self, pid: int) -> float:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            parts = stat.split()
            if len(parts) >= 14:
                utime = int(parts[13])
                stime = int(parts[14])
                total = utime + stime
                time.time()
                if pid not in self._cpu_samples:
                    self._cpu_samples[pid] = [0.0]
                self._cpu_samples[pid].append(float(total))
                if len(self._cpu_samples[pid]) > 2:
                    delta = self._cpu_samples[pid][-1] - self._cpu_samples[pid][-2]
                    self._cpu_samples[pid] = self._cpu_samples[pid][-2:]
                    if delta > 0:
                        return delta / 100.0
        except (OSError, IndexError, ValueError) as e:
            log.warning("ResourceShield CPU estimation failed for PID %s: %s", pid, e)
        return 0.0

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True


resource_shield = ResourceShield()
