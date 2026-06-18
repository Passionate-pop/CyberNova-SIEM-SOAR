"""
Cryptojacking Detector — identifies cryptocurrency mining processes,
network traffic to mining pools, and browser-based mining scripts.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

log = logging.getLogger("cybernova.protection.cryptojacking")

MINING_PROCESS_NAMES = [
    "xmrig", "xmrig-nvidia", "xmrig-amd", "xmrig-cpu",
    "cpuminer", "minerd", "ccminer", "sgminer", "bfgminer",
    "cgminer", "ethminer", "claymore", "PhoenixMiner",
    "TeamRedMiner", "lolMiner", "T-Rex", "NBMiner", "GMiner",
    "bminer", "ewbf", "dstm", "zm", "ewbf",
    "cryptonight", "stratum", "monero", "xmr",
    "ethdcrminer64", "ethdcrminer", "EthDcrMiner",
]

MINING_POOL_DOMAINS = [
    "pool.minexmr.com", "xmrpool.eu", "minexmr.com",
    "supportxmr.com", "pool.supportxmr.com",
    "ethermine.org", "pool.ethermine.org",
    "f2pool.com", "eth.f2pool.com",
    "nanopool.org", "eth.nanopool.org",
    "poolin.com", "eth.poolin.com",
    "sparkpool.com", "eth.sparkpool.com",
    "miningpoolhub.com", "hub.miningpoolhub.com",
    "zpool.ca", "nicehash.com",
    "daggerhashimoto", "stratum+tcp://", "stratum+ssl://",
]

BROWSER_MINER_SCRIPTS = [
    "coinhive", "coin-hive", "cryptoloot", "miner",
    "deepminer", "jsecoin", "webmine", "minr",
    "monerominer", "coinimp", "mining",
]

MINING_PORT_RANGES = [
    (3333, 3339), (4444, 4449), (5555, 5559),
    (7777, 7779), (8888, 8889), (14444, 14445),
    (20535, 20536), (33433, 33435),
]


def detect_mining_processes() -> List[Dict[str, Any]]:
    findings = []
    try:
        proc = Path("/proc")
        if not proc.exists():
            return findings
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_text(errors="replace").lower()
                comm = (entry / "comm").read_text(errors="replace").strip().lower()
            except (OSError, PermissionError) as e:
                log.warning("Cryptojacking: could not read process %s: %s", entry.name, e)
                continue

            combined = f"{cmdline} {comm}"
            for name in MINING_PROCESS_NAMES:
                if name.lower() in combined:
                    findings.append({
                        "type": "cryptominer_process",
                        "severity": "critical",
                        "risk_score": 95.0,
                        "message": f"Cryptominer process detected: {comm} (PID {entry.name})",
                        "process": comm, "pid": int(entry.name),
                        "matched_pattern": name,
                    })
                    break

            for pool in MINING_POOL_DOMAINS:
                if pool.lower() in cmdline:
                    findings.append({
                        "type": "mining_pool_connection",
                        "severity": "high",
                        "risk_score": 88.0,
                        "message": f"Mining pool connection in process {comm}: {pool}",
                        "process": comm, "pool": pool,
                    })
                    break

            if "stratum" in cmdline:
                findings.append({
                    "type": "stratum_protocol_usage",
                    "severity": "critical",
                    "risk_score": 92.0,
                    "message": f"Stratum mining protocol in use by {comm}",
                    "process": comm, "pid": int(entry.name),
                })
    except Exception as e:
        log.warning("Mining process detection error: %s", e)
    return findings


def detect_browser_mining(content: str) -> List[Dict[str, Any]]:
    findings = []
    for script in BROWSER_MINER_SCRIPTS:
        if script.lower() in content.lower():
            findings.append({
                "type": "browser_cryptominer",
                "severity": "high",
                "risk_score": 85.0,
                "message": f"Browser-based cryptominer script detected: {script}",
                "matched_script": script,
            })
    return findings


def check_cpu_mining_indicator(cpu_percent: float, processes: int) -> List[Dict[str, Any]]:
    findings = []
    if cpu_percent > 80.0 and processes <= 5:
        findings.append({
            "type": "sustained_high_cpu",
            "severity": "medium",
            "risk_score": 60.0,
            "message": f"Sustained {cpu_percent:.0f}% CPU with low process count — possible miner",
            "cpu_percent": cpu_percent, "process_count": processes,
        })
    return findings


def scan() -> Dict[str, Any]:
    all_findings = []
    all_findings.extend(detect_mining_processes())

    miner_detected = any(f.get("type") == "cryptominer_process" for f in all_findings)
    pool_detected = any(f.get("type") == "mining_pool_connection" for f in all_findings)
    max_risk = max((f.get("risk_score", 0) for f in all_findings), default=0.0)

    return {
        "scan_complete": True,
        "cryptominer_detected": miner_detected or pool_detected,
        "max_risk_score": round(max_risk, 1),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


cryptojacking_detector = scan
