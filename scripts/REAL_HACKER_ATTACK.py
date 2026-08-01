#!/usr/bin/env python3
"""
CyberNova -- REAL ALERT GENERATOR
==================================
Injects 13 events that EXACTLY match detection rules.
Creates REAL dashboard alerts -- instantly.

Auto-detects your JWT token. If it's stale (DB was reset),
auto-logins to get a fresh one and retries.

USAGE:
  python scripts\REAL_HACKER_ATTACK.py
"""

import os, sys, json, time, random
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import ssl

# -- Config -----------------------------------------------------------
API = "http://localhost:8000"
ADMIN_USER = "admin"
ADMIN_PASS = "CMklXpm1LKHXGB7M"

# -- Detect stored token ----------------------------------------------
_cfg = {"token": ""}
try:
    p = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "CyberNova", "agent_config.json")
    if os.path.exists(p):
        with open(p) as f:
            _cfg = json.load(f)
except Exception:
    pass

stored_token = os.environ.get("CYBERNOVA_TOKEN") or os.environ.get("TOKEN") or _cfg.get("token", "") or ""
TOKEN = stored_token

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sent_ok = 0
sent_fail = 0

def req_post(path, data=None, token=None):
    """POST request with optional token. If no token, sends without auth header."""
    body = json.dumps(data).encode("utf-8") if data is not None else b"{}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(f"{API}{path}", data=body, headers=headers, method="POST")
    return json.loads(urlopen(req, timeout=10, context=ctx).read().decode())

def req_get(path, token=None):
    """GET request with optional token."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(f"{API}{path}", headers=headers, method="GET")
    return json.loads(urlopen(req, timeout=10, context=ctx).read().decode())

def try_login():
    """Try to get a fresh token by logging in."""
    global TOKEN
    print("  Attempting login as admin...")
    try:
        body = json.dumps({"username": ADMIN_USER, "password": ADMIN_PASS}).encode()
        req = Request(f"{API}/api/v1/auth/login", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        resp = json.loads(urlopen(req, timeout=10, context=ctx).read().decode())
        fresh = resp.get("access_token", "")
        if fresh:
            TOKEN = fresh
            print("  Got fresh token!")
            return True
    except HTTPError as e:
        err = e.read().decode()[:150]
        print(f"  Login failed: HTTP {e.code} - {err}")
    except Exception as e:
        print(f"  Login failed: {e}")
    return False

# =====================================================================

start_ts = time.time()

print("")
print("  " + "=" * 60)
print("  CYBERNOVA -- REAL ALERT GENERATOR")
print("  13 attacks -> REAL dashboard alerts")
print("  " + "=" * 60)
print("")

# -- Check pipeline status -------------------------------------------
pipeline_ok = False
try:
    if TOKEN:
        status = req_get("/api/v1/pipeline/status", TOKEN)
        if status.get("running"):
            pipeline_ok = True
            print("  Pipeline: RUNNING")
        else:
            print("  Pipeline: STOPPED - starting...")
            req_post("/api/v1/pipeline/start", token=TOKEN)
            pipeline_ok = True
            print("  Pipeline started.")
except Exception as e:
    print(f"  Pipeline check: {str(e)[:60]}")

print("")

# =====================================================================
# SEND 13 ATTACKS WITH AUTO-RETRY ON 500
# =====================================================================

attacks = [
    ("T1016 Reconnaissance",       "external_connection", "high",     "External connection to unknown host -- recon scan",     {"dest_ip": "45.33.32.156", "protocol": "TCP", "dest_port": 443}),
    ("T1005 Malicious File",       "suspicious_file",     "high",     "Suspicious file with double extension: invoice.pdf.exe",  {"file_path": r"C:\Users\Public\invoice.pdf.exe"}),
    ("T1059.001 Encoded PS",       "encoded_powershell",  "critical", "PowerShell -Enc with base64 payload -- hidden execution",  {"command_line": "powershell -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"}),
    ("T1003 Credential Dump",      "malicious_process",   "critical", "LSASS dumped via mimikatz -- credential theft",           {"process_name": "mimikatz.exe", "command_line": "mimikatz.exe sekurlsa::logonPasswords"}),
    ("T1562 Defense Evasion",      "tamper_detected",     "critical", "Windows Defender disabled via registry -- tampering",     {"registry_key": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware"}),
    ("T1546.001 Scheduled Task",   "scheduled_task",      "high",     "Suspicious scheduled task -- hidden PowerShell as SYSTEM",{"task_name": "WindowsUpdateTask"}),
    ("T1048 C2 Beacon",            "malicious_process",   "critical", "C2 beacon to external server on port 443",              {"process_name": "powershell.exe", "dest_ip": "198.51.100.50", "dest_port": 443}),
    ("T1547.001 Registry Run Key", "registry_changed",    "high",     "Run key added under HKLM for persistence",              {"registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc"}),
    ("T1136 Admin Account",        "user_created",        "high",     "New admin account: SupportAdmin -- lateral movement",    {"username": "SupportAdmin", "group": "Administrators"}),
    ("T1070 Log Tampering",        "file_changed",        "high",     "Security event log cleared -- attacker covering tracks", {"file_path": r"C:\Windows\System32\winevt\Logs\Security.evtx"}),
    ("T1486 Ransomware",           "file_changed",        "critical", "Mass file renaming to .locked -- ransomware outbreak",   {"file_path": r"C:\Users\Public\Documents\*.locked"}),
    ("T1546.003 WMI Persistence",  "registry_changed",    "medium",   "WMI __EventFilter subscription for stealth persistence",{"registry_key": r"root\subscription\__EventFilter"}),
    ("Boot Config Query",          "unusual_process",     "medium",   "BCD config queried via bcdedit -- bootkit recon",        {"process_name": "bcdedit.exe", "command_line": "bcdedit /enum all"}),
]

# Send with retry on 500
need_login = False

def send_attack(name, event_type, severity, desc, extra, use_token):
    """Send one attack event. Returns True on success."""
    event = {"event_type": event_type, "severity": severity, "message": desc,
        "source_ip": f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(2,254)}",
        "timestamp": datetime.now(timezone.utc).isoformat()}
    event.update(extra)
    req_post("/api/v1/pipeline/ingest",
        {"source": "attack_sim", "source_type": "api", "events": [event]},
        token=use_token)
    return True

# First pass: send all attacks
for name, event_type, severity, desc, extra in attacks:
    try:
        send_attack(name, event_type, severity, desc, extra, TOKEN)
        sent_ok += 1
        print(f"  [{severity.upper():8}] {name}")
    except HTTPError as e:
        sent_fail += 1
        body = e.read().decode()[:80]
        print(f"  [FAIL] {name} -> HTTP {e.code}: {body}")
        if e.code == 500:
            need_login = True
    except Exception as e:
        sent_fail += 1
        print(f"  [FAIL] {name} -> {str(e)[:60]}")

# If any failed with 500, try login and retry all failed
if need_login:
    print("")
    print("  Some events failed (stale token after DB reset).")
    if try_login():
        print("  Retrying with fresh token...")
        print("")
        sent_ok = 0
        sent_fail = 0
        for name, event_type, severity, desc, extra in attacks:
            try:
                send_attack(name, event_type, severity, desc, extra, TOKEN)
                sent_ok += 1
                print(f"  [{severity.upper():8}] {name}")
            except HTTPError as e:
                sent_fail += 1
                body = e.read().decode()[:80]
                print(f"  [FAIL] {name} -> HTTP {e.code}: {body}")
            except Exception as e:
                sent_fail += 1
                print(f"  [FAIL] {name} -> {str(e)[:60]}")

# -- Poll for alerts -------------------------------------------------
print("")
print("  Checking for alerts...", end="")
sys.stdout.flush()

alerts_found = 0
alerts = []
for _ in range(12):
    try:
        req = Request(f"{API}/api/v1/dashboard/alerts?limit=50",
            headers={"Authorization": f"Bearer {TOKEN}"}, method="GET")
        resp = urlopen(req, timeout=3, context=ctx)
        data = json.loads(resp.read().decode())
        result = data if isinstance(data, list) else (data.get("alerts") or data.get("items") or data.get("results") or [])
        if len(result) > 0:
            alerts = result
            alerts_found = len(result)
            print(f" {alerts_found} alerts!")
            break
    except Exception:
        pass
    print(".", end="")
    sys.stdout.flush()
    time.sleep(1)

print("")

# -- Results ---------------------------------------------------------
elapsed = time.time() - start_ts
print("")
print("  " + "=" * 60)
print(f"  DONE -- {sent_ok} sent, {sent_fail} failed ({elapsed:.0f}s)")
print("")

if alerts_found > 0:
    print(f"  {alerts_found} alerts created on your dashboard!")
    print("")
    sev_counts = {}
    for a in alerts:
        s = a.get("severity", "unknown").upper() if isinstance(a, dict) else "?"
        sev_counts[s] = sev_counts.get(s, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in sev_counts:
            print(f"    {sev}: {sev_counts[sev]}")
    print("")
    for a in alerts[-6:]:
        if isinstance(a, dict):
            sev = a.get("severity", "?")
            et = a.get("event_type") or a.get("rule_name") or "?"
            msg = (a.get("message") or a.get("description") or "")[:70]
            print(f"    [{sev.upper():8}] {et}")
            print(f"              {msg}")
            print("")
else:
    print("  No alerts found yet. Pipeline may still be processing.")
    print("  Check the dashboard in 10-15 seconds.")

print(f"  Dashboard: http://localhost:8080/app/")
print("  " + "=" * 60)
print("")
