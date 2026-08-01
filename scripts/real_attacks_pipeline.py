#!/usr/bin/env python3
"""
CyberNova -- REAL ATTACK SIMULATOR (Pipeline Edition)
Sends events directly into POST /api/v1/pipeline/ingest so they go through
normalization -> enrichment -> detection -> correlation -> SOAR.
Each event type matches a specific detection rule in rules.py.
"""
import json, sys, time, os
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import ssl

# Force UTF-8 for stdout to avoid cp1252 issues
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

API = "http://localhost:8000"
TOKEN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TOKEN", "")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def post(path, data, token):
    body = json.dumps(data).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    req = Request(f"{API}{path}", data=body, headers=headers, method="POST")
    return json.loads(urlopen(req, timeout=15, context=ctx).read().decode())

# =====================================================================
# REAL ATTACK EVENTS - each matches specific detection rule(s) in rules.py
# =====================================================================
attacks = [
    # 1. Malware Detection (critical, 95.0) - event_type: malware_detected
    {
        "event_type": "malware_detected",
        "severity": "critical",
        "message": "TrojanDropper:Win32/Malgent!MTB detected in C:\\Users\\Public\\svchost.exe - signature match",
        "source_ip": "203.0.113.45",
        "process_name": "svchost.exe",
        "file_path": "C:\\Users\\Public\\svchost.exe",
    },
    # 2. Ransomware (critical, 98.0) - event_type contains "ransom"
    {
        "event_type": "ransomware_outbreak",
        "severity": "critical",
        "message": "Mass file encryption: 2,847 files renamed to .locked in C:\\Users\\Public\\Documents - ransomware outbreak",
        "source_ip": "198.51.100.20",
        "file_path": "C:\\Users\\Public\\Documents\\*.locked",
    },
    # 3. C2 Beacon (critical, 92.0) - event_type contains "c2"
    {
        "event_type": "c2_beacon_detected",
        "severity": "critical",
        "message": "C2 communication detected: powershell.exe beaconing to 45.33.32.156:4443 every 30s",
        "source_ip": "10.0.0.5",
        "dest_ip": "45.33.32.156",
        "dest_port": 4443,
        "process_name": "powershell.exe",
    },
    # 4. SQL Injection (critical, 90.0) - event_type contains "sql injection"
    {
        "event_type": "sql_injection_attempt",
        "severity": "critical",
        "message": "SQL injection at /api/users: UNION SELECT username,password_hash,email FROM users-- (blocked by WAF)",
        "source_ip": "192.168.1.100",
        "dest_port": 443,
        "url": "/api/users?id=1 UNION SELECT username,password_hash,email FROM users--",
    },
    # 5. Privilege Escalation (critical, 90.0) - event_type contains "privilege escalat"
    {
        "event_type": "privilege_escalation_attack",
        "severity": "critical",
        "message": "Privilege escalation exploited: user 'supportadmin' added to Domain Admins via CVE-2025-2620",
        "source_ip": "10.0.0.15",
        "user": "supportadmin",
    },
    # 6. Webshell (critical, 95.0) - event_type: webshell_detected
    {
        "event_type": "webshell_detected",
        "severity": "critical",
        "message": "Webshell uploaded: C:\\inetpub\\wwwroot\\upload.aspx - contains base64-encoded PowerShell payload",
        "source_ip": "203.0.113.100",
        "file_path": "C:\\inetpub\\wwwroot\\upload.aspx",
    },
    # 7. Rootkit (critical, 98.0) - event_type: rootkit_detected
    {
        "event_type": "rootkit_detected",
        "severity": "critical",
        "message": "Rootkit detected: Alureon variant hiding processes on LAPTOP-3F4IM0LO - unsigned kernel driver loaded",
        "source_ip": "10.0.0.5",
        "hostname": "LAPTOP-3F4IM0LO",
    },
    # 8. Keylogger (critical, 95.0) - event_type: keylog_detected
    {
        "event_type": "keylog_detected",
        "severity": "critical",
        "message": "Keylogger active: SetWindowsHookEx installed in chrome.exe - capturing keystrokes and clipboard",
        "source_ip": "10.0.0.5",
        "process_name": "chrome.exe",
    },
    # 9. Data Exfiltration (high, 80.0) - event_type contains "data exfil"
    {
        "event_type": "data_exfiltration_event",
        "severity": "critical",
        "message": "Data exfiltration: 250MB of customer PII uploaded to 198.51.100.50:443 via HTTPS tunnel",
        "source_ip": "10.0.0.5",
        "dest_ip": "198.51.100.50",
        "dest_port": 443,
        "bytes": 250000000,
    },
    # 10. C2 via message match (critical, 92.0) - message contains "command and control"
    {
        "event_type": "network_connection",
        "severity": "high",
        "message": "C2 communication detected - command and control beacon to known bad IP 198.51.100.99:8080",
        "source_ip": "10.0.0.5",
        "dest_ip": "198.51.100.99",
        "dest_port": 8080,
    },
    # 11. Tamper detected (critical, 99.0) - event_type: tamper_detected
    {
        "event_type": "tamper_detected",
        "severity": "critical",
        "message": "Windows Defender disabled via registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware=1",
        "source_ip": "10.0.0.5",
        "registry_key": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
    },
    # 12. Cryptominer (critical, 95.0) - event_type: cryptominer_detected
    {
        "event_type": "cryptominer_detected",
        "severity": "critical",
        "message": "Cryptominer running: xmrig.exe consuming 98% CPU on server - Monero wallet detected",
        "source_ip": "10.0.0.5",
        "process_name": "xmrig.exe",
    },
    # 13. DLP Leak (critical, 90.0) - event_type: dlp_leak_detected
    {
        "event_type": "dlp_leak_detected",
        "severity": "critical",
        "message": "Sensitive data leak: 5,000 credit card numbers posted to pastebin.com from internal IP",
        "source_ip": "10.0.0.5",
    },
    # 14. Encoded PowerShell in message (critical, 88.0)
    {
        "event_type": "process_start",
        "severity": "high",
        "message": "Encoded PowerShell command executed: powershell -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        "source_ip": "10.0.0.5",
        "command_line": "powershell -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    },
    # 15. Phishing in message (high, 82.0)
    {
        "event_type": "email_reported",
        "severity": "high",
        "message": "Phishing campaign detected: spoofed email from security@cybernova-verify.com harvesting O365 credentials - 25 employees targeted",
        "source_ip": "203.0.113.200",
    },
    # 16. DNS Tunneling in message (high, 80.0)
    {
        "event_type": "dns_query",
        "severity": "high",
        "message": "DNS tunneling detected - base64-encoded subdomain queries to c2.xyzmalware.net from internal resolver",
        "source_ip": "10.0.0.5",
        "dest_ip": "8.8.8.8",
    },
    # 17. Lateral Movement in message (high, 82.0)
    {
        "event_type": "network_logon",
        "severity": "critical",
        "message": "Lateral movement detected: pass-the-hash attack via ADMIN$ from 10.0.0.15 to 10.0.0.20",
        "source_ip": "10.0.0.15",
        "dest_ip": "10.0.0.20",
        "user": "NT AUTHORITY\\SYSTEM",
    },
    # 18. Brute Force in message (high, 78.0)
    {
        "event_type": "authentication_failure",
        "severity": "high",
        "message": "SSH brute force attack: 1,500 failed login attempts from 45.33.32.156 to root@10.0.0.5:22 in 5 min",
        "source_ip": "45.33.32.156",
        "dest_port": 22,
        "user": "root",
    },
    # 19. Critical severity catch-all (critical, 95.0)
    {
        "event_type": "kernel_integrity_violation",
        "severity": "critical",
        "message": "Windows kernel integrity violation: driver signature enforcement bypassed - unsigned driver loaded",
        "source_ip": "10.0.0.5",
    },
    # 20. Platform compromised (critical, 99.0)
    {
        "event_type": "platform_compromised",
        "severity": "critical",
        "message": "CyberNova management API key exfiltrated from vault - platform access from unauthorized IP 91.234.56.78",
        "source_ip": "91.234.56.78",
    },
]

print("=" * 60)
print("  CYBERNOVA - REAL ATTACK PIPELINE INJECTION")
print("  20 attack events -> detection rules -> alerts")
print("=" * 60)

# Send all events in one batch
batch = {"source": "attack_sim", "source_type": "api", "events": attacks}

try:
    result = post("/api/v1/pipeline/ingest", batch, TOKEN)
    q = result.get('events_queued', '?')
    ids = result.get('task_ids', ['-'])
    print(f"  [OK] Pipeline accepted {q} events | Batch: {ids[0][:20]}...")
except HTTPError as e:
    body = e.read().decode()[:300]
    print(f"  [FAIL] HTTP {e.code}: {body}")
    sys.exit(1)
except Exception as e:
    print(f"  [FAIL] {e}")
    sys.exit(1)

# Wait for pipeline to process
print()
print("  Waiting for pipeline processing...", end="", flush=True)
for _ in range(8):
    time.sleep(1)
    print(".", end="", flush=True)
print()

# Check alerts from dashboard
print()
print("  Checking alerts...")
try:
    req = Request(f"{API}/api/v1/dashboard/alerts?limit=50",
                  headers={"Authorization": f"Bearer {TOKEN}"}, method="GET")
    resp = urlopen(req, timeout=5, context=ctx)
    data = json.loads(resp.read().decode())
    alerts = data if isinstance(data, list) else (data.get("alerts") or data.get("items") or data.get("results") or [])

    print(f"  [DATA] {len(alerts)} alerts found")

    # Group by severity
    sev_counts = {}
    for a in alerts:
        s = a.get("severity", "unknown").upper() if isinstance(a, dict) else "?"
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            print(f"    [{sev[:4]:4}] {sev}: {sev_counts[sev]}")

    print()
    print("  Latest alerts by rule:")
    print("  " + "-" * 55)
    for a in alerts[:10]:
        sev = a.get("severity", "?").upper() if isinstance(a, dict) else "?"
        rule = a.get("rule_name") or a.get("event_type") or "?"
        msg = (a.get("message") or a.get("description") or "")[:70]
        print(f"  [{sev[:4]:4}] {rule}")
        print(f"         {msg}")

except Exception as e:
    print(f"  [WARN] Alert check: {e}")

print()
print("=" * 60)
print("  Dashboard: http://localhost:8080/app/")
print("=" * 60)
