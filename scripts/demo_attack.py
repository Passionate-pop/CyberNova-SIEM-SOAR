#!/usr/bin/env python3
"""
CyberNova — Live Demo Attack Script
Run this AFTER registering on the dashboard.

This sends REALISTIC attack events through the CyberNova pipeline.
Watch the dashboard at http://localhost:8080/app/ for live alerts.

Usage:
    python scripts/demo_attack.py
"""
import json, sys, time, httpx

BASE = "http://localhost:8000"
USERNAME = input("  Username: ").strip() or "admin"
PASSWORD = input("  Password: ").strip() or "admin"

# Login
print("\n[*] Logging in...")
r = httpx.post(f"{BASE}/api/v1/auth/login", json={"username": USERNAME, "password": PASSWORD}, timeout=10)
if r.status_code != 200:
    print(f"[!] Login failed: {r.text}")
    sys.exit(1)
token = r.json()["access_token"]
print(f"[+] Logged in as {USERNAME}")
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Attack events — realistic server attacks
attacks = [
    {"event_type":"failed_login","severity":"high","message":"SSH brute force: 1,247 failed attempts from 45.33.32.156 to root@10.0.0.5:22 — credential stuffing","source_ip":"45.33.32.156","user":"root"},
    {"event_type":"malicious_process","severity":"critical","message":"Suspicious process /tmp/.systemd-boot with no parent — masquerading as system binary","source_ip":"10.0.0.5","process_name":".systemd-boot"},
    {"event_type":"unusual_process","severity":"high","message":"Reverse shell from 10.0.0.5:4444 to 198.51.100.20:9999 — possible C2 callback","source_ip":"10.0.0.5","dest_ip":"198.51.100.20"},
    {"event_type":"scheduled_task","severity":"high","message":"Cron @reboot /var/tmp/.cache-update added for www-data — persistence mechanism","source_ip":"10.0.0.5","user":"www-data"},
    {"event_type":"user_created","severity":"high","message":"New user 'supportadmin' with UID 0 and sudo — possible backdoor account","source_ip":"10.0.0.5","user":"supportadmin"},
    {"event_type":"file_changed","severity":"high","message":"/etc/shadow accessed outside normal password change — credential harvesting","source_ip":"10.0.0.5"},
    {"event_type":"encoded_powershell","severity":"critical","message":"Encoded PowerShell download cradle detected on Windows host","source_ip":"10.0.0.5"},
    {"event_type":"tamper_detected","severity":"critical","message":"auditd config cleared — audit will not start on reboot, attacker covering tracks","source_ip":"10.0.0.5"},
    {"event_type":"new_listener","severity":"high","message":"New TCP listener on 0.0.0.0:4444 — possible bind shell, no known service","source_ip":"10.0.0.5"},
    {"event_type":"suspicious_network","severity":"high","message":"Port scan: 185.220.101.20 scanned 2,304 ports on 10.0.0.5 in 12s — reconnaissance","source_ip":"185.220.101.20","dest_ip":"10.0.0.5"},
    {"event_type":"external_connection","severity":"high","message":"Unknown outbound to 198.51.100.50:443 — no DNS match, possible C2 beacon","source_ip":"10.0.0.5","dest_ip":"198.51.100.50"},
    {"event_type":"suspicious_file","severity":"high","message":"Web shell /var/www/html/upload.php with system() + base64_decode — RCE possible","source_ip":"192.168.1.100"},
    {"event_type":"phishing_in_message","severity":"high","message":"Email with fake login page link detected in user inbox — credential phish","source_ip":"45.33.32.156","user":"staff@company.com"},
]

payload = {"source": "live_demo", "source_type": "api", "events": attacks}

print(f"\n[*] Sending {len(attacks)} real attack events through CyberNova pipeline...")
r = httpx.post(f"{BASE}/api/v1/pipeline/ingest", headers=headers, json=payload, timeout=15)

if r.status_code == 200:
    data = r.json()
    print(f"[+] {data.get('events_queued', 0)} events accepted by pipeline")
    print(f"[+] Pipeline processing: enrichment → detection → correlation...")
    print(f"\n  ⏳ Alerts will appear in ~10-15 seconds")
    print(f"  👉 WATCH THE DASHBOARD: http://localhost:8080/app/")
    print(f"  🚨 Live toast notifications will pop up via WebSocket\n")
    
    # Poll for results
    print("[*] Polling for alerts (checking every 5s)...")
    for i in range(12):
        time.sleep(5)
        r2 = httpx.get(f"{BASE}/api/v1/dashboard/summary", headers=headers, timeout=10)
        if r2.status_code == 200:
            s = r2.json()
            total = s.get("total_alerts", 0)
            crit = s.get("severity_counts", {}).get("critical", 0)
            high = s.get("severity_counts", {}).get("high", 0)
            if total > 0:
                print(f"\n  [tick {i+1}] 🔴 {crit} critical | 🟠 {high} high | total: {total} alerts")
                if total >= 10:
                    print(f"\n✅ ALL ATTACKS DETECTED! Dashboard shows {total} alerts.")
                    print(f"   Go to http://localhost:8080/app/ to investigate.")
                    break
            else:
                print(f"  [tick {i+1}] Pipeline processing... (0 alerts so far)")
else:
    print(f"[!] Failed: {r.status_code} {r.text[:200]}")
