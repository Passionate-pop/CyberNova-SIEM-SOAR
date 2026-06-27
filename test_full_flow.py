#!/usr/bin/env python3
"""Test the FULL real CyberNova flow end-to-end."""
import urllib.request
import json
import time
import sys

BASE = "http://localhost:8000"
PASSWORD = "CMklXpm1LKHXGB7M"

def api(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": str(e), "status": e.code, "body": e.read().decode()[:200]}
    except Exception as e:
        return {"error": str(e)}

print("=" * 60)
print("  CYBERNOVA FULL REAL FLOW TEST")
print("=" * 60)

# Step 1: Login
print("\n>> Step 1: Login")
login = api("POST", "/api/v1/auth/login", body={"username": "admin", "password": PASSWORD})
token = login.get("access_token", "")
if token:
    print(f"  [PASS] Logged in, token: {token[:20]}...")
else:
    print(f"  [FAIL] Login failed: {login}")
    sys.exit(1)

# Step 2: Check agent download endpoints
print("\n>> Step 2: Agent download endpoints")
req = urllib.request.Request(f"{BASE}/agent.ps1")
try:
    resp = urllib.request.urlopen(req, timeout=10)
    size = len(resp.read())
    print(f"  [PASS] agent.ps1: HTTP {resp.status}, {size} bytes")
except Exception as e:
    print(f"  [FAIL] agent.ps1: {e}")

req = urllib.request.Request(f"{BASE}/agent.sh")
try:
    resp = urllib.request.urlopen(req, timeout=10)
    size = len(resp.read())
    print(f"  [PASS] agent.sh: HTTP {resp.status}, {size} bytes")
except Exception as e:
    print(f"  [FAIL] agent.sh: {e}")

# Step 3: Register a device via telemetry
print("\n>> Step 3: Register device via telemetry")
telemetry_body = {
    "system": {
        "hostname": "REAL-SERVER-TEST",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04",
        "ip_addresses": ["192.168.1.200"],
        "cpu_usage": 55.2,
        "memory_usage": 68.5,
        "agent_version": "2.0.0"
    },
    "heartbeat_interval": 30,
    "sequence_number": 1,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "processes": [
        {
            "pid": 9999,
            "name": "sshd",
            "cpu_percent": 0.5,
            "memory_mb": 15.0,
            "path": "/usr/sbin/sshd",
            "command_line": "/usr/sbin/sshd -D",
            "user": "root"
        }
    ],
    "connections": [
        {
            "local_ip": "192.168.1.200",
            "local_port": 22,
            "remote_ip": "10.0.0.5",
            "remote_port": 54321,
            "state": "ESTABLISHED",
            "protocol": "tcp"
        }
    ]
}
telemetry = api("POST", "/api/v1/agent/telemetry", token=token, body=telemetry_body)
if telemetry.get("device_registered"):
    print(f"  [PASS] Device registered: {telemetry['device_id']}")
    print(f"         Events forwarded: {telemetry.get('events_forwarded', 0)}")
    print(f"         Device token: {telemetry.get('device_token', '')[:20]}...")
else:
    print(f"  [INFO] Device may already exist: {telemetry}")

# Step 4: Send attack event - MIMIKATZ
print("\n>> Step 4: Send mimikatz attack event")
attack_body = {
    "source": "agent",
    "hostname": "REAL-SERVER-TEST",
    "event_type": "malicious_process",
    "severity": "critical",
    "message": "Mimikatz credential dumper executed on REAL-SERVER-TEST - possible credential theft",
    "ip_address": "192.168.1.200",
    "source_ip": "192.168.1.200"
}
attack = api("POST", "/api/v1/ingest/event", token=token, body=attack_body)
print(f"  Attack event result: {json.dumps(attack)[:200]}")

# Step 5: Send another attack - port scan
print("\n>> Step 5: Send port scan event")
scan_body = {
    "source": "agent",
    "hostname": "REAL-SERVER-TEST",
    "event_type": "port_scan",
    "severity": "medium",
    "message": "Port scan detected - attacker scanning ports on REAL-SERVER-TEST",
    "ip_address": "192.168.1.200",
    "source_ip": "203.0.113.100"
}
scan = api("POST", "/api/v1/ingest/event", token=token, body=scan_body)
print(f"  Port scan event result: {json.dumps(scan)[:200]}")

# Wait for pipeline to process
print("\n>> Waiting 5 seconds for pipeline processing...")
time.sleep(5)

# Step 6: Check alerts
print("\n>> Step 6: Check alerts in dashboard")
alerts = api("GET", "/api/v1/dashboard/alerts?limit=20", token=token)
if isinstance(alerts, list):
    print(f"  Total alerts: {len(alerts)}")
    
    # Look for our mimikatz and port scan alerts
    mimikatz_alerts = [a for a in alerts if "mimikatz" in str(a.get("description", "") or a.get("rule_name", "")).lower()]
    portscan_alerts = [a for a in alerts if "port scan" in str(a.get("description", "") or a.get("rule_name", "")).lower()]
    
    print(f"  Mimikatz alerts detected: {len(mimikatz_alerts)}")
    print(f"  Port scan alerts detected: {len(portscan_alerts)}")
    
    for a in mimikatz_alerts:
        print(f"  *** FOUND: [{a.get('severity','?')}] {a.get('rule_name','?')}: {a.get('description','')[:100]}")
    for a in portscan_alerts:
        print(f"  *** FOUND: [{a.get('severity','?')}] {a.get('rule_name','?')}: {a.get('description','')[:100]}")
    
    if not mimikatz_alerts and not portscan_alerts:
        print("  *** NO NEW ALERTS CREATED! Events got lost in the pipeline!")
        print("  Last 5 alerts:")
        for a in alerts[-5:]:
            print(f"     [{a.get('severity','?')}] {a.get('rule_name','?')}: {a.get('description','')[:80]}")
else:
    print(f"  [FAIL] Could not fetch alerts: {alerts}")

# Step 7: Check devices
print("\n>> Step 7: Check registered devices")
devices = api("GET", "/api/v1/devices/list", token=token)
if isinstance(devices, list):
    print(f"  Total devices: {len(devices)}")
    for d in devices:
        print(f"     {d.get('hostname','?')} [{d.get('status','?')}] IP: {d.get('ip_address','')}")
else:
    print(f"  Could not fetch devices: {devices}")

# Step 8: Check dashboard summary
print("\n>> Step 8: Dashboard summary")
summary = api("GET", "/api/v1/dashboard/summary", token=token)
if isinstance(summary, dict):
    print(f"  Total alerts: {summary.get('total_alerts', 0)}")
    print(f"  Active threats: {summary.get('active_threats', 0)}")
    print(f"  Blocked IPs: {summary.get('blocked_ips', 0)}")
    print(f"  Devices: {summary.get('total_devices', 0)}")
    print(f"  System health: {summary.get('system_health', 0)}%")
else:
    print(f"  Could not fetch summary: {summary}")

print("\n" + "=" * 60)
print("  TEST COMPLETE")
print("=" * 60)
