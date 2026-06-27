"""CyberNova — Attack simulation & verification test"""
import asyncio
import httpx
import json
import time

BASE = "http://localhost:8000"

TEST_EVENTS = [
    {"event_type": "malware_detected", "severity": "critical", "source_ip": "192.168.1.100", "dest_ip": "8.8.8.8", "protocol": "TCP", "dest_port": 443, "hostname": "WORKSTATION-042", "user": "jsmith", "message": "Trojan.Dropper detected in user downloads"},
    {"event_type": "authentication_failure", "severity": "high", "source_ip": "203.0.113.50", "dest_ip": "192.168.1.10", "protocol": "TCP", "dest_port": 22, "hostname": "SRV-APP-01", "user": "admin", "message": "SSH brute force: 50 failed attempts"},
    {"event_type": "sql_injection", "severity": "high", "source_ip": "198.51.100.25", "dest_ip": "192.168.1.20", "protocol": "TCP", "dest_port": 443, "hostname": "SRV-WEB-01", "user": "anonymous", "message": "SQL injection attempt detected in login form"},
    {"event_type": "c2_communication", "severity": "critical", "source_ip": "192.168.1.100", "dest_ip": "185.220.101.42", "protocol": "TCP", "dest_port": 443, "hostname": "WORKSTATION-042", "user": "SYSTEM", "message": "Outbound connection to known Tor exit node"},
    {"event_type": "ransomware_signature", "severity": "critical", "source_ip": "192.168.1.150", "dest_ip": "", "protocol": "", "dest_port": 0, "hostname": "FILESERVER-01", "user": "backup_service", "message": "Known ransomware signature (WannaCry) detected"},
    {"event_type": "lateral_movement", "severity": "high", "source_ip": "192.168.1.100", "dest_ip": "192.168.1.105", "protocol": "SMB", "dest_port": 445, "hostname": "WORKSTATION-042", "user": "jsmith", "message": "Pass-the-hash attack detected: lateral movement"},
    {"event_type": "port_scan", "severity": "medium", "source_ip": "198.51.100.100", "dest_ip": "192.168.1.0/24", "protocol": "TCP", "dest_port": 0, "hostname": "unknown", "user": "", "message": "Sequential port scan: ports 22,80,443,3306,5432"},
    {"event_type": "data_transfer", "severity": "critical", "source_ip": "192.168.1.50", "dest_ip": "45.33.32.156", "protocol": "DNS", "dest_port": 53, "hostname": "SRV-DB-01", "user": "db_service", "message": "Large DNS queries - potential DNS tunneling"},
    {"event_type": "phishing_detected", "severity": "medium", "source_ip": "203.0.113.200", "dest_ip": "", "protocol": "SMTP", "dest_port": 25, "hostname": "MAIL-GW-01", "user": "victim@company.com", "message": "Phishing email with malicious link detected"},
    {"event_type": "privilege_change", "severity": "high", "source_ip": "192.168.1.75", "dest_ip": "", "protocol": "", "dest_port": 0, "hostname": "SRV-AUTH-01", "user": "attacker", "message": "Unauthorized privilege escalation attempt"},
    {"event_type": "anomalous_login", "severity": "low", "source_ip": "73.156.177.45", "dest_ip": "192.168.1.10", "protocol": "RDP", "dest_port": 3389, "hostname": "SRV-RDP-01", "user": "cfo", "message": "Login from unusual location for CFO account"},
    {"event_type": "dns_tunneling", "severity": "high", "source_ip": "192.168.1.50", "dest_ip": "8.8.4.4", "protocol": "DNS", "dest_port": 53, "hostname": "SRV-DB-01", "user": "app_service", "message": "Abnormal DNS query volume: 5000 queries/minute"},
]

async def main():
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Register fresh user
        uname = f"attack_{int(time.time())}"
        r = await client.post(f"{BASE}/api/v1/auth/register", json={
            "username": uname, "email": f"{uname}@t.io",
            "password": "TestPass123!", "roles": ["admin"]
        })
        token = ""
        if r.status_code == 200:
            token = r.json().get("access_token") or r.json().get("token", "")
        if not token:
            r = await client.post(f"{BASE}/api/v1/auth/login", json={"username": uname, "password": "TestPass123!"})
            if r.status_code == 200:
                token = r.json().get("access_token") or r.json().get("token", "")

        if not token:
            print("FAIL: No token - aborting")
            return 1

        headers = {"Authorization": f"Bearer {token}"}
        print(f"User: {uname}")
        print(f"Token: {token[:20]}...")
        print()

        # Step 1: Inject events
        print("=== 1. INJECT 12 SECURITY EVENTS ===")
        r = await client.post(f"{BASE}/api/v1/ingest/", headers=headers, json={
            "source": "test_injector", "source_type": "api", "events": TEST_EVENTS
        })
        print(f"   Ingest: {r.status_code}", end="")
        if r.status_code == 200:
            d = r.json()
            queued = d.get("events_queued", d.get("queued", "?"))
            print(f" - Events queued: {queued}")
        else:
            print(f" - {r.text[:100]}")
            # Try alternate ingest endpoint
            print("   Trying /api/v1/events/ingest...")
            r = await client.post(f"{BASE}/api/v1/events/ingest", headers=headers, json={
                "source": "test_injector", "source_type": "api", "events": TEST_EVENTS
            })
            print(f"   Ingest (alt): {r.status_code}", end="")
            if r.status_code == 200:
                print(f" - OK")
            else:
                print(f" - {r.text[:100]}")

        # Step 2: Run pipeline
        print()
        print("=== 2. RUN DETECTION PIPELINE ===")
        r = await client.post(f"{BASE}/api/v1/dashboard/pipeline/run", headers=headers)
        print(f"   Pipeline: {r.status_code}")
        if r.status_code == 200:
            d = r.json()
            print(f"   Normalized: {d.get('normalized_count', 0)}")
            print(f"   Enriched:   {d.get('enriched_count', 0)}")
            print(f"   Alerts:     {d.get('alerts_created', 0)}")
        else:
            print(f"   {r.text[:200]}")

        # Step 3: Dashboard summary
        print()
        print("=== 3. DASHBOARD SUMMARY ===")
        r = await client.get(f"{BASE}/api/v1/dashboard/summary", headers=headers)
        print(f"   Dashboard: {r.status_code}")
        if r.status_code == 200:
            d = r.json()
            for k, v in d.items():
                print(f"   {k}: {v}")
        else:
            print(f"   {r.text[:200]}")

        # Step 4: Check alerts
        print()
        print("=== 4. ALERTS ===")
        r = await client.get(f"{BASE}/api/v1/alerts", headers=headers)
        print(f"   Alerts: {r.status_code}")
        if r.status_code == 200:
            alerts = r.json()
            if isinstance(alerts, list):
                print(f"   Total: {len(alerts)}")
                for a in alerts[:5]:
                    print(f"   [{a.get('severity','?')}] {a.get('event_type','?')} - {a.get('message','')[:60]}")
            elif isinstance(alerts, dict):
                items = alerts.get("items", alerts.get("alerts", []))
                print(f"   Total: {len(items)}")
                for a in items[:5]:
                    print(f"   [{a.get('severity','?')}] {a.get('event_type','?')}")

        # Step 5: Pipeline stats
        print()
        print("=== 5. PIPELINE STATS ===")
        r = await client.get(f"{BASE}/api/v1/pipeline/stats", headers=headers)
        print(f"   Pipeline: {r.status_code}")
        if r.status_code == 200:
            print(f"   {json.dumps(r.json(), indent=2)[:200]}")

        print()
        print("=== COMPLETE ===")
        return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))
