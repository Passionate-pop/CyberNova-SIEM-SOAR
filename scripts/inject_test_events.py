"""
CyberNova — Test Event Injector
Injects simulated security events to test the detection pipeline.
Run this script AFTER starting the backend (uvicorn).

Usage:
    python scripts/inject_test_events.py
"""
import asyncio
import httpx
import json
import os
from datetime import datetime, timezone

# Read from secrets file as primary source, fall back to env vars
_SECRETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secrets")
_ADMIN_PW_FILE = os.path.join(_SECRETS_DIR, "admin_password.txt")
_FALLBACK_PW = ""
try:
    with open(_ADMIN_PW_FILE) as f:
        _FALLBACK_PW = f.read().strip()
except (FileNotFoundError, IOError):
    _FALLBACK_PW = os.environ.get("ADMIN_PASSWORD", "admin123")

BASE_URL = os.environ.get("CYBERNOVA_BASE", "http://localhost:8000")
ADMIN_USER = os.environ.get("CYBERNOVA_USER", "admin")
ADMIN_PASS = os.environ.get("CYBERNOVA_PASSWORD") or os.environ.get("ADMIN_PASSWORD", _FALLBACK_PW)

# Simulated security events (NOT real harmful data)
TEST_EVENTS = [
    # Malware Detection
    {
        "event_type": "malware_detected",
        "severity": "critical",
        "source_ip": "192.168.1.100",
        "dest_ip": "8.8.8.8",
        "protocol": "TCP",
        "dest_port": 443,
        "hostname": "WORKSTATION-042",
        "user": "jsmith",
        "message": "Trojan.Dropper detected in C:\\Users\\jsmith\\Downloads\\invoice.pdf.exe",
    },
    # Brute Force SSH
    {
        "event_type": "authentication_failure",
        "severity": "high",
        "source_ip": "203.0.113.50",
        "dest_ip": "192.168.1.10",
        "protocol": "TCP",
        "dest_port": 22,
        "hostname": "SRV-APP-01",
        "user": "admin",
        "message": "SSH brute force: 50 failed attempts from 203.0.113.50",
    },
    # SQL Injection
    {
        "event_type": "sql_injection",
        "severity": "high",
        "source_ip": "198.51.100.25",
        "dest_ip": "192.168.1.20",
        "protocol": "TCP",
        "dest_port": 443,
        "hostname": "SRV-WEB-01",
        "user": "anonymous",
        "message": "SQL injection attempt detected: ' OR 1=1 -- in login form",
    },
    # Data Exfiltration
    {
        "event_type": "data_transfer",
        "severity": "critical",
        "source_ip": "192.168.1.50",
        "dest_ip": "45.33.32.156",
        "protocol": "DNS",
        "dest_port": 53,
        "hostname": "SRV-DB-01",
        "user": "db_service",
        "message": "Large DNS queries with encoded data payload detected - potential DNS tunneling",
    },
    # C2 Communication
    {
        "event_type": "c2_communication",
        "severity": "critical",
        "source_ip": "192.168.1.100",
        "dest_ip": "185.220.101.42",
        "protocol": "TCP",
        "dest_port": 443,
        "hostname": "WORKSTATION-042",
        "user": "SYSTEM",
        "message": "Outbound connection to known Tor exit node - potential C2 communication",
    },
    # Port Scan
    {
        "event_type": "port_scan",
        "severity": "medium",
        "source_ip": "198.51.100.100",
        "dest_ip": "192.168.1.0/24",
        "protocol": "TCP",
        "dest_port": 0,
        "hostname": "unknown",
        "user": "",
        "message": "Sequential port scan detected: ports 22,80,443,3306,5432 from 198.51.100.100",
    },
    # Privilege Escalation
    {
        "event_type": "privilege_change",
        "severity": "high",
        "source_ip": "192.168.1.75",
        "dest_ip": "",
        "protocol": "",
        "dest_port": 0,
        "hostname": "SRV-AUTH-01",
        "user": "attacker",
        "message": "Unauthorized privilege escalation: standard user attempting sudo exploit",
    },
    # Phishing
    {
        "event_type": "phishing_detected",
        "severity": "medium",
        "source_ip": "203.0.113.200",
        "dest_ip": "",
        "protocol": "SMTP",
        "dest_port": 25,
        "hostname": "MAIL-GW-01",
        "user": "victim@company.com",
        "message": "Phishing email with malicious link detected: fake-bank-login.com",
    },
    # Ransomware Signature
    {
        "event_type": "ransomware_signature",
        "severity": "critical",
        "source_ip": "192.168.1.150",
        "dest_ip": "",
        "protocol": "",
        "dest_port": 0,
        "hostname": "FILESERVER-01",
        "user": "backup_service",
        "message": "Known ransomware signature (WannaCry) detected in backup directory",
    },
    # Lateral Movement
    {
        "event_type": "lateral_movement",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "dest_ip": "192.168.1.105",
        "protocol": "SMB",
        "dest_port": 445,
        "hostname": "WORKSTATION-042",
        "user": "jsmith",
        "message": "Pass-the-hash attack detected: lateral movement from WKS-042 to WKS-043",
    },
    # Anomalous Login
    {
        "event_type": "anomalous_login",
        "severity": "low",
        "source_ip": "73.156.177.45",
        "dest_ip": "192.168.1.10",
        "protocol": "RDP",
        "dest_port": 3389,
        "hostname": "SRV-RDP-01",
        "user": "cfo",
        "message": "Login from unusual location detected for CFO account outside business hours",
    },
    # DNS Tunneling
    {
        "event_type": "dns_tunneling",
        "severity": "high",
        "source_ip": "192.168.1.50",
        "dest_ip": "8.8.4.4",
        "protocol": "DNS",
        "dest_port": 53,
        "hostname": "SRV-DB-01",
        "user": "app_service",
        "message": "Abnormal DNS query volume: 5000 queries/minute from database server",
    },
]


async def get_auth_token():
    """Login and get JWT token."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Try to login (default credentials or register)
        try:
            response = await client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS}
            )
            if response.status_code == 200:
                data = response.json()
                print(f"[OK] Logged in as admin")
                return data.get("access_token")
        except Exception as e:
            print(f"Login failed: {e}")
        
        # Try to register
        try:
            response = await client.post(
                f"{BASE_URL}/api/v1/auth/register",
                json={
                    "username": ADMIN_USER,
                    "email": f"{ADMIN_USER}@cybernova.local",
                    "password": ADMIN_PASS
                }
            )
            if response.status_code in [200, 201]:
                data = response.json()
                print(f"[OK] Registered new user: admin")
                return data.get("access_token")
        except Exception as e:
            print(f"Registration failed: {e}")
    
    return None


async def ingest_events(token: str):
    """Ingest test events into the pipeline."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        # Use the correct ingestion endpoint
        ingest_url = f"{BASE_URL}/api/v1/ingest/"
        response = await client.post(
            ingest_url,
            headers=headers,
            json={
                "source": "test_injector",
                "source_type": "api",
                "events": TEST_EVENTS
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n[OK] Ingested {data.get('events_queued', 0)} events")
            return True
        else:
            print(f"[X] Ingest failed: {response.status_code} - {response.text}")
            return False


async def run_pipeline(token: str):
    """Run the detection pipeline."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{BASE_URL}/api/v1/dashboard/pipeline/run",
            headers=headers,
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] Pipeline completed:")
            print(f"  - Normalized: {data.get('normalized_count', 0)}")
            print(f"  - Enriched: {data.get('enriched_count', 0)}")
            print(f"  - Alerts created: {data.get('alerts_created', 0)}")
            return True
        else:
            print(f"[X] Pipeline run failed: {response.status_code} - {response.text}")
            return False


async def check_alerts(token: str):
    """Check generated alerts."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/dashboard/alerts",
            headers=headers,
        )
        
        if response.status_code == 200:
            alerts = response.json()
            print(f"\n--- DETECTED ALERTS ({len(alerts)} total) ---")
            for alert in alerts[:10]:  # Show first 10
                severity = alert.get('severity', 'unknown').upper()
                severity_indicator = {
                    'CRITICAL': '[!]',
                    'HIGH': '[#]',
                    'MEDIUM': '[$]',
                    'LOW': '[i]'
                }.get(severity, '[?]')
                print(f"{severity_indicator} [{severity}] {alert.get('type', 'Unknown')}")
                print(f"   {alert.get('description', '')[:80]}...")
                print()
            if len(alerts) > 10:
                print(f"... and {len(alerts) - 10} more alerts")
            return alerts
        else:
            print(f"[X] Failed to fetch alerts: {response.status_code}")
            return []


async def check_incidents(token: str):
    """Check created incidents."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/dashboard/incidents",
            headers=headers,
        )
        
        if response.status_code == 200:
            incidents = response.json()
            print(f"\n--- CREATED INCIDENTS ({len(incidents)} total) ---")
            for incident in incidents:
                severity = incident.get('severity', 'unknown').upper()
                print(f"[!] [{severity}] {incident.get('title', 'Untitled')}")
            return incidents
        else:
            print(f"[X] Failed to fetch incidents: {response.status_code}")
            return []


async def check_summary(token: str):
    """Check dashboard summary."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/dashboard/summary",
            headers=headers,
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n--- DASHBOARD SUMMARY ---")
            print(f"Total Alerts: {data.get('total_alerts', 0)}")
            print(f"Active Incidents: {data.get('active_incidents', 0)}")
            print(f"Risk Score: {data.get('risk_score', 0)}/100")
            print(f"System Health: {data.get('system_health', 0)}%")
            return data
        else:
            print(f"[X] Failed to fetch summary: {response.status_code}")
            return None


async def main():
    print("=" * 60)
    print("[*] CyberNova - Real Security Event Injector")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print()
    
    # Step 1: Get authentication
    print("[1/4] Authenticating...")
    token = await get_auth_token()
    if not token:
        print("[X] Authentication failed. Is the backend running?")
        print("  Run: uvicorn cybernova.main:app --reload")
        return
    
    # Step 2: Ingest test events (real security events)
    print("\n[2/4] Injecting security events into pipeline...")
    await ingest_events(token)
    
    # Step 3: Run the full pipeline (normalize → enrich → detect → correlate)
    print("\n[3/4] Running detection pipeline...")
    await run_pipeline(token)
    
    # Step 4: Check results
    print("\n[4/4] Checking detection results...")
    await check_alerts(token)
    await check_incidents(token)
    
    # Final summary
    print("\n" + "=" * 60)
    print("DASHBOARD SUMMARY")
    print("=" * 60)
    await check_summary(token)
    
    print("\n[OK] Test complete! Check the frontend at http://localhost:5173")
    print("\nLogin credentials:")
    print(f"  Username: {ADMIN_USER}")
    print("  Password: admin123")


if __name__ == "__main__":
    asyncio.run(main())
