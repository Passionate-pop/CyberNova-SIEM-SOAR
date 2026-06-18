#!/usr/bin/env python3
"""
CyberNova — Real-Time SIEM Pipeline Demo
Demonstrates the complete pipeline from ingestion to SOAR response.
"""
import asyncio
import httpx
import json
import os
import sys
import time
from datetime import datetime

# Windows cp1252 terminal workaround — strip emoji safely
def safe_print(text: str):
    """Print text, replacing unsupported characters on Windows terminals."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8'))

BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"


class CyberNovaRealTimeDemo:
    """Real-time SIEM demonstration."""
    
    def __init__(self):
        self.token = None
        self.tenant_id = "demo-tenant"
        
    async def run(self):
        safe_print("=" * 70)
        safe_print(">> CYBERNOVA REAL-TIME SIEM/SOAR DEMO <<")
        safe_print("=" * 70)
        
        # Step 1: Login
        safe_print("\n>> Step 1: Authentication")
        await self.login()
        
        # Step 2: Check pipeline status
        safe_print("\n>> Step 2: Pipeline Status")
        await self.check_pipeline_status()
        
        # Step 3: Start pipeline if not running
        safe_print("\n>> Step 3: Start Pipeline")
        await self.start_pipeline()
        
        # Step 4: Ingest simulated security events
        safe_print("\n>> Step 4: Ingest Security Events (Real-Time)")
        await self.ingest_events()
        
        # Step 5: Wait for processing
        safe_print("\n>> Step 5: Pipeline Processing...")
        await self.wait_for_processing()
        
        # Step 6: Check results
        safe_print("\n>> Step 6: View Results")
        await self.view_results()
        
        # Step 7: Test SOAR
        safe_print("\n>> Step 7: Test SOAR Response")
        await self.test_soar()
        
        # Step 8: Pipeline metrics
        safe_print("\n>> Step 8: Pipeline Metrics")
        await self.get_metrics()
        
        safe_print("\n" + "=" * 70)
        safe_print("[OK] DEMO COMPLETE")
        safe_print("=" * 70)
    
    async def login(self):
        """Login and get JWT token."""
        # Try to register first (if user doesn't exist)
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{API_BASE}/auth/register",
                    json={
                        "username": "demo",
                        "email": "demo@cybernova.io",
                        "password": "Demo1234!",
                        "tenant_name": self.tenant_id,
                        "roles": ["admin"],
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self.token = data["access_token"]
                    safe_print(f"   [OK] Registered new user")
                elif resp.status_code == 409:
                    safe_print(f"   -> User exists, logging in...")
        except Exception:
            pass
        
        # Login
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_BASE}/auth/login",
                json={"username": "demo", "password": "Demo1234!"},
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data["access_token"]
                safe_print(f"   [OK] Authenticated: {self.token[:50]}...")
            else:
                safe_print(f"   [FAIL] Login failed: {resp.text}")
                self.token = None
    
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}
    
    async def check_pipeline_status(self):
        """Check if pipeline is running."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{API_BASE}/pipeline/status", headers=self.headers())
            if resp.status_code == 200:
                data = resp.json()
                running = data.get("running", False)
                stats = data.get("stats", {})
                safe_print(f"   Pipeline: {'[RUNNING]' if running else '[STOPPED]'}")
                safe_print(f"   Events Ingested: {stats.get('events_ingested', 0)}")
                safe_print(f"   Alerts Created: {stats.get('alerts_created', 0)}")
            else:
                safe_print(f"   [FAIL] Status check failed")
    
    async def start_pipeline(self):
        """Start the real-time pipeline."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{API_BASE}/pipeline/start", headers=self.headers())
            if resp.status_code == 200:
                data = resp.json()
                safe_print(f"   [OK] Pipeline started: {data.get('message', 'OK')}")
            elif resp.status_code == 200 and "already_running" in resp.text:
                safe_print(f"   -> Pipeline already running")
            else:
                safe_print(f"   [FAIL] Start failed: {resp.text}")
    
    async def ingest_events(self):
        """Ingest realistic security events into the pipeline."""
        events = [
            # SSH Brute Force
            {
                "source": "firewall",
                "source_type": "syslog",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "auth_failure",
                        "severity": "high",
                        "src_ip": "203.0.113.50",
                        "dst_ip": "10.0.0.5",
                        "protocol": "TCP",
                        "dst_port": 22,
                        "message": "SSH brute force: 500 failed logins from 203.0.113.50",
                        "user": "root",
                    },
                ],
            },
            # SQL Injection
            {
                "source": "waf",
                "source_type": "api",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "sqli_detected",
                        "severity": "critical",
                        "src_ip": "198.51.100.25",
                        "dst_ip": "10.0.0.20",
                        "protocol": "TCP",
                        "dst_port": 443,
                        "message": "SQL injection detected: ' OR 1=1 -- in login form",
                        "hostname": "web-server-01",
                    },
                ],
            },
            # C2 Communication
            {
                "source": "ids",
                "source_type": "netflow",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "network_connection",
                        "severity": "critical",
                        "src_ip": "10.0.0.15",
                        "dst_ip": "45.33.32.156",
                        "protocol": "TCP",
                        "dst_port": 443,
                        "message": "Suspicious outbound connection to known C2 server",
                    },
                ],
            },
            # Malware Detection
            {
                "source": "edr",
                "source_type": "api",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "malware_detected",
                        "severity": "critical",
                        "src_ip": "10.0.0.42",
                        "dst_ip": "10.0.0.1",
                        "message": "Trojan.Dropper detected and quarantined",
                        "hostname": "workstation-042",
                        "user": "jsmith",
                    },
                ],
            },
            # Data Exfiltration
            {
                "source": "dlp",
                "source_type": "api",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "data_exfiltration",
                        "severity": "critical",
                        "src_ip": "10.0.0.30",
                        "dst_ip": "192.0.2.100",
                        "message": "Large data transfer detected via DNS tunneling",
                        "hostname": "db-server-01",
                    },
                ],
            },
            # Phishing
            {
                "source": "email_gateway",
                "source_type": "api",
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "phishing_detected",
                        "severity": "high",
                        "src_ip": "198.51.100.10",
                        "message": "Phishing email with malicious attachment detected",
                        "user": "bwilson",
                    },
                ],
            },
        ]
        
        total_queued = 0
        async with httpx.AsyncClient(timeout=30) as client:
            for event_batch in events:
                try:
                    resp = await client.post(
                        f"{API_BASE}/pipeline/ingest",
                        json=event_batch,
                        headers=self.headers(),
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        queued = data.get("events_queued", 0)
                        total_queued += queued
                        safe_print(f"   [OK] Ingested {queued} events: {event_batch['source']}")
                    else:
                        safe_print(f"   [FAIL] Ingestion failed: {resp.text}")
                except Exception as e:
                    safe_print(f"   [FAIL] Error: {e}")
        
        safe_print(f"   [STATS] Total events queued: {total_queued}")
    
    async def wait_for_processing(self, seconds: int = 3):
        """Wait for pipeline to process events."""
        for i in range(seconds):
            safe_print(f"   [WAIT] Processing... ({i+1}/{seconds})")
            await asyncio.sleep(1)
    
    async def view_results(self):
        """View alerts and incidents created."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{API_BASE}/dashboard/alerts", headers=self.headers())
            if resp.status_code == 200:
                alerts = resp.json()
                safe_print(f"\n   [STATS] ALERTS ({len(alerts)} total)")
                for alert in alerts[:5]:
                    severity = alert.get("severity", "unknown")
                    level = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}.get(severity, "[INFO]")
                    safe_print(f"      {level} {alert.get('type', 'Unknown')}: {alert.get('source_ip', 'N/A')}")
            else:
                safe_print(f"\n   [STATS] ALERTS: (pipeline may be processing - check /api/v1/pipeline/status)")
            
            resp = await client.get(f"{API_BASE}/dashboard/incidents", headers=self.headers())
            if resp.status_code == 200:
                incidents = resp.json()
                safe_print(f"\n   [STATS] INCIDENTS ({len(incidents)} total)")
                for incident in incidents[:3]:
                    safe_print(f"      [!] {incident.get('title', 'Unknown')}")
    
    async def test_soar(self):
        """Test SOAR automated response."""
        # Get first alert
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{API_BASE}/dashboard/alerts", headers=self.headers())
            if resp.status_code == 200:
                alerts = resp.json()
                if alerts:
                    alert = alerts[0]
                    safe_print(f"\n   >> Testing SOAR on alert: {alert.get('type')}")
                    
                    # Trigger SOAR action
                    resp = await client.post(
                        f"{API_BASE}/dashboard/response/action",
                        json={
                            "action_type": "block_ip",
                            "target": alert.get("source_ip", "0.0.0.0"),
                            "alert_id": alert.get("alert_id"),
                        },
                        headers=self.headers(),
                    )
                    if resp.status_code == 200:
                        action = resp.json()
                        safe_print(f"   [OK] SOAR Action Created: {action.get('action_type')}")
                        safe_print(f"      Status: {action.get('status')}")
                        safe_print(f"      Target: {action.get('target')}")
                    else:
                        safe_print(f"   [FAIL] SOAR action failed: {resp.text}")
    
    async def get_metrics(self):
        """Get pipeline metrics."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{API_BASE}/pipeline/metrics", headers=self.headers())
            if resp.status_code == 200:
                metrics = resp.json()
                safe_print(f"\n   [STATS] PIPELINE METRICS")
                safe_print(f"      Events Ingested: {metrics.get('events_ingested_total', 0)}")
                safe_print(f"      Events Normalized: {metrics.get('events_normalized_total', 0)}")
                safe_print(f"      Events Enriched: {metrics.get('events_enriched_total', 0)}")
                safe_print(f"      Alerts Created: {metrics.get('alerts_created_total', 0)}")
                safe_print(f"      SOAR Actions: {metrics.get('soar_actions_triggered_total', 0)}")
                
                safe_print(f"\n   [STATS] QUEUE DEPTHS")
                safe_print(f"      Detection Queue: {metrics.get('queue_detection_depth', 0)}")
                safe_print(f"      SOAR Queue: {metrics.get('queue_soar_depth', 0)}")


async def main():
    demo = CyberNovaRealTimeDemo()
    await demo.run()


if __name__ == "__main__":
    asyncio.run(main())
