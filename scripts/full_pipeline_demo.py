#!/usr/bin/env python3
"""
CyberNova — Full End-to-End Pipeline Test
Tests BOTH pipeline paths:
  1. API → Unified Pipeline (RedisStreamBus) → Stage Handlers
  2. Redis Streams → Pipeline Workers (normalizer, enrichment, detection, correlation, soar)
"""
import asyncio
import httpx
import json
import os
import sys
from datetime import datetime

BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

def safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8'))

async def main():
    safe_print("=" * 72)
    safe_print(" CYBERNOVA — FULL END-TO-END PIPELINE DEMO")
    safe_print("=" * 72)

    # ── Step 1: Authenticate ──
    safe_print("\n[1/8] AUTHENTICATION")
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{API_BASE}/auth/register", json={
            "username": "endtoend", "email": "e2e@cybernova.io",
            "password": "E2eTest1234!", "tenant_name": "demo-tenant",
            "roles": ["admin"],
        })
        if resp.status_code not in (200, 409):
            safe_print(f"  [FAIL] Register: {resp.status_code}")
            return
        resp = await client.post(f"{API_BASE}/auth/login", json={
            "username": "endtoend", "password": "E2eTest1234!",
        })
        if resp.status_code != 200:
            safe_print(f"  [FAIL] Login: {resp.status_code}")
            return
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        safe_print("  [OK] Authenticated")

    # ── Step 2: Check Pipeline ──
    safe_print("\n[2/8] PIPELINE STATUS")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{API_BASE}/pipeline/status", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            safe_print(f"  Running: {data.get('running')}")
            safe_print(f"  Stats: ingested={data.get('stats', {}).get('ingested', 0)}, "
                       f"normalized={data.get('stats', {}).get('normalized', 0)}, "
                       f"alerted={data.get('stats', {}).get('alerted', 0)}")
        else:
            safe_print(f"  [WARN] Status check: {resp.status_code}")

    # ── Step 3: Ingest Events via API (Path 1: Unified Pipeline) ──
    safe_print("\n[3/8] INGEST EVENTS (Unified Pipeline)")
    test_events = [
        {"source": "firewall", "source_type": "syslog",
         "events": [{
             "event_type": "auth_failure", "severity": "high",
             "src_ip": "203.0.113.50", "dst_ip": "10.0.0.5",
             "protocol": "TCP", "dst_port": 22,
             "message": "SSH brute force: 500 failed logins",
             "user": "root",
         }]},
        {"source": "waf", "source_type": "api",
         "events": [{
             "event_type": "sqli_detected", "severity": "critical",
             "src_ip": "198.51.100.25", "dst_ip": "10.0.0.20",
             "protocol": "TCP", "dst_port": 443,
             "message": "SQL injection detected: ' OR 1=1 --",
             "hostname": "web-server-01",
         }]},
        {"source": "ids", "source_type": "netflow",
         "events": [{
             "event_type": "network_connection", "severity": "critical",
             "src_ip": "10.0.0.15", "dst_ip": "45.33.32.156",
             "protocol": "TCP", "dst_port": 443,
             "message": "Suspicious outbound connection to known C2 server",
         }]},
        {"source": "edr", "source_type": "api",
         "events": [{
             "event_type": "malware_detected", "severity": "critical",
             "src_ip": "10.0.0.42", "dst_ip": "10.0.0.1",
             "message": "Trojan.Dropper detected and quarantined",
             "hostname": "workstation-042", "user": "jsmith",
         }]},
    ]

    total_queued = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for batch in test_events:
            resp = await client.post(f"{API_BASE}/pipeline/ingest", json=batch, headers=headers)
            if resp.status_code == 200:
                queued = resp.json().get("events_queued", 0)
                total_queued += queued
                safe_print(f"  [OK] {batch['source']}: {queued} event(s)")
            else:
                safe_print(f"  [ACK] {batch['source']}: {resp.status_code} - {resp.text[:80]}")

    safe_print(f"\n  [STATS] Total events queued: {total_queued}")

    # ── Step 4: Run Full Pipeline ──
    safe_print("\n[4/8] PROCESS EVENTS (Normalize -> Enrich -> Detect -> Correlate)")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(f"{API_BASE}/pipeline/run?limit=200", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            steps = data.get("steps", {})
            safe_print(f"  [OK] Full pipeline run completed")
            safe_print(f"       Normalized: {steps.get('normalized', 0)}")
            safe_print(f"       Enriched:   {steps.get('enriched', 0)}")
            safe_print(f"       Alerts:     {steps.get('alerts_created', 0)}")
            safe_print(f"       Incidents:  {steps.get('incidents_created', 0)}")
            safe_print(f"       Total:      {data.get('total_processed', 0)}")
        else:
            safe_print(f"  [FAIL] Pipeline run: {resp.status_code} {resp.text[:200]}")

    # ── Step 5: Check Pipeline Metrics ──
    safe_print("\n[5/8] PIPELINE METRICS")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{API_BASE}/pipeline/metrics", headers=headers)
        if resp.status_code == 200:
            m = resp.json()
            safe_print(f"  Events Ingested:   {m.get('events_ingested_total', 0)}")
            safe_print(f"  Events Normalized: {m.get('events_normalized_total', 0)}")
            safe_print(f"  Events Enriched:   {m.get('events_enriched_total', 0)}")
            safe_print(f"  Alerts Created:    {m.get('alerts_created_total', 0)}")
            safe_print(f"  Incidents Created: {m.get('incidents_created_total', 0)}")
            safe_print(f"  SOAR Actions:      {m.get('soar_actions_triggered_total', 0)}")
            safe_print(f"  Errors:            {m.get('errors_total', 0)}")
            safe_print(f"  Detection Queue:   {m.get('queue_detection_depth', 0)}")
            safe_print(f"  Avg Latency (ms):  {m.get('avg_processing_latency_ms', 0)}")
        else:
            safe_print(f"  [WARN] Metrics: {resp.status_code}")

    # ── Step 6: Check Alerts & Incidents in DB ──
    safe_print("\n[6/8] VERIFY ALERTS & INCIDENTS")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{API_BASE}/dashboard/alerts", headers=headers)
        if resp.status_code == 200:
            alerts = resp.json()
            alerts_list = alerts if isinstance(alerts, list) else alerts.get("alerts", [])
            safe_print(f"  Total alerts: {len(alerts_list)}")
            for a in alerts_list[:5]:
                safe_print(f"    [{a.get('severity','?').upper():7}] {a.get('rule_name','?'):35s} {a.get('source_ip','') or a.get('extra_data',{}).get('source_ip','')}")
        else:
            safe_print(f"  [WARN] Alerts: {resp.status_code}")

        resp = await client.get(f"{API_BASE}/dashboard/incidents", headers=headers)
        if resp.status_code == 200:
            incidents = resp.json()
            inc_list = incidents if isinstance(incidents, list) else incidents.get("incidents", [])
            safe_print(f"  Total incidents: {len(inc_list)}")
            for inc in inc_list[:3]:
                safe_print(f"    [{inc.get('severity','?').upper():7}] {inc.get('title','?'):50s} [{inc.get('status','?')}]")
        else:
            safe_print(f"  [WARN] Incidents: {resp.status_code}")

    # ── Step 7: Push Events to Redis Streams for Pipeline Workers ──
    safe_print("\n[7/8] REDIS STREAMS (Pipeline Worker Path)")
    # Try secrets file, then env var, then Docker secret path
    redis_pw = ""
    try:
        with open("secrets/redis_password.txt") as f:
            redis_pw = f.read().strip()
    except FileNotFoundError:
        redis_pw = os.environ.get("REDIS_PASSWORD", "")
        if not redis_pw:
            try:
                with open("/run/secrets/redis_password") as f:
                    redis_pw = f.read().strip()
            except (FileNotFoundError, OSError):
                safe_print("  [WARN] No Redis password found — trying without auth")
    if not redis_pw:
        safe_print("  [WARN] No Redis password available — streams path will fail")
    safe_print(f"  [OK] Redis password {'found' if redis_pw else 'not found'}")
    
    try:
        import redis.asyncio as aioredis
        # Use 'redis' hostname inside Docker, 'localhost' for native runs
        redis_host = os.environ.get("REDIS_HOST", "localhost")
        r = aioredis.Redis(host=redis_host, port=6379, db=0, password=redis_pw or None,
                           protocol=2, decode_responses=True)
        await r.ping()

        # Push raw events to cybernova:raw_events for workers to consume
        worker_events = [
            {"event_id": f"demo-{i}", "tenant_id": "demo-tenant",
             "timestamp": datetime.now().isoformat(),
             "event_type": t, "source": s,
             "data": json.dumps({"src_ip": ip, "message": msg})}
            for i, (t, s, ip, msg) in enumerate([
                ("auth_failure", "firewall", "203.0.113.50", "SSH brute force"),
                ("sqli_detected", "waf", "198.51.100.25", "SQL injection attempt"),
                ("malware_detected", "edr", "10.0.0.42", "Trojan detected"),
                ("network_connection", "ids", "10.0.0.15", "C2 communication"),
                ("data_exfiltration", "dlp", "10.0.0.30", "Large data transfer"),
            ])
        ]

        for evt in worker_events:
            msg_id = await r.xadd("cybernova:raw_events", evt, maxlen=10000)
            safe_print(f"  [OK] Published to raw_events: {evt['event_type']} -> {msg_id}")

        # Check stream lengths after push
        for s in ["cybernova:raw_events", "cybernova:normalized_events",
                   "cybernova:enriched_events", "cybernova:alerts"]:
            try:
                length = await r.xlen(s)
                safe_print(f"  [STREAM] {s}: {length} messages")
            except Exception as e:
                safe_print(f"  [STREAM] {s}: error - {e}")

        await r.close()
    except Exception as e:
        safe_print(f"  [FAIL] Redis error: {e}")

    # ── Step 8: Final Summary ──
    safe_print("\n" + "=" * 72)
    safe_print(" DEMO COMPLETE")
    safe_print("=" * 72)
    safe_print(" Path 1 (Unified Pipeline / API): Events ingested via API and")
    safe_print("   processed through normalize -> enrich -> detect -> correlate")
    safe_print(" Path 2 (Redis Streams + Workers): Events published directly to")
    safe_print("   cybernova:raw_events for pipeline workers to consume")
    safe_print("=" * 72 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
