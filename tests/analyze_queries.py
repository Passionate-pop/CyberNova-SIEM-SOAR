#!/usr/bin/env python3
"""
Slow Query Analysis — CyberNOVA Database Optimization
=====================================================
Connects to the target database and runs EXPLAIN ANALYZE on the most common
tenant-scoped query patterns for alerts, normalized_events, and raw_events.

Usage:
    python tests/analyze_queries.py --dsn postgresql://user:pass@host:5432/cybernova

Run BEFORE and AFTER applying migration 0005 to compare index performance.
Outputs include: query plan, execution time, rows scanned, and index usage.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

QUERIES = [
    # ── alerts ──────────────────────────────────────────────────────────
    {
        "name": "alerts: tenant + last 24h + severity",
        "sql": """
            EXPLAIN ANALYZE
            SELECT id, severity, risk_score, created_at
            FROM alerts
            WHERE tenant_id = 'default'
              AND created_at >= NOW() - INTERVAL '24 hours'
              AND severity = 'critical'
            ORDER BY created_at DESC
            LIMIT 100;
        """,
    },
    {
        "name": "alerts: tenant + date range",
        "sql": """
            EXPLAIN ANALYZE
            SELECT id, severity, risk_score, status
            FROM alerts
            WHERE tenant_id = 'default'
              AND created_at BETWEEN NOW() - INTERVAL '7 days' AND NOW()
            ORDER BY created_at DESC;
        """,
    },
    {
        "name": "alerts: tenant + severity count",
        "sql": """
            EXPLAIN ANALYZE
            SELECT severity, COUNT(*) as cnt
            FROM alerts
            WHERE tenant_id = 'default'
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY severity
            ORDER BY cnt DESC;
        """,
    },
    # ── normalized_events ──────────────────────────────────────────────
    {
        "name": "normalized_events: tenant + time range",
        "sql": """
            EXPLAIN ANALYZE
            SELECT id, event_type, severity, source_ip
            FROM normalized_events
            WHERE tenant_id = 'default'
              AND normalized_at BETWEEN NOW() - INTERVAL '1 hour' AND NOW()
            ORDER BY normalized_at DESC
            LIMIT 200;
        """,
    },
    {
        "name": "normalized_events: tenant + type + time",
        "sql": """
            EXPLAIN ANALYZE
            SELECT id, severity, source_ip
            FROM normalized_events
            WHERE tenant_id = 'default'
              AND event_type = 'suricata_alert'
              AND normalized_at >= NOW() - INTERVAL '24 hours'
            ORDER BY normalized_at DESC
            LIMIT 100;
        """,
    },
    {
        "name": "normalized_events: tenant daily volume",
        "sql": """
            EXPLAIN ANALYZE
            SELECT DATE(normalized_at) as day, COUNT(*) as cnt
            FROM normalized_events
            WHERE tenant_id = 'default'
              AND normalized_at >= NOW() - INTERVAL '7 days'
            GROUP BY day
            ORDER BY day;
        """,
    },
    # ── raw_events ─────────────────────────────────────────────────────
    {
        "name": "raw_events: tenant + received time range",
        "sql": """
            EXPLAIN ANALYZE
            SELECT id, source, source_type
            FROM raw_events
            WHERE tenant_id = 'default'
              AND received_at BETWEEN NOW() - INTERVAL '1 hour' AND NOW()
            ORDER BY received_at DESC
            LIMIT 200;
        """,
    },
    {
        "name": "raw_events: tenant daily ingestion count",
        "sql": """
            EXPLAIN ANALYZE
            SELECT DATE(received_at) as day, COUNT(*) as cnt
            FROM raw_events
            WHERE tenant_id = 'default'
              AND received_at >= NOW() - INTERVAL '7 days'
            GROUP BY day
            ORDER BY day;
        """,
    },
]


def colorize_plan(plan: str) -> str:
    """Simple highlighting for query plan output."""
    lines = plan.split("\n")
    highlighted = []
    for line in lines:
        lower = line.lower()
        if "seq scan" in lower or "sequential scan" in lower:
            line = f"\033[91m{line}\033[0m"  # red
        elif "index scan" in lower or "index only scan" in lower:
            line = f"\033[92m{line}\033[0m"  # green
        elif "bitmap" in lower:
            line = f"\033[93m{line}\033[0m"  # yellow
        elif "rows=" in lower:
            parts = line.split("rows=")
            if len(parts) > 1:
                rows_val = parts[1].split()[0].strip()
                line = f"\033[94m{line}\033[0m"  # blue
        highlighted.append(line)
    return "\n".join(highlighted)


async def run_query(dsn: str, query: Dict[str, Any]) -> Dict[str, Any]:
    """Execute EXPLAIN ANALYZE and return timing + plan."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine(dsn.replace("postgresql://", "postgresql+psycopg://"))
        async with engine.connect() as conn:
            start = time.perf_counter()
            result = await conn.exec_driver_sql(query["sql"])
            rows = result.fetchall()
            elapsed = (time.perf_counter() - start) * 1000
            plan = "\n".join(r[0] for r in rows)
    except Exception as e:
        return {"name": query["name"], "error": str(e), "elapsed_ms": 0, "plan": ""}

    timing_ms = None
    for line in plan.split("\n"):
        if "Execution Time" in line:
            import re
            m = re.search(r"([\d.]+)\s*ms", line)
            if m:
                timing_ms = float(m.group(1))

    scan_type = "unknown"
    for line in plan.split("\n"):
        lower = line.lower()
        if "index scan" in lower:
            scan_type = "index_scan"
        elif "index only scan" in lower:
            scan_type = "index_only_scan"
        elif "seq scan" in lower:
            scan_type = "seq_scan"
        elif "bitmap" in lower:
            scan_type = "bitmap_scan"

    rows_examined = 0
    for line in plan.split("\n"):
        if "rows=" in line.lower():
            parts = line.split("rows=")
            try:
                rows_examined = int(parts[1].split()[0].strip().replace(",", ""))
            except (ValueError, IndexError):
                pass

    return {
        "name": query["name"],
        "elapsed_ms": round(elapsed, 2),
        "timing_ms": timing_ms,
        "scan_type": scan_type,
        "rows_examined": rows_examined,
        "plan": plan,
    }


def print_report(results: List[Dict[str, Any]]) -> None:
    print("=" * 80)
    print("  CyberNOVA — Slow Query Analysis Report")
    print("=" * 80)
    print()

    total_time = 0
    for r in results:
        total_time += r["elapsed_ms"]
        status = "OK" if "error" not in r else "ERROR"
        scan_icon = {"index_scan": "✓", "index_only_scan": "✓", "seq_scan": "✗ SEQ SCAN", "bitmap_scan": "~"}.get(
            r.get("scan_type", ""), "?"
        )
        print(f"  [{status}] {r['name']}")
        print(f"         Time: {r['elapsed_ms']:>8.2f} ms  "
              f"(EXPLAIN: {r.get('timing_ms', 'N/A')} ms)  "
              f"Scan: {scan_icon}  "
              f"Rows: {r.get('rows_examined', '?')}")
        if r.get("error"):
            print(f"         ERROR: {r['error']}")
        print()

    print("-" * 80)
    print(f"  Total execution time: {total_time:.2f} ms")
    print()

    print("  Detailed plans:")
    for r in results:
        if r.get("plan"):
            print(f"  --- {r['name']} ---")
            for line in r["plan"].split("\n"):
                print(f"  {line}")
            print()


async def main():
    parser = argparse.ArgumentParser(description="Analyze pipeline query performance")
    parser.add_argument("--dsn", required=True, help="PostgreSQL DSN (postgresql://user:pass@host/db)")
    args = parser.parse_args()

    print("\nAnalyzing queries...\n")
    results = []
    for query in QUERIES:
        r = await run_query(args.dsn, query)
        results.append(r)
        print(f"  {r['name']}: {r['elapsed_ms']:>8.2f} ms  |  {r.get('scan_type', '?')}")

    print()
    print_report(results)


if __name__ == "__main__":
    asyncio.run(main())
