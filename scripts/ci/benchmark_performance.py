#!/usr/bin/env python3
"""
Performance benchmark runner for CI.

Runs the PipelineBenchmark and compares P99 latency against a stored baseline.
Exits with code 1 if P99 > 110% of baseline.
"""
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("perf_benchmark")

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO_ROOT / ".github" / "performance" / "baseline.json"
RESULTS_PATH = REPO_ROOT / ".github" / "performance" / "results.json"
EVENT_COUNT = 500
BATCH_SIZE = 50
THRESHOLD_PCT = 10


async def init_tables():
    from sqlalchemy import create_engine
    from cybernova.database.postgres.models import Base

    db_url = os.environ.get("DATABASE_URL", "")
    sync_url = db_url.replace("postgresql+psycopg://", "postgresql+psycopg2://")
    engine = create_engine(sync_url)
    Base.metadata.create_all(engine)
    engine.dispose()
    log.info("Database tables created")


async def main():
    # 1. Create DB tables
    await init_tables()

    # 2. Start leader election (bypasses leader check in pipeline)
    from cybernova.ha.leader import leader_election
    await leader_election.start()

    # 3. Initialize and start the pipeline
    from cybernova.pipeline.unified_pipeline import unified_pipeline
    await unified_pipeline.initialize()
    await unified_pipeline.start()
    log.info("Pipeline initialized and started")

    # 4. Run benchmark
    from cybernova.performance.benchmark import pipeline_benchmark
    log.info("Running benchmark: %d events, batch size %d", EVENT_COUNT, BATCH_SIZE)
    result = await pipeline_benchmark.run(event_count=EVENT_COUNT, batch_size=BATCH_SIZE)

    p99 = result.get("latency_ms", {}).get("p99", 0)
    p95 = result.get("latency_ms", {}).get("p95", 0)
    p50 = result.get("latency_ms", {}).get("p50", 0)
    eps = result.get("eps", 0)
    elapsed = result.get("elapsed_seconds", 0)
    error_rate = result.get("error_rate", 0)

    log.info("Results: EPS=%.1f, elapsed=%.2fs, P50=%.2fms, P95=%.2fms, P99=%.2fms, errors=%.1f%%",
             eps, elapsed, p50, p95, p99, error_rate)

    # 5. Save results for artifact upload
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(result, f, indent=2)

    # 6. Compare against baseline
    if BASELINE_PATH.exists():
        with open(BASELINE_PATH) as f:
            baseline = json.load(f)

        baseline_p99 = baseline.get("latency_ms", {}).get("p99", 0)
        if baseline_p99 <= 0:
            log.info("Baseline P99 is 0 or missing — skipping regression check")
            sys.exit(0)

        threshold = baseline_p99 * (1 + THRESHOLD_PCT / 100)
        log.info("Baseline P99: %.2fms | Current P99: %.2fms | Threshold (110%%): %.2fms",
                 baseline_p99, p99, threshold)

        if p99 > threshold:
            log.error("FAIL: P99 latency %.2fms exceeds 110%% of baseline (%.2fms)", p99, threshold)
            sys.exit(1)

        log.info("PASS: P99 latency within acceptable range")
    else:
        log.warning("No baseline found at %s — first run only, always passes", BASELINE_PATH)

    # 7. Cleanup
    await unified_pipeline.close()
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
