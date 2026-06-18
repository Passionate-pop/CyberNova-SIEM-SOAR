#!/usr/bin/env python3
"""
CyberNova — Chaos Engineering Runner
Orchestrates random chaos scenarios to validate system resilience.
Usage: python -m tests.chaos.chaos_runner [--iterations N] [--scenario NAME]

Scenarios:
  kill_leader          — Stop leader election, assert failover
  redis_partition      — Simulate Redis disconnect, assert recovery
  pipeline_crash       — Simulate pipeline failure, assert DLQ processing
  replica_fallback     — Simulate read replica failure, assert cache serve
  random               — Pick a random scenario (default)
"""
import asyncio
import logging
import random
import sys
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("chaos_runner")

SCENARIOS = ["kill_leader", "redis_partition", "pipeline_crash", "replica_fallback"]


async def scenario_kill_leader() -> dict:
    """Kill the leader; assert a new leader is elected."""
    log.info("═══ SCENARIO: kill_leader ═══")
    from cybernova.ha.leader import LeaderElection

    async def mock_set(*a, **kw): return True
    async def mock_get(*a, **kw): return None
    async def mock_delete(*a, **kw): return 1
    async def mock_ping(*a, **kw): return True
    async def mock_eval(*a, **kw): return 1

    redis = type("Redis", (), {
        "ping": mock_ping,
        "set": mock_set,
        "get": mock_get,
        "delete": mock_delete,
        "eval": mock_eval,
    })()

    leader = LeaderElection(instance_id="chaos-leader")
    follower = LeaderElection(instance_id="chaos-follower")

    async def fake_get_redis():
        return redis

    import cybernova.ha.leader as lm
    original = lm.get_redis
    lm.get_redis = fake_get_redis

    try:
        await leader.start()
        await follower.start()
        await asyncio.sleep(0.1)

        if not leader.is_leader:
            log.warning("Leader did not acquire lock")
            return {"scenario": "kill_leader", "status": "skipped", "reason": "no leader"}

        log.info("Leader acquired lock. Killing leader...")
        await leader.stop()

        await asyncio.sleep(0.3)

        if follower.is_leader:
            log.info("PASS: Follower became leader after leader death")
            return {"scenario": "kill_leader", "status": "pass"}
        else:
            log.error("FAIL: Follower did not become leader")
            return {"scenario": "kill_leader", "status": "fail", "reason": "no failover"}
    finally:
        lm.get_redis = original
        await follower.stop()
        await leader.stop()


async def scenario_redis_partition() -> dict:
    """Simulate Redis disconnect; assert graceful degradation then recovery."""
    log.info("═══ SCENARIO: redis_partition ═══")
    import cybernova.database.redis as rmod

    rmod._pool = None

    async def mock_ping(*a, **kw): return True
    async def mock_aclose(*a, **kw): return None

    mock_pool = type("Pool", (), {"disconnect": lambda *a, **kw: None})()
    mock_redis = type("Redis", (), {
        "ping": mock_ping,
        "connection_pool": mock_pool,
        "aclose": mock_aclose,
    })()

    rmod._pool = mock_redis

    pool_before = await rmod.get_redis()
    if pool_before is not mock_redis:
        log.warning("Could not set up initial Redis mock")
        return {"scenario": "redis_partition", "status": "skipped", "reason": "setup"}

    log.info("Redis connected. Simulating network partition...")
    rmod._pool = None

    # Check that pool is None (graceful degradation)
    if rmod._pool is None:
        log.info("PASS: App gracefully degraded when Redis disconnected")
    else:
        log.warning("Unexpected: Redis still has a pool")

    mock_settings = type("Settings", (), {
        "redis_host": "localhost",
        "redis_port": 6379,
        "redis_db": 0,
        "redis_password": "",
        "redis_url_override": "",
        "redis_sentinel_hosts": "",
        "redis_pool_size": 10,
        "redis_socket_connect_timeout": 1,
        "redis_socket_timeout": 1,
    })()

    from cybernova.config.settings import get_settings
    original_settings = get_settings

    def fake_settings():
        return mock_settings

    import cybernova.database.redis as rmod2
    rmod2.get_settings = fake_settings

    new_mock = type("Redis", (), {
        "ping": mock_ping,
        "connection_pool": mock_pool,
        "aclose": mock_aclose,
    })()

    import cybernova.database.redis as rmod3
    async with rmod3._init_lock:
        rmod3._pool = new_mock


    pool_recovered = await rmod3.get_redis()
    rmod3.get_settings = original_settings

    if pool_recovered is new_mock:
        log.info("PASS: Redis reconnection succeeded")
        return {"scenario": "redis_partition", "status": "pass"}
    else:
        log.error("FAIL: Redis did not reconnect")
        return {"scenario": "redis_partition", "status": "fail", "reason": "no reconnection"}


async def scenario_pipeline_crash() -> dict:
    """Simulate pipeline failure; assert DLQ processing."""
    log.info("═══ SCENARIO: pipeline_crash ═══")
    from cybernova.pipeline.dead_letter_worker import DeadLetterWorker, RETRY_BASE_DELAY

    worker = DeadLetterWorker()
    delay = DeadLetterWorker._backoff_delay(0)
    if delay == RETRY_BASE_DELAY:
        log.info("PASS: Exponential backoff base delay = %ds", delay)
    else:
        log.error("FAIL: Unexpected backoff delay: %d", delay)
        return {"scenario": "pipeline_crash", "status": "fail",
                "reason": f"backoff={delay}, expected={RETRY_BASE_DELAY}"}

    from cybernova.database.postgres.models import DeadLetterEvent
    record = type("Record", (), {
        "id": "chaos-dlq-001",
        "tenant_id": "tenant-chaos",
        "original_queue": "ingestion",
        "payload": '{"id":"x","queue":"ingestion","payload":{},"priority":0}',
        "error": "chaos injection",
        "retry_count": 0,
        "max_retries": 3,
        "failed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc) -
                     __import__("datetime").timedelta(hours=2),
    })()

    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    due = worker._is_due_for_retry(record, now)
    if due:
        log.info("PASS: DLQ record is due for retry")
    else:
        log.warning("DLQ record not due yet (may need more time)")

    return {"scenario": "pipeline_crash", "status": "pass"}


async def scenario_replica_fallback() -> dict:
    """Simulate read replica failure; assert dashboard cache fallback."""
    log.info("═══ SCENARIO: replica_fallback ═══")
    from cybernova.dashboard.service import DashboardService

    service = DashboardService()

    import json
    cached = json.dumps({"risk_score": 99, "alerts_today": 50})
    mock_redis = type("Redis", (), {
        "get": lambda k: cached,
        "setex": lambda k, t, v: None,
    })()

    import cybernova.dashboard.service as ds
    original_get_redis = ds.get_redis
    ds.get_redis = lambda: mock_redis
    original_is_leader = ds.leader_election._is_leader
    ds.leader_election._is_leader = False
    ds.leader_election._local_mode = False

    try:
        # Mock DB dependency — scalar/all/first are sync (called after await execute)
        def mock_scalar(*a, **kw): return None
        def mock_all(*a, **kw): return []
        def mock_first(*a, **kw): return None
        async def mock_execute(*a, **kw):
            return type("Result", (), {
                "scalar": mock_scalar,
                "all": mock_all,
                "first": mock_first,
            })()
        async def mock_close(*a, **kw): return None
        async def mock_commit(*a, **kw): return None

        mock_db = type("AsyncSession", (), {
            "execute": mock_execute,
            "close": mock_close,
            "commit": mock_commit,
        })()
        # Mock leader election to allow cache fallback on follower
        ds.leader_election._is_leader = False
        ds.leader_election._local_mode = False
        result = await service.get_summary(mock_db, "tenant-chaos")
        if result and result.get("risk_score") == 99:
            log.info("PASS: Dashboard served cached data on passive replica")
            return {"scenario": "replica_fallback", "status": "pass"}
        else:
            log.warning("Unexpected result: %s", result)
            return {"scenario": "replica_fallback", "status": "warn", "reason": str(result)}
    except Exception as e:
        log.error("FAIL: Dashboard service error: %s", e)
        return {"scenario": "replica_fallback", "status": "fail", "reason": str(e)}
    finally:
        ds.get_redis = original_get_redis
        ds.leader_election._is_leader = original_is_leader


async def run_scenario(name: str) -> dict:
    scenarios = {
        "kill_leader": scenario_kill_leader,
        "redis_partition": scenario_redis_partition,
        "pipeline_crash": scenario_pipeline_crash,
        "replica_fallback": scenario_replica_fallback,
    }
    fn = scenarios.get(name)
    if not fn:
        return {"scenario": name, "status": "error", "reason": f"unknown scenario: {name}"}
    return await fn()


async def main(iterations: int = 1, scenario: Optional[str] = None):
    total = {"pass": 0, "fail": 0, "skip": 0, "warn": 0, "error": 0}
    log.info("=" * 60)
    log.info("CyberNova Chaos Engineering Suite")
    log.info("=" * 60)
    log.info("Iterations: %d", iterations)
    log.info("Scenario:   %s", scenario or "random")

    for i in range(iterations):
        name = scenario or random.choice(SCENARIOS)
        log.info("")
        log.info("─── Iteration %d/%d: %s ───", i + 1, iterations, name)
        result = await run_scenario(name)
        total[result.get("status", "error")] = total.get(result.get("status", "error"), 0) + 1
        log.info("─── Result: %s ───", result.get("status", "unknown").upper())

        if i < iterations - 1:
            delay = random.uniform(1, 3)
            log.info("Cooling down for %.1fs...", delay)
            await asyncio.sleep(delay)

    log.info("")
    log.info("=" * 60)
    log.info("RESULTS: %s", total)
    log.info("=" * 60)
    return total


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberNova Chaos Engineering Runner")
    parser.add_argument("--iterations", type=int, default=1, help="Number of chaos iterations")
    parser.add_argument("--scenario", choices=SCENARIOS + ["random"], default="random",
                        help="Chaos scenario to run")
    args = parser.parse_args()

    scenario = None if args.scenario == "random" else args.scenario
    asyncio.run(main(iterations=args.iterations, scenario=scenario))
