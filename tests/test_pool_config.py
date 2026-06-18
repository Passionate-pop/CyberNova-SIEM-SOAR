"""Tests for connection pool configuration calculator and session pool sizing."""

from cybernova.database.pool_config import PoolCalculator, suggest_env_vars
from cybernova.database.postgres.session import compute_pool_size, compute_max_overflow
from cybernova.config.settings import get_settings


# ── PoolCalculator ───────────────────────────────────────────────────────────


def test_pool_calculator_defaults():
    calc = PoolCalculator()
    s = calc.summary()
    assert s["eps"] == 10_000
    assert s["batch"] == 100
    assert s["pool_size"] >= 10
    assert s["max_overflow"] >= 5


def test_pool_calculator_at_10k_eps():
    calc = PoolCalculator(eps=10_000, batch=100)
    assert calc.pool_size == 12  # 10000/1000 + 100/50 = 10 + 2 = 12
    assert calc.max_overflow == 6  # 12 // 2


def test_pool_calculator_at_50k_eps():
    calc = PoolCalculator(eps=50_000, batch=100)
    # 50000/1000 + 100/50 = 50 + 2 = 52, clamped to 50
    assert calc.pool_size == 50
    assert calc.max_overflow == 25


def test_pool_calculator_at_100k_eps():
    calc = PoolCalculator(eps=100_000, batch=200)
    # 100000/1000 + 200/50 = 100 + 4 = 104, clamped to 50
    assert calc.pool_size == 50
    assert calc.max_overflow == 25


def test_pool_calculator_low_eps():
    calc = PoolCalculator(eps=1000, batch=10)
    # 1000/1000 + 10/50 = 1 + 0.2 = 1.2, clamped to min 10
    assert calc.pool_size == 10
    assert calc.max_overflow == 5


def test_pool_calculator_total_connections():
    calc = PoolCalculator(eps=10_000, batch=100, workers=8)
    total = calc.max_per_worker * calc.workers
    assert total == calc.total_connections
    assert calc.recommended_pg_max_connections > total


def test_pool_calculator_recommended_pg_exceeds_total():
    calc = PoolCalculator(eps=10_000, batch=100, workers=8)
    assert calc.recommended_pg_max_connections > calc.total_connections
    assert calc.recommended_pg_max_connections == calc.total_connections + calc.admin_reserved


def test_suggest_env_vars_output():
    calc = PoolCalculator(eps=10_000, batch=100, workers=8)
    env = suggest_env_vars(calc)
    assert "DB_EXPECTED_EPS=10000" in env
    assert "DB_BATCH_SIZE=100" in env
    assert "POSTGRES_MAX_CONNECTIONS=" in env


def test_pool_calculator_print_report():
    calc = PoolCalculator(eps=10_000)
    report = calc.print_report()
    assert "EPS" in report
    assert "pool_size" in report
    assert "recommended" in report


# ── session.py pool sizing ────────────────────────────────────────────────────


def test_compute_pool_size_returns_int():
    size = compute_pool_size()
    assert isinstance(size, int)
    assert 10 <= size <= 50


def test_compute_max_overflow_returns_int():
    overflow = compute_max_overflow()
    assert isinstance(overflow, int)
    assert overflow >= 5


def test_pool_settings_env_overrides():
    cfg = get_settings()
    assert hasattr(cfg, "db_pool_size")
    assert hasattr(cfg, "db_max_overflow")
    assert hasattr(cfg, "db_max_connections")
    assert hasattr(cfg, "db_expected_eps")
    assert hasattr(cfg, "db_batch_size")
