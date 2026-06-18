"""Tests for Redis memory monitor — info parsing, prefix estimation, alert logic."""

import pytest

from cybernova.monitoring.redis_memory import (
    RedisMemoryInfo, PrefixMemoryEstimate, MemoryAlert, MemoryReport,
    RedisMemoryMonitor, PREFIXES_OF_INTEREST, STATE_PREFIXES,
)
from cybernova.config.settings import get_settings


# ── RedisMemoryInfo ──────────────────────────────────────────────────────────


def test_info_usage_pct_with_maxmemory():
    info = RedisMemoryInfo(used_memory=256_000_000, maxmemory=512_000_000)
    assert info.usage_pct == 50.0


def test_info_usage_pct_zero_when_no_maxmemory():
    info = RedisMemoryInfo(used_memory=100_000, maxmemory=0)
    assert info.usage_pct == 0.0


def test_info_is_near_limit_true_at_80():
    info = RedisMemoryInfo(used_memory=409_600_000, maxmemory=512_000_000)
    assert info.is_near_limit is True


def test_info_is_near_limit_false_below_80():
    info = RedisMemoryInfo(used_memory=300_000_000, maxmemory=512_000_000)
    assert info.is_near_limit is False


def test_info_from_info_parses_raw():
    raw = {
        "used_memory": 1048576,
        "used_memory_human": "1.00M",
        "maxmemory": 536870912,
        "maxmemory_human": "512.00M",
        "used_memory_rss": 2097152,
        "used_memory_peak": 2097152,
        "mem_fragmentation_ratio": 1.5,
        "evicted_keys": 10,
        "total_system_memory": 8589934592,
        "uptime_in_seconds": 3600,
    }
    info = RedisMemoryInfo.from_info(raw)
    assert info.used_memory == 1048576
    assert info.maxmemory == 536870912
    assert info.usage_pct == pytest.approx(0.2, rel=0.1)
    assert info.evicted_keys == 10


# ── PrefixMemoryEstimate ─────────────────────────────────────────────────────


def test_prefix_estimate_human_bytes():
    est = PrefixMemoryEstimate(prefix="test:*", key_count=1, estimated_bytes=500)
    assert "B" in est.estimated_human


def test_prefix_estimate_human_kb():
    est = PrefixMemoryEstimate(prefix="test:*", key_count=10, estimated_bytes=2048)
    assert "KB" in est.estimated_human


def test_prefix_estimate_human_mb():
    est = PrefixMemoryEstimate(prefix="test:*", key_count=1000, estimated_bytes=2_097_152)
    assert "MB" in est.estimated_human


# ── MemoryReport ─────────────────────────────────────────────────────────────


def test_memory_report_to_dict():
    info = RedisMemoryInfo(used_memory=100, maxmemory=200, used_memory_human="100B", maxmemory_human="200B")
    report = MemoryReport(info=info, state_usage_pct=30.0)
    d = report.to_dict()
    assert d["info"]["usage_pct"] == 50.0
    assert d["state_usage_pct"] == 30.0
    assert d["state_alert"] is False


def test_memory_report_state_alert_true():
    info = RedisMemoryInfo(used_memory=200_000_000, maxmemory=512_000_000)
    report = MemoryReport(info=info, state_usage_pct=65.0, state_alert=True)
    assert report.state_alert is True


# ── Prefix constants ─────────────────────────────────────────────────────────


def test_state_prefixes_defined():
    assert "state:*" in STATE_PREFIXES
    assert "cybernova:state:*" in STATE_PREFIXES


def test_prefixes_of_interest_includes_state():
    assert "state:*" in PREFIXES_OF_INTEREST
    assert "idemp:*" in PREFIXES_OF_INTEREST
    assert "dedup:*" in PREFIXES_OF_INTEREST


# ── RedisMemoryMonitor (unit) ────────────────────────────────────────────────


def test_monitor_created_disabled_without_redis():
    monitor = RedisMemoryMonitor(redis=None)
    assert monitor._warn_pct == get_settings().redis_memory_warn_pct
    assert monitor._check_interval == get_settings().redis_memory_check_interval


def test_monitor_last_report_none_initially():
    monitor = RedisMemoryMonitor(redis=None)
    assert monitor.last_report is None


# ── Sum prefixes helper ──────────────────────────────────────────────────────


def test_sum_prefixes_combines_matching():
    estimates = [
        PrefixMemoryEstimate(prefix="state:*", key_count=100, estimated_bytes=50_000),
        PrefixMemoryEstimate(prefix="cybernova:state:*", key_count=50, estimated_bytes=25_000),
        PrefixMemoryEstimate(prefix="idemp:*", key_count=200, estimated_bytes=10_000),
    ]
    result = RedisMemoryMonitor._sum_prefixes(estimates, STATE_PREFIXES)
    assert result.key_count == 150
    assert result.estimated_bytes == 75_000
    assert "state" in result.prefix


